// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"encoding/json"
	"testing"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/conforma/cli/internal/opa/rule"
)

//////////////////////////////////////////////////////////////////////////////
// test scaffolding
//////////////////////////////////////////////////////////////////////////////

func makeSource(ruleData string, includes []string) ecc.Source {
	s := ecc.Source{}
	if ruleData != "" {
		s.RuleData = &extv1.JSON{Raw: json.RawMessage(ruleData)}
	}
	if len(includes) > 0 {
		s.Config = &ecc.SourceConfig{Include: includes}
	}
	return s
}

//////////////////////////////////////////////////////////////////////////////
// FilterFactory tests
//////////////////////////////////////////////////////////////////////////////

func TestDefaultFilterFactory(t *testing.T) {
	tests := []struct {
		name        string
		source      ecc.Source
		wantFilters int
	}{
		{
			name:        "no config",
			source:      ecc.Source{},
			wantFilters: 1, // Always adds PipelineIntentionFilter
		},
		{
			name:        "pipeline intention only",
			source:      makeSource(`{"pipeline_intention":"release"}`, nil),
			wantFilters: 1,
		},
		{
			name:        "include list only",
			source:      makeSource("", []string{"@redhat", "cve"}),
			wantFilters: 2, // PipelineIntentionFilter + IncludeListFilter
		},
		{
			name:        "both pipeline_intention and include list",
			source:      makeSource(`{"pipeline_intention":"release"}`, []string{"@redhat", "cve"}),
			wantFilters: 2,
		},
		{
			name:        "no includes and no pipeline_intention - PipelineIntentionFilter still added",
			source:      makeSource("", nil),
			wantFilters: 1, // PipelineIntentionFilter is always added
		},
	}

	for _, tc := range tests {
		got := NewDefaultFilterFactory().CreateFilters(tc.source)
		assert.Len(t, got, tc.wantFilters, tc.name)
	}
}

//////////////////////////////////////////////////////////////////////////////
// IncludeListFilter – core behaviour
//////////////////////////////////////////////////////////////////////////////

func TestIncludeListFilter(t *testing.T) {
	rules := policyRules{
		"pkg.rule":    {Collections: []string{"redhat"}},
		"cve.rule":    {Collections: []string{"security"}},
		"other.rule":  {},
		"labels.rule": {Collections: []string{"security"}},
		"foo.bar":     {},
	}

	tests := []struct {
		name     string
		entries  []string
		wantPkgs []string
	}{
		{
			name:     "@redhat collection",
			entries:  []string{"@redhat"},
			wantPkgs: []string{"pkg"},
		},
		{
			name:     "explicit package",
			entries:  []string{"cve"},
			wantPkgs: []string{"cve"},
		},
		{
			name:     "package.rule entry",
			entries:  []string{"labels.rule"},
			wantPkgs: []string{"labels"},
		},
		{
			name:     "OR across entries",
			entries:  []string{"@redhat", "cve"},
			wantPkgs: []string{"pkg", "cve"},
		},
		{
			name:     "non‑existent entry",
			entries:  []string{"@none"},
			wantPkgs: []string{},
		},
	}

	for _, tc := range tests {
		got := filterNamespaces(rules, NewIncludeListFilter(tc.entries))
		assert.ElementsMatch(t, tc.wantPkgs, got, tc.name)
	}
}

//////////////////////////////////////////////////////////////////////////////
// PipelineIntentionFilter
//////////////////////////////////////////////////////////////////////////////

func TestPipelineIntentionFilter(t *testing.T) {
	rules := policyRules{
		"a.r": {PipelineIntention: []string{"release"}},
		"b.r": {PipelineIntention: []string{"dev"}},
		"c.r": {},
	}

	tests := []struct {
		name       string
		intentions []string
		wantPkgs   []string
	}{
		{
			name:       "no intentions ⇒ only packages with no pipeline_intention metadata",
			intentions: nil,
			wantPkgs:   []string{"c"}, // Only c has no pipeline_intention metadata
		},
		{
			name:       "pipeline_intention set - include packages with matching pipeline_intention metadata",
			intentions: []string{"release"},
			wantPkgs:   []string{"a"}, // Only a has matching pipeline_intention metadata
		},
		{
			name:       "pipeline_intention set with multiple values - include packages with any matching pipeline_intention metadata",
			intentions: []string{"dev", "release"},
			wantPkgs:   []string{"a", "b"}, // Both a and b have matching pipeline_intention metadata
		},
	}

	for _, tc := range tests {
		got := filterNamespaces(rules, NewPipelineIntentionFilter(tc.intentions))
		assert.ElementsMatch(t, tc.wantPkgs, got, tc.name)
	}
}

//////////////////////////////////////////////////////////////////////////////
// Complete filtering behavior tests
//////////////////////////////////////////////////////////////////////////////

func TestCompleteFilteringBehavior(t *testing.T) {
	rules := policyRules{
		"release.rule1": {PipelineIntention: []string{"release"}},
		"release.rule2": {PipelineIntention: []string{"release", "production"}},
		"dev.rule1":     {PipelineIntention: []string{"dev"}},
		"general.rule1": {}, // No pipeline_intention metadata
		"general.rule2": {}, // No pipeline_intention metadata
	}

	tests := []struct {
		name        string
		source      ecc.Source
		expectedPkg []string
	}{
		{
			name:        "no includes and no pipeline_intention - only packages with no pipeline_intention metadata",
			source:      makeSource("", nil),
			expectedPkg: []string{"general"}, // Only general has no pipeline_intention metadata
		},
		{
			name:        "pipeline_intention set - only packages with matching pipeline_intention metadata",
			source:      makeSource(`{"pipeline_intention":"release"}`, nil),
			expectedPkg: []string{"release"}, // Only release has matching pipeline_intention metadata
		},
		{
			name:        "includes set - only matching packages with no pipeline_intention metadata",
			source:      makeSource("", []string{"release", "general"}),
			expectedPkg: []string{"general"}, // Only general has no pipeline_intention metadata and matches includes
		},
		{
			name:        "both pipeline_intention and includes - AND logic",
			source:      makeSource(`{"pipeline_intention":"release"}`, []string{"release"}),
			expectedPkg: []string{"release"}, // Only release matches both conditions
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filterFactory := NewDefaultFilterFactory()
			filters := filterFactory.CreateFilters(tc.source)
			got := filterNamespaces(rules, filters...)
			assert.ElementsMatch(t, tc.expectedPkg, got, tc.name)
		})
	}
}

//////////////////////////////////////////////////////////////////////////////
// Test filtering with rules that don't have metadata
//////////////////////////////////////////////////////////////////////////////

func TestFilteringWithRulesWithoutMetadata(t *testing.T) {
	// This test demonstrates how filtering works with rules that don't have
	// pipeline_intention metadata, like the example fail_with_data.rego rule.
	rules := policyRules{
		"main.fail_with_data": {}, // Rule without any metadata (like fail_with_data.rego)
		"release.security":    {PipelineIntention: []string{"release"}},
		"dev.validation":      {PipelineIntention: []string{"dev"}},
		"general.basic":       {}, // Another rule without metadata
	}

	tests := []struct {
		name        string
		source      ecc.Source
		expectedPkg []string
		description string
	}{
		{
			name:        "no pipeline_intention - only rules without metadata",
			source:      makeSource("", nil),
			expectedPkg: []string{"main", "general"}, // Only packages with rules that have no pipeline_intention metadata
			description: "When no pipeline_intention is configured, only rules without pipeline_intention metadata are evaluated",
		},
		{
			name:        "pipeline_intention set - only rules with matching metadata",
			source:      makeSource(`{"pipeline_intention":"release"}`, nil),
			expectedPkg: []string{"release"}, // Only package with matching pipeline_intention metadata
			description: "When pipeline_intention is set, only rules with matching pipeline_intention metadata are evaluated",
		},
		{
			name:        "includes with no pipeline_intention - only matching rules without metadata",
			source:      makeSource("", []string{"main", "release"}),
			expectedPkg: []string{"main"}, // Only main has no pipeline_intention metadata and matches includes
			description: "When includes are set but no pipeline_intention, only rules without metadata that match includes are evaluated",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filterFactory := NewDefaultFilterFactory()
			filters := filterFactory.CreateFilters(tc.source)
			got := filterNamespaces(rules, filters...)
			assert.ElementsMatch(t, tc.expectedPkg, got, tc.description)
		})
	}
}

//////////////////////////////////////////////////////////////////////////////
// NewDefaultFilterFactory tests
//////////////////////////////////////////////////////////////////////////////

// MockRuleInfo creates a mock rule.Info for testing
func MockRuleInfo(pkg string, collections []string, pipelineIntention []string) rule.Info {
	return rule.Info{
		Package:           pkg,
		Collections:       collections,
		PipelineIntention: pipelineIntention,
		Code:              "MOCK001",
		Description:       "Mock rule for testing",
		Kind:              "deny",
		ShortName:         "mock",
		Title:             "Mock Rule",
	}
}

// MockSource creates a mock ecc.Source for testing
func MockSource(ruleData string, includes []string) ecc.Source {
	source := ecc.Source{}

	if ruleData != "" {
		source.RuleData = &extv1.JSON{Raw: json.RawMessage(ruleData)}
	}

	if len(includes) > 0 {
		source.Config = &ecc.SourceConfig{Include: includes}
	}

	return source
}

func TestNewDefaultFilterFactory(t *testing.T) {
	tests := []struct {
		name               string
		source             ecc.Source
		expectedCount      int
		expectedType       string
		description        string
		expectedIntentions []string
		expectedIncludes   []string
	}{
		{
			name:               "source with pipeline_intention - only PipelineIntentionFilter",
			source:             MockSource(`{"pipeline_intention": "release"}`, nil),
			expectedCount:      1,
			expectedType:       "*evaluator.DefaultFilterFactory",
			description:        "Source with pipeline_intention should create only PipelineIntentionFilter",
			expectedIntentions: []string{"release"},
			expectedIncludes:   nil,
		},
		{
			name:               "source with includes only",
			source:             MockSource("", []string{"@redhat", "security"}),
			expectedCount:      2,
			expectedType:       "*evaluator.DefaultFilterFactory",
			description:        "Source with only includes should create PipelineIntentionFilter and IncludeListFilter",
			expectedIntentions: []string{},
			expectedIncludes:   []string{"@redhat", "security"},
		},
		{
			name:               "source with both pipeline_intention and includes",
			source:             MockSource(`{"pipeline_intention": ["release", "production"]}`, []string{"@redhat"}),
			expectedCount:      2,
			expectedType:       "*evaluator.DefaultFilterFactory",
			description:        "Source with both should create PipelineIntentionFilter and IncludeListFilter",
			expectedIntentions: []string{"release", "production"},
			expectedIncludes:   []string{"@redhat"},
		},
		{
			name:               "source with empty pipeline_intention array",
			source:             MockSource(`{"pipeline_intention": []}`, nil),
			expectedCount:      1,
			expectedType:       "*evaluator.DefaultFilterFactory",
			description:        "Source with empty pipeline_intention array should create only PipelineIntentionFilter",
			expectedIntentions: []string{},
			expectedIncludes:   nil,
		},
		{
			name:               "source with complex pipeline_intention types",
			source:             MockSource(`{"pipeline_intention": ["dev", "staging", "release"]}`, nil),
			expectedCount:      1,
			expectedType:       "*evaluator.DefaultFilterFactory",
			description:        "Source with complex pipeline_intention array should create only PipelineIntentionFilter",
			expectedIntentions: []string{"dev", "staging", "release"},
			expectedIncludes:   nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			factory := NewDefaultFilterFactory()

			// Act
			filters := factory.CreateFilters(tc.source)

			// Assert: Basic filter count and type validation
			assert.Len(t, filters, tc.expectedCount, tc.description)
			assert.IsType(t, &PipelineIntentionFilter{}, filters[0], "first filter should be PipelineIntentionFilter")

			// Enhanced validation: Check PipelineIntentionFilter configuration
			if tc.expectedIntentions != nil {
				pipelineFilter := filters[0].(*PipelineIntentionFilter)
				assert.ElementsMatch(t, tc.expectedIntentions, pipelineFilter.targetIntentions,
					"PipelineIntentionFilter should have correct target intentions")
			}

			// Enhanced validation: Check IncludeListFilter configuration when present
			if tc.expectedCount > 1 {
				assert.IsType(t, &IncludeListFilter{}, filters[1], "second filter should be IncludeListFilter")

				if tc.expectedIncludes != nil {
					includeFilter := filters[1].(*IncludeListFilter)
					assert.ElementsMatch(t, tc.expectedIncludes, includeFilter.entries,
						"IncludeListFilter should have correct entries")
				}
			}

			// Test actual filtering behavior for all test cases
			// Create mock rules for testing different scenarios
			mockRules := policyRules{
				"security.cve": {
					Collections:       []string{"security", "redhat"},
					PipelineIntention: []string{"release"},
				},
				"general.rule": {
					Collections:       []string{"redhat"},
					PipelineIntention: []string{"staging"},
				},
			}

			// Apply filters to mock rules
			result := filterNamespaces(mockRules, filters...)

			// Test filtering behavior based on test case
			switch tc.name {
			case "source with pipeline_intention - only PipelineIntentionFilter":
				// Should only include packages with matching pipeline_intention
				assert.ElementsMatch(t, []string{"security"}, result,
					"should only include packages with matching pipeline_intention metadata")

			case "source with includes only":
				// Should only include packages matching include criteria with no pipeline_intention metadata
				// general.rule has redhat collection but has pipeline intention, so it won't match
				assert.ElementsMatch(t, []string{}, result,
					"should not include any packages since none match both no pipeline intention and include criteria")

			case "source with both pipeline_intention and includes":
				// Should only include packages matching both pipeline_intention and include criteria
				assert.ElementsMatch(t, []string{"security"}, result,
					"should only include packages matching both pipeline_intention and include criteria")

			case "source with complex pipeline_intention types":
				// Should include packages with any of the complex pipeline_intention values
				assert.ElementsMatch(t, []string{"security", "general"}, result,
					"should include packages with any matching pipeline_intention from complex array")
			}

		})
	}
}

// TestNewPipelineIntentionFilter tests the NewPipelineIntentionFilter function
func TestNewPipelineIntentionFilter(t *testing.T) {
	tests := []struct {
		name             string
		targetIntentions []string
		expectedType     string
		description      string
	}{
		{
			name:             "create filter with target intentions",
			targetIntentions: []string{"release", "staging"},
			expectedType:     "*evaluator.PipelineIntentionFilter",
			description:      "Should create PipelineIntentionFilter with specified target intentions",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			filter := NewPipelineIntentionFilter(tc.targetIntentions)

			// Assert
			assert.NotNil(t, filter, "Filter should not be nil")
			assert.IsType(t, &PipelineIntentionFilter{}, filter, tc.description)

			// Verify the filter has the correct target intentions
			pipelineFilter := filter.(*PipelineIntentionFilter)
			assert.ElementsMatch(t, tc.targetIntentions, pipelineFilter.targetIntentions,
				"Filter should have correct target intentions")
		})
	}
}

// TestPipelineIntentionFilter_Include tests the Include method of PipelineIntentionFilter
func TestPipelineIntentionFilter_Include(t *testing.T) {
	tests := []struct {
		name             string
		targetIntentions []string
		mockRules        []rule.Info
		expectedResult   bool
		description      string
	}{
		{
			name:             "target intentions - include packages with matching pipeline intention",
			targetIntentions: []string{"release", "staging"},
			mockRules: []rule.Info{
				{
					Collections:       []string{"security"},
					PipelineIntention: []string{"release"},
				},
			},
			expectedResult: true,
			description:    "Should include package when target intentions match rule pipeline intention",
		},
		{
			name:             "target intentions - exclude packages with no matching pipeline intention",
			targetIntentions: []string{"release", "staging"},
			mockRules: []rule.Info{
				{
					Collections:       []string{"security"},
					PipelineIntention: []string{"production"},
				},
			},
			expectedResult: false,
			description:    "Should exclude package when no rule pipeline intention matches target intentions",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			filter := &PipelineIntentionFilter{targetIntentions: tc.targetIntentions}

			// Act
			result := filter.Include("test-package", tc.mockRules)

			// Assert
			assert.Equal(t, tc.expectedResult, result, tc.description)
		})
	}
}

// TestIncludeListFilter_Include tests the Include method of IncludeListFilter
func TestIncludeListFilter_Include(t *testing.T) {
	tests := []struct {
		name           string
		entries        []string
		packageName    string
		mockRules      []rule.Info
		expectedResult bool
		description    string
	}{
		{
			name:        "collection-based filtering - @redhat",
			entries:     []string{"@redhat", "security"},
			packageName: "general",
			mockRules: []rule.Info{
				{
					Collections:       []string{"redhat"},
					PipelineIntention: []string{},
				},
			},
			expectedResult: true,
			description:    "Should include package when any rule belongs to @redhat collection",
		},
		{
			name:        "no matches found",
			entries:     []string{"@redhat", "security"},
			packageName: "general",
			mockRules: []rule.Info{
				{
					Collections:       []string{"quality"},
					PipelineIntention: []string{},
				},
			},
			expectedResult: false,
			description:    "Should exclude package when no entries match package or collections",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			filter := &IncludeListFilter{entries: tc.entries}

			// Act
			result := filter.Include(tc.packageName, tc.mockRules)

			// Assert
			assert.Equal(t, tc.expectedResult, result, tc.description)
		})
	}
}

// TestExtractStringArrayFromRuleData tests the extractStringArrayFromRuleData function
func TestExtractStringArrayFromRuleData(t *testing.T) {
	tests := []struct {
		name           string
		source         ecc.Source
		key            string
		expectedResult []string
		description    string
	}{
		{
			name:           "single string value - should convert to array",
			source:         MockSource(`{"pipeline_intention": "release"}`, nil),
			key:            "pipeline_intention",
			expectedResult: []string{"release"},
			description:    "Should convert single string value to string array as per documentation example",
		},
		{
			name:           "string array value - should extract as is",
			source:         MockSource(`{"pipeline_intention": ["release", "production"]}`, nil),
			key:            "pipeline_intention",
			expectedResult: []string{"release", "production"},
			description:    "Should extract string array when value is already an array as per documentation example",
		},
		{
			name:           "key not found - should return empty array",
			source:         MockSource(`{}`, nil),
			key:            "pipeline_intention",
			expectedResult: []string{},
			description:    "Should return empty array when key does not exist as per documentation example",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			result := extractStringArrayFromRuleData(tc.source, tc.key)

			// Assert
			assert.ElementsMatch(t, tc.expectedResult, result, tc.description)
		})
	}
}
