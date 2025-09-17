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

package applicationsnapshot

import (
	"context"
	"testing"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/evaluator"
)

func TestGenerateSnapshotPredicate(t *testing.T) {
	ctx := context.Background()

	// Create test components
	components := []Component{
		{
			SnapshotComponent: app.SnapshotComponent{
				Name:           "component-1",
				ContainerImage: "quay.io/test/component1@sha256:abc123",
				Source:         app.ComponentSource{},
			},
			Success: true,
			Violations: []evaluator.Result{
				{Message: "minor violation"},
			},
			Warnings: []evaluator.Result{
				{Message: "warning"},
			},
			Successes: []evaluator.Result{
				{Message: "success 1"},
				{Message: "success 2"},
			},
		},
		{
			SnapshotComponent: app.SnapshotComponent{
				Name:           "component-2",
				ContainerImage: "quay.io/test/component2@sha256:def456",
				Source:         app.ComponentSource{},
			},
			Success: false,
			Violations: []evaluator.Result{
				{Message: "critical violation"},
			},
			Warnings:  []evaluator.Result{},
			Successes: []evaluator.Result{},
		},
	}

	// Create test report
	report := Report{
		Success:    false, // Overall failure due to component-2
		Snapshot:   "test-snapshot-123",
		Components: components,
		Key:        "test-key",
		Policy: ecc.EnterpriseContractPolicySpec{
			Name: "test-policy",
			Sources: []ecc.Source{
				{
					Name: "test-source",
					Policy: []string{
						"https://github.com/enterprise-contract/ec-policies//policy/lib?ref=main",
					},
				},
			},
		},
		EcVersion:     "1.2.0",
		EffectiveTime: time.Now(),
	}

	// Create generator
	generator := NewSnapshotPredicateGenerator(report)

	// Generate Predicate
	predicate, err := generator.GeneratePredicate(ctx)
	require.NoError(t, err)
	require.NotNil(t, predicate)

	// Verify Predicate structure
	assert.Equal(t, "failed", predicate.Status)
	assert.Equal(t, "conforma", predicate.Verifier)
	assert.Equal(t, "test-policy", predicate.Policy.Name)
	assert.NotEmpty(t, predicate.Timestamp)

	// Verify image references
	assert.Contains(t, predicate.ImageRefs, "quay.io/test/component1@sha256:abc123")
	assert.Contains(t, predicate.ImageRefs, "quay.io/test/component2@sha256:def456")

	// Verify summary
	require.NotNil(t, predicate.Summary)
	assert.Equal(t, "test-snapshot-123", predicate.Summary.Snapshot)
	assert.Equal(t, 2, predicate.Summary.Components)
	assert.Equal(t, false, predicate.Summary.Success)
	assert.Equal(t, "test-key", predicate.Summary.Key)
	assert.Equal(t, "1.2.0", predicate.Summary.EcVersion)

	// Verify component details
	componentDetails := predicate.Summary.ComponentDetails
	assert.Len(t, componentDetails, 2)

	// Check first component details
	comp1 := componentDetails[0]
	assert.Equal(t, "component-1", comp1.Name)
	assert.Equal(t, "quay.io/test/component1@sha256:abc123", comp1.ContainerImage)
	assert.Equal(t, true, comp1.Success)
	assert.Equal(t, 1, comp1.Violations)
	assert.Equal(t, 1, comp1.Warnings)
	assert.Equal(t, 2, comp1.Successes)

	// Check second component details
	comp2 := componentDetails[1]
	assert.Equal(t, "component-2", comp2.Name)
	assert.Equal(t, "quay.io/test/component2@sha256:def456", comp2.ContainerImage)
	assert.Equal(t, false, comp2.Success)
	assert.Equal(t, 1, comp2.Violations)
	assert.Equal(t, 0, comp2.Warnings)
	assert.Equal(t, 0, comp2.Successes)
}

func TestGenerateSnapshotPredicateWithExpansion(t *testing.T) {
	ctx := context.Background()

	// Create expansion info
	expansion := NewExpansionInfo()
	expansion.SetIndexAlias("quay.io/test/multiarch:latest", "quay.io/test/multiarch@sha256:index123")
	expansion.AddChildToIndex("quay.io/test/multiarch@sha256:index123", "quay.io/test/multiarch@sha256:amd64")
	expansion.AddChildToIndex("quay.io/test/multiarch@sha256:index123", "quay.io/test/multiarch@sha256:arm64")

	// Create test components with multi-arch image
	components := []Component{
		{
			SnapshotComponent: app.SnapshotComponent{
				Name:           "multiarch-component",
				ContainerImage: "quay.io/test/multiarch:latest",
				Source:         app.ComponentSource{},
			},
			Success: true,
		},
		{
			SnapshotComponent: app.SnapshotComponent{
				Name:           "simple-component",
				ContainerImage: "quay.io/test/simple@sha256:abc123",
				Source:         app.ComponentSource{},
			},
			Success: true,
		},
	}

	// Create test report with expansion info
	report := Report{
		Success:    true,
		Snapshot:   "multiarch-snapshot",
		Components: components,
		Key:        "multiarch-key",
		Policy: ecc.EnterpriseContractPolicySpec{
			Name: "multiarch-policy",
		},
		Expansion: expansion,
	}

	// Create generator
	generator := NewSnapshotPredicateGenerator(report)

	// Generate Predicate
	predicate, err := generator.GeneratePredicate(ctx)
	require.NoError(t, err)
	require.NotNil(t, predicate)

	// Verify image references include all images
	expectedRefs := []string{
		"quay.io/test/multiarch:latest",
		"quay.io/test/multiarch@sha256:index123",
		"quay.io/test/multiarch@sha256:amd64",
		"quay.io/test/multiarch@sha256:arm64",
		"quay.io/test/simple@sha256:abc123",
	}

	for _, expectedRef := range expectedRefs {
		assert.Contains(t, predicate.ImageRefs, expectedRef)
	}

	// Should not have duplicates
	assert.Equal(t, len(expectedRefs), len(predicate.ImageRefs))
}

func TestGenerateSnapshotPredicateSuccess(t *testing.T) {
	ctx := context.Background()

	// Create test components that all pass
	components := []Component{
		{
			SnapshotComponent: app.SnapshotComponent{
				Name:           "success-component-1",
				ContainerImage: "quay.io/test/success1@sha256:abc123",
				Source:         app.ComponentSource{},
			},
			Success:    true,
			Violations: []evaluator.Result{},
			Warnings:   []evaluator.Result{},
			Successes: []evaluator.Result{
				{Message: "all checks passed"},
			},
		},
		{
			SnapshotComponent: app.SnapshotComponent{
				Name:           "success-component-2",
				ContainerImage: "quay.io/test/success2@sha256:def456",
				Source:         app.ComponentSource{},
			},
			Success:    true,
			Violations: []evaluator.Result{},
			Warnings:   []evaluator.Result{},
			Successes: []evaluator.Result{
				{Message: "all checks passed"},
			},
		},
	}

	// Create test report
	report := Report{
		Success:    true,
		Snapshot:   "success-snapshot",
		Components: components,
		Key:        "success-key",
		Policy: ecc.EnterpriseContractPolicySpec{
			Name: "success-policy",
		},
		EcVersion:     "2.0.0",
		EffectiveTime: time.Now(),
	}

	// Create generator
	generator := NewSnapshotPredicateGenerator(report)

	// Generate Predicate
	predicate, err := generator.GeneratePredicate(ctx)
	require.NoError(t, err)
	require.NotNil(t, predicate)

	// Verify Predicate structure for success case
	assert.Equal(t, "passed", predicate.Status)
	assert.Equal(t, "conforma", predicate.Verifier)
	assert.Equal(t, "success-policy", predicate.Policy.Name)
	assert.Equal(t, "success-snapshot", predicate.Summary.Snapshot)
	assert.Equal(t, 2, predicate.Summary.Components)
	assert.Equal(t, true, predicate.Summary.Success)
	assert.Equal(t, "success-key", predicate.Summary.Key)
	assert.Equal(t, "2.0.0", predicate.Summary.EcVersion)
}

func TestWriteSnapshotPredicate(t *testing.T) {
	// Create a test SnapshotPredicate
	predicate := &SnapshotPredicate{
		Policy: ecc.EnterpriseContractPolicySpec{
			Name: "test-policy",
		},
		ImageRefs: []string{
			"quay.io/test/component1@sha256:abc123",
			"quay.io/test/component2@sha256:def456",
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    "passed",
		Summary: SnapshotSummary{
			Snapshot:   "test-snapshot",
			Components: 2,
			Success:    true,
		},
	}

	// Create writer
	writer := NewSnapshotPredicateWriter()

	// Write Predicate
	path, err := writer.WritePredicate(predicate)
	require.NoError(t, err)
	require.NotEmpty(t, path)
	assert.Contains(t, path, "application-snapshot-vsa.json")
}

func TestGetAllImageRefsSnapshot(t *testing.T) {
	// Create expansion info
	expansion := NewExpansionInfo()
	expansion.SetIndexAlias("quay.io/test/multiarch:latest", "quay.io/test/multiarch@sha256:index123")
	expansion.AddChildToIndex("quay.io/test/multiarch@sha256:index123", "quay.io/test/multiarch@sha256:amd64")
	expansion.AddChildToIndex("quay.io/test/multiarch@sha256:index123", "quay.io/test/multiarch@sha256:arm64")

	// Create test components
	components := []Component{
		{
			SnapshotComponent: app.SnapshotComponent{
				Name:           "multiarch-component",
				ContainerImage: "quay.io/test/multiarch:latest",
				Source:         app.ComponentSource{},
			},
		},
		{
			SnapshotComponent: app.SnapshotComponent{
				Name:           "simple-component",
				ContainerImage: "quay.io/test/simple@sha256:abc123",
				Source:         app.ComponentSource{},
			},
		},
	}

	// Create test report
	report := Report{
		Components: components,
		Expansion:  expansion,
	}

	// Create generator
	generator := NewSnapshotPredicateGenerator(report)

	// Test getAllImageRefs method
	imageRefs := generator.getAllImageRefs()

	// Should contain all image references
	expectedRefs := []string{
		"quay.io/test/multiarch:latest",
		"quay.io/test/multiarch@sha256:index123",
		"quay.io/test/multiarch@sha256:amd64",
		"quay.io/test/multiarch@sha256:arm64",
		"quay.io/test/simple@sha256:abc123",
	}

	for _, expectedRef := range expectedRefs {
		assert.Contains(t, imageRefs, expectedRef)
	}

	// Should not have duplicates
	assert.Equal(t, len(expectedRefs), len(imageRefs))
}

func TestNormalizeIndexRef(t *testing.T) {
	// Create expansion info
	expansion := NewExpansionInfo()
	expansion.SetIndexAlias("quay.io/test/image:latest", "quay.io/test/image@sha256:index123")

	tests := []struct {
		name     string
		ref      string
		expected string
	}{
		{
			name:     "normalized reference",
			ref:      "quay.io/test/image:latest",
			expected: "quay.io/test/image@sha256:index123",
		},
		{
			name:     "non-index reference",
			ref:      "quay.io/test/simple@sha256:abc123",
			expected: "quay.io/test/simple@sha256:abc123",
		},
		{
			name:     "nil expansion",
			ref:      "quay.io/test/image:latest",
			expected: "quay.io/test/image:latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var exp *ExpansionInfo
			if tt.name != "nil expansion" {
				exp = expansion
			}
			result := normalizeIndexRef(tt.ref, exp)
			assert.Equal(t, tt.expected, result)
		})
	}
}
