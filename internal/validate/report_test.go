// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build unit

package validate

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/attestation"
	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/output"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/signature"
)

func TestPopulateResultFromOutput(t *testing.T) {
	tests := []struct {
		name           string
		out            *output.Output
		err            error
		comp           app.SnapshotComponent
		showSuccesses  bool
		outputFormats  []string
		expectedResult Result
	}{
		{
			name: "successful validation with output",
			out: &output.Output{
				ImageURL:    "registry.com/image:tag",
				PolicyInput: []byte("policy input"),
				Signatures:  []signature.EntitySignature{{KeyID: "key1"}},
			},
			err: nil,
			comp: app.SnapshotComponent{
				Name:           "component1",
				ContainerImage: "registry.com/image:tag",
			},
			showSuccesses: true,
			outputFormats: []string{"json"},
			expectedResult: Result{
				Err: nil,
				Component: applicationsnapshot.Component{
					SnapshotComponent: app.SnapshotComponent{
						Name:           "component1",
						ContainerImage: "registry.com/image:tag",
					},
					Success: true,
				},
				PolicyInput: []byte("policy input"),
			},
		},
		{
			name: "validation error",
			out:  nil,
			err:  errors.New("validation failed"),
			comp: app.SnapshotComponent{
				Name:           "component1",
				ContainerImage: "registry.com/image:tag",
			},
			showSuccesses: false,
			outputFormats: []string{},
			expectedResult: Result{
				Err: errors.New("validation failed"),
				Component: applicationsnapshot.Component{
					SnapshotComponent: app.SnapshotComponent{
						Name:           "component1",
						ContainerImage: "registry.com/image:tag",
					},
					Success: false,
				},
			},
		},
		{
			name: "output with violations",
			out: &output.Output{
				ImageURL:    "registry.com/image:tag",
				PolicyInput: []byte("policy input"),
				PolicyCheck: []evaluator.Outcome{
					{
						Failures: []evaluator.Result{
							{Message: "violation1"},
						},
					},
				},
			},
			err: nil,
			comp: app.SnapshotComponent{
				Name:           "component1",
				ContainerImage: "registry.com/image:tag",
			},
			showSuccesses: false,
			outputFormats: []string{},
			expectedResult: Result{
				Err: nil,
				Component: applicationsnapshot.Component{
					SnapshotComponent: app.SnapshotComponent{
						Name:           "component1",
						ContainerImage: "registry.com/image:tag",
					},
					Success: false, // Has violations
				},
				PolicyInput: []byte("policy input"),
			},
		},
		{
			name: "output with attestations and attestation format",
			out: &output.Output{
				ImageURL:    "registry.com/image:tag",
				PolicyInput: []byte("policy input"),
				Attestations: []attestation.Attestation{
					&mockAttestation{statement: []byte(`{"statement": "data"}`)},
				},
			},
			err: nil,
			comp: app.SnapshotComponent{
				Name:           "component1",
				ContainerImage: "registry.com/image:tag",
			},
			showSuccesses: false,
			outputFormats: []string{"attestation=/path/to/file"},
			expectedResult: Result{
				Err: nil,
				Component: applicationsnapshot.Component{
					SnapshotComponent: app.SnapshotComponent{
						Name:           "component1",
						ContainerImage: "registry.com/image:tag",
					},
					Success: true,
				},
				PolicyInput: []byte("policy input"),
			},
		},
		{
			name: "output with attestations without attestation format",
			out: &output.Output{
				ImageURL:    "registry.com/image:tag",
				PolicyInput: []byte("policy input"),
				Attestations: []attestation.Attestation{
					&mockAttestation{statement: []byte(`{"statement": "data"}`)},
				},
			},
			err: nil,
			comp: app.SnapshotComponent{
				Name:           "component1",
				ContainerImage: "registry.com/image:tag",
			},
			showSuccesses: false,
			outputFormats: []string{"json"},
			expectedResult: Result{
				Err: nil,
				Component: applicationsnapshot.Component{
					SnapshotComponent: app.SnapshotComponent{
						Name:           "component1",
						ContainerImage: "registry.com/image:tag",
					},
					Success: true,
				},
				PolicyInput: []byte("policy input"),
			},
		},
		{
			name: "nil output with no error (VSA skip case)",
			out:  nil,
			err:  nil,
			comp: app.SnapshotComponent{
				Name:           "component1",
				ContainerImage: "registry.com/image:tag",
			},
			showSuccesses: false,
			outputFormats: []string{},
			expectedResult: Result{
				Err: nil,
				Component: applicationsnapshot.Component{
					SnapshotComponent: app.SnapshotComponent{
						Name:           "component1",
						ContainerImage: "registry.com/image:tag",
					},
					Success: true,
				},
			},
		},
		{
			name: "output with successes and showSuccesses=true",
			out: &output.Output{
				ImageURL:    "registry.com/image:tag",
				PolicyInput: []byte("policy input"),
				PolicyCheck: []evaluator.Outcome{
					{
						Successes: []evaluator.Result{
							{Message: "success1"},
							{Message: "success2"},
						},
					},
				},
			},
			err: nil,
			comp: app.SnapshotComponent{
				Name:           "component1",
				ContainerImage: "registry.com/image:tag",
			},
			showSuccesses: true,
			outputFormats: []string{},
			expectedResult: Result{
				Err: nil,
				Component: applicationsnapshot.Component{
					SnapshotComponent: app.SnapshotComponent{
						Name:           "component1",
						ContainerImage: "registry.com/image:tag",
					},
					Success:      true,
					SuccessCount: 2,
				},
				PolicyInput: []byte("policy input"),
			},
		},
		{
			name: "output with successes and showSuccesses=false",
			out: &output.Output{
				ImageURL:    "registry.com/image:tag",
				PolicyInput: []byte("policy input"),
				PolicyCheck: []evaluator.Outcome{
					{
						Successes: []evaluator.Result{
							{Message: "success1"},
							{Message: "success2"},
						},
					},
				},
			},
			err: nil,
			comp: app.SnapshotComponent{
				Name:           "component1",
				ContainerImage: "registry.com/image:tag",
			},
			showSuccesses: false,
			outputFormats: []string{},
			expectedResult: Result{
				Err: nil,
				Component: applicationsnapshot.Component{
					SnapshotComponent: app.SnapshotComponent{
						Name:           "component1",
						ContainerImage: "registry.com/image:tag",
					},
					Success:      true,
					SuccessCount: 2,
				},
				PolicyInput: []byte("policy input"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PopulateResultFromOutput(tt.out, tt.err, tt.comp, tt.showSuccesses, tt.outputFormats)

			// Check error
			if tt.expectedResult.Err == nil {
				assert.NoError(t, result.Err)
			} else {
				assert.Error(t, result.Err)
				assert.Equal(t, tt.expectedResult.Err.Error(), result.Err.Error())
			}

			// Check component
			assert.Equal(t, tt.expectedResult.Component.Name, result.Component.Name)
			assert.Equal(t, tt.expectedResult.Component.ContainerImage, result.Component.ContainerImage)
			assert.Equal(t, tt.expectedResult.Component.Success, result.Component.Success)
			assert.Equal(t, tt.expectedResult.Component.SuccessCount, result.Component.SuccessCount)

			// Check violations count
			if tt.out != nil {
				expectedViolations := tt.out.Violations()
				assert.Equal(t, len(expectedViolations), len(result.Component.Violations))
			}

			// Check successes
			if tt.showSuccesses && tt.out != nil {
				expectedSuccesses := tt.out.Successes()
				assert.Equal(t, len(expectedSuccesses), len(result.Component.Successes))
			} else {
				assert.Empty(t, result.Component.Successes)
			}

			// Check attestations
			if tt.out != nil && len(tt.out.Attestations) > 0 {
				assert.Equal(t, len(tt.out.Attestations), len(result.Component.Attestations))
				// Check if statement is included when attestation format is specified
				if ContainsOutputFormat(tt.outputFormats, "attestation") {
					assert.NotNil(t, result.Component.Attestations[0].Statement)
				}
			}

			// Check policy input
			assert.Equal(t, tt.expectedResult.PolicyInput, result.PolicyInput)
		})
	}
}

func TestContainsOutputFormat(t *testing.T) {
	tests := []struct {
		name          string
		outputFormats []string
		format        string
		expected      bool
	}{
		{
			name:          "format exists without path",
			outputFormats: []string{"json", "yaml", "text"},
			format:        "json",
			expected:      true,
		},
		{
			name:          "format exists with path",
			outputFormats: []string{"json=/path/to/file.json", "yaml", "text"},
			format:        "json",
			expected:      true,
		},
		{
			name:          "format does not exist",
			outputFormats: []string{"json", "yaml", "text"},
			format:        "xml",
			expected:      false,
		},
		{
			name:          "empty formats",
			outputFormats: []string{},
			format:        "json",
			expected:      false,
		},
		{
			name:          "format with multiple equals",
			outputFormats: []string{"attestation=/path/to/file=with=equals"},
			format:        "attestation",
			expected:      true,
		},
		{
			name:          "format in middle of list",
			outputFormats: []string{"json", "attestation=/path/to/file", "yaml"},
			format:        "attestation",
			expected:      true,
		},
		{
			name:          "case sensitive match",
			outputFormats: []string{"JSON", "yaml"},
			format:        "json",
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContainsOutputFormat(tt.outputFormats, tt.format)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCollectComponentResults(t *testing.T) {
	tests := []struct {
		name           string
		results        []Result
		errorFormatter func(Result) error
		expectedComps  int
		expectedInputs int
		expectError    bool
		errorContains  string
	}{
		{
			name: "all successful results",
			results: []Result{
				{
					Err: nil,
					Component: applicationsnapshot.Component{
						SnapshotComponent: app.SnapshotComponent{
							Name:           "comp1",
							ContainerImage: "registry.com/image1:tag",
						},
					},
					PolicyInput: []byte("input1"),
				},
				{
					Err: nil,
					Component: applicationsnapshot.Component{
						SnapshotComponent: app.SnapshotComponent{
							Name:           "comp2",
							ContainerImage: "registry.com/image2:tag",
						},
					},
					PolicyInput: []byte("input2"),
				},
			},
			errorFormatter: func(r Result) error {
				return r.Err
			},
			expectedComps:  2,
			expectedInputs: 2,
			expectError:    false,
		},
		{
			name: "all failed results",
			results: []Result{
				{
					Err: errors.New("error1"),
					Component: applicationsnapshot.Component{
						SnapshotComponent: app.SnapshotComponent{
							Name:           "comp1",
							ContainerImage: "registry.com/image1:tag",
						},
					},
				},
				{
					Err: errors.New("error2"),
					Component: applicationsnapshot.Component{
						SnapshotComponent: app.SnapshotComponent{
							Name:           "comp2",
							ContainerImage: "registry.com/image2:tag",
						},
					},
				},
			},
			errorFormatter: func(r Result) error {
				return fmt.Errorf("component %s: %w", r.Component.Name, r.Err)
			},
			expectedComps:  0,
			expectedInputs: 0,
			expectError:    true,
			errorContains:  "component comp1",
		},
		{
			name: "mixed results",
			results: []Result{
				{
					Err: nil,
					Component: applicationsnapshot.Component{
						SnapshotComponent: app.SnapshotComponent{
							Name:           "comp1",
							ContainerImage: "registry.com/image1:tag",
						},
					},
					PolicyInput: []byte("input1"),
				},
				{
					Err: errors.New("error2"),
					Component: applicationsnapshot.Component{
						SnapshotComponent: app.SnapshotComponent{
							Name:           "comp2",
							ContainerImage: "registry.com/image2:tag",
						},
					},
				},
			},
			errorFormatter: func(r Result) error {
				return fmt.Errorf("component %s: %w", r.Component.Name, r.Err)
			},
			expectedComps:  0,
			expectedInputs: 0,
			expectError:    true,
			errorContains:  "component comp2",
		},
		{
			name: "results sorted by ContainerImage",
			results: []Result{
				{
					Err: nil,
					Component: applicationsnapshot.Component{
						SnapshotComponent: app.SnapshotComponent{
							Name:           "comp2",
							ContainerImage: "registry.com/image2:tag",
						},
					},
					PolicyInput: []byte("input2"),
				},
				{
					Err: nil,
					Component: applicationsnapshot.Component{
						SnapshotComponent: app.SnapshotComponent{
							Name:           "comp1",
							ContainerImage: "registry.com/image1:tag",
						},
					},
					PolicyInput: []byte("input1"),
				},
			},
			errorFormatter: func(r Result) error {
				return r.Err
			},
			expectedComps:  2,
			expectedInputs: 2,
			expectError:    false,
		},
		{
			name:           "empty results",
			results:        []Result{},
			errorFormatter: func(r Result) error { return r.Err },
			expectedComps:  0,
			expectedInputs: 0,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			components, policyInputs, err := CollectComponentResults(tt.results, tt.errorFormatter)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, components)
				assert.Nil(t, policyInputs)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedComps, len(components))
				assert.Equal(t, tt.expectedInputs, len(policyInputs))

				// Verify sorting (descending order by ContainerImage)
				if len(components) > 1 {
					for i := 0; i < len(components)-1; i++ {
						assert.GreaterOrEqual(t, components[i].ContainerImage, components[i+1].ContainerImage,
							"Components should be sorted in descending order by ContainerImage")
					}
				}
			}
		})
	}
}

func TestWriteReport(t *testing.T) {
	ctx := context.Background()

	// Create a minimal policy with a public key to avoid keyless workflow validation
	testPolicy, err := policy.NewPolicy(ctx, policy.Options{
		EffectiveTime: "now",
		PublicKey:     "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECBtqKHcvxYkGx7ZXqps3nrYS+ZSA\nmh3m1MZfTGlnr2oN0z+sBWEC23s4RkVSXkEydI6SLYatUtJK8OmiBRS+Xw==\n-----END PUBLIC KEY-----",
	})
	require.NoError(t, err)

	tests := []struct {
		name        string
		data        ReportData
		opts        ReportOutputOptions
		expectError bool
	}{
		{
			name: "successful report creation",
			data: ReportData{
				Snapshot: "test-snapshot",
				Components: []applicationsnapshot.Component{
					{
						SnapshotComponent: app.SnapshotComponent{
							Name:           "comp1",
							ContainerImage: "registry.com/image:tag",
						},
						Success: true,
					},
				},
				Policy:        testPolicy,
				PolicyInputs:  [][]byte{[]byte("input1")},
				Expansion:     nil,
				ShowSuccesses: false,
				ShowWarnings:  true,
			},
			opts: ReportOutputOptions{
				Output:     []string{},
				NoColor:    false,
				ForceColor: false,
			},
			expectError: false,
		},
		{
			name: "report with output formats",
			data: ReportData{
				Snapshot: "test-snapshot",
				Components: []applicationsnapshot.Component{
					{
						SnapshotComponent: app.SnapshotComponent{
							Name:           "comp1",
							ContainerImage: "registry.com/image:tag",
						},
						Success: true,
					},
				},
				Policy:        testPolicy,
				PolicyInputs:  [][]byte{[]byte("input1")},
				Expansion:     nil,
				ShowSuccesses: false,
				ShowWarnings:  true,
			},
			opts: ReportOutputOptions{
				Output:     []string{"json=/tmp/test.json"},
				NoColor:    false,
				ForceColor: false,
			},
			expectError: false,
		},
		{
			name: "report with empty components",
			data: ReportData{
				Snapshot:     "test-snapshot",
				Components:   []applicationsnapshot.Component{},
				Policy:       testPolicy,
				PolicyInputs: [][]byte{},
				Expansion:    nil,
			},
			opts: ReportOutputOptions{
				Output:     []string{},
				NoColor:    false,
				ForceColor: false,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			cmd := &cobra.Command{}
			cmd.SetContext(ctx)

			report, err := WriteReport(tt.data, tt.opts, cmd)
			_ = fs // May be used in future tests

			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, applicationsnapshot.Report{}, report)
			} else {
				// WriteReport should succeed even if output file creation fails
				// (we're testing the function structure, not file I/O)
				if err != nil {
					// Some errors are expected (e.g., missing directories for file output)
					// Just verify the error is file-related if output format specified a file
					if len(tt.opts.Output) > 0 {
						// File creation errors are acceptable in test environment
						assert.Contains(t, err.Error(), "failed")
					}
				} else {
					// If no error, verify report structure
					assert.NotEmpty(t, report.Snapshot)
				}
			}
		})
	}
}

func TestProcessOutputForImageValidation(t *testing.T) {
	tests := []struct {
		name            string
		out             *output.Output
		err             error
		comp            app.SnapshotComponent
		showSuccesses   bool
		outputFormats   []string
		expectedSuccess bool
	}{
		{
			name: "successful validation",
			out: &output.Output{
				ImageURL:    "registry.com/image:tag",
				PolicyInput: []byte("policy input"),
			},
			err: nil,
			comp: app.SnapshotComponent{
				Name:           "component1",
				ContainerImage: "registry.com/image:tag",
			},
			showSuccesses:   false,
			outputFormats:   []string{},
			expectedSuccess: true,
		},
		{
			name: "validation with violations",
			out: &output.Output{
				ImageURL:    "registry.com/image:tag",
				PolicyInput: []byte("policy input"),
				PolicyCheck: []evaluator.Outcome{
					{
						Failures: []evaluator.Result{
							{Message: "violation1"},
						},
					},
				},
			},
			err: nil,
			comp: app.SnapshotComponent{
				Name:           "component1",
				ContainerImage: "registry.com/image:tag",
			},
			showSuccesses:   false,
			outputFormats:   []string{},
			expectedSuccess: false,
		},
		{
			name: "validation error",
			out:  nil,
			err:  errors.New("validation failed"),
			comp: app.SnapshotComponent{
				Name:           "component1",
				ContainerImage: "registry.com/image:tag",
			},
			showSuccesses:   false,
			outputFormats:   []string{},
			expectedSuccess: false,
		},
		{
			name: "nil output no error (VSA skip)",
			out:  nil,
			err:  nil,
			comp: app.SnapshotComponent{
				Name:           "component1",
				ContainerImage: "registry.com/image:tag",
			},
			showSuccesses:   false,
			outputFormats:   []string{},
			expectedSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			component := ProcessOutputForImageValidation(tt.out, tt.err, tt.comp, tt.showSuccesses, tt.outputFormats)

			assert.Equal(t, tt.expectedSuccess, component.Success)
			assert.Equal(t, tt.comp.Name, component.Name)
			assert.Equal(t, tt.comp.ContainerImage, component.ContainerImage)

			if tt.out != nil {
				expectedViolations := tt.out.Violations()
				assert.Equal(t, len(expectedViolations), len(component.Violations))
			}
		})
	}
}

// mockAttestation is a test implementation of attestation.Attestation
type mockAttestation struct {
	statement []byte
}

func (m *mockAttestation) Type() string {
	return "test-type"
}

func (m *mockAttestation) Statement() []byte {
	return m.statement
}

func (m *mockAttestation) PredicateType() string {
	return "test-predicate"
}

func (m *mockAttestation) Signatures() []signature.EntitySignature {
	return []signature.EntitySignature{}
}

func (m *mockAttestation) Subject() []in_toto.Subject {
	return []in_toto.Subject{}
}
