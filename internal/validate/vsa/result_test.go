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

package vsa

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/conforma/cli/internal/evaluator"
)

// TestVSAValidationResult_Comprehensive tests the unified result structure comprehensively
func TestVSAValidationResult_Comprehensive(t *testing.T) {
	t.Run("VSA success with no fallback", func(t *testing.T) {
		result := &VSAValidationResult{
			VSAPhaseResult: &VSAPhaseResult{
				Passed:           true,
				Message:          "VSA validation passed",
				PredicateOutcome: "passed",
			},
			ImageValidationResult: nil,
			OverallSuccess:        true,
			UsedFallback:          false,
			ImageRef:              "registry.com/image:latest",
		}

		// Test JSON output
		err := result.PrintJSON(io.Discard)
		assert.NoError(t, err)

		// Test console output
		var buf bytes.Buffer
		err = result.PrintConsole(&buf)
		assert.NoError(t, err)
		output := buf.String()
		assert.Contains(t, output, "✅ VSA validation passed")
		assert.Contains(t, output, "Predicate Outcome: passed")
		assert.NotContains(t, output, "🔄 Using image validation")
	})

	t.Run("VSA failure with successful fallback", func(t *testing.T) {
		result := &VSAValidationResult{
			VSAPhaseResult: &VSAPhaseResult{
				Passed:           false,
				Message:          "VSA validation failed",
				PredicateOutcome: "failed",
			},
			ImageValidationResult: &ImageValidationResult{
				Passed: true,
				Successes: []evaluator.Result{
					{
						Message: "Image validation passed",
					},
				},
			},
			OverallSuccess: true,
			UsedFallback:   true,
			ImageRef:       "registry.com/image:latest",
		}

		// Test JSON output
		err := result.PrintJSON(io.Discard)
		assert.NoError(t, err)

		// Test console output
		var buf bytes.Buffer
		err = result.PrintConsole(&buf)
		assert.NoError(t, err)
		output := buf.String()
		assert.Contains(t, output, "❌ VSA validation failed")
		assert.Contains(t, output, "Predicate Outcome: failed")
		assert.Contains(t, output, "🔄 Using image validation")
		assert.Contains(t, output, "✅ Image validation passed")
	})

	t.Run("VSA failure with failed fallback", func(t *testing.T) {
		result := &VSAValidationResult{
			VSAPhaseResult: &VSAPhaseResult{
				Passed:           false,
				Message:          "VSA validation failed",
				PredicateOutcome: "failed",
			},
			ImageValidationResult: &ImageValidationResult{
				Passed: false,
				Violations: []evaluator.Result{
					{
						Message: "Missing required trusted_tasks data",
					},
					{
						Message: "PipelineTask uses an untrusted task reference",
					},
				},
			},
			OverallSuccess: false,
			UsedFallback:   true,
			ImageRef:       "registry.com/image:latest",
		}

		// Test JSON output
		err := result.PrintJSON(io.Discard)
		assert.NoError(t, err)

		// Test console output
		var buf bytes.Buffer
		err = result.PrintConsole(&buf)
		assert.NoError(t, err)
		output := buf.String()
		assert.Contains(t, output, "❌ VSA validation failed")
		assert.Contains(t, output, "Predicate Outcome: failed")
		assert.Contains(t, output, "🔄 Using image validation")
		assert.Contains(t, output, "❌ Image validation failed")
		assert.Contains(t, output, "Violations: 2")
	})

	t.Run("VSA failure with fallback warnings", func(t *testing.T) {
		result := &VSAValidationResult{
			VSAPhaseResult: &VSAPhaseResult{
				Passed:           false,
				Message:          "VSA validation failed",
				PredicateOutcome: "failed",
			},
			ImageValidationResult: &ImageValidationResult{
				Passed: true,
				Warnings: []evaluator.Result{
					{
						Message: "Using deprecated task reference",
					},
				},
				Successes: []evaluator.Result{
					{
						Message: "Image validation passed",
					},
				},
			},
			OverallSuccess: true,
			UsedFallback:   true,
			ImageRef:       "registry.com/image:latest",
		}

		// Test console output
		var buf bytes.Buffer
		err := result.PrintConsole(&buf)
		assert.NoError(t, err)
		output := buf.String()
		assert.Contains(t, output, "❌ VSA validation failed")
		assert.Contains(t, output, "Predicate Outcome: failed")
		assert.Contains(t, output, "🔄 Using image validation")
		assert.Contains(t, output, "✅ Image validation passed")
		assert.Contains(t, output, "Warnings: 1")
	})

	t.Run("VSA success with predicate status", func(t *testing.T) {
		result := &VSAValidationResult{
			VSAPhaseResult: &VSAPhaseResult{
				Passed:           true,
				Message:          "VSA validation passed",
				PredicateOutcome: "passed",
			},
			ImageValidationResult: nil,
			OverallSuccess:        true,
			UsedFallback:          false,
			ImageRef:              "registry.com/image:latest",
		}

		// Test console output
		var buf bytes.Buffer
		err := result.PrintConsole(&buf)
		assert.NoError(t, err)
		output := buf.String()
		assert.Contains(t, output, "✅ VSA validation passed")
		assert.Contains(t, output, "Predicate Outcome: passed")
		assert.NotContains(t, output, "🔄 Using image validation")
	})

	t.Run("VSA failure with different predicate statuses", func(t *testing.T) {
		statuses := []string{"failed", "error", "warning", "unknown", "pending"}

		for _, status := range statuses {
			t.Run("status_"+status, func(t *testing.T) {
				result := &VSAValidationResult{
					VSAPhaseResult: &VSAPhaseResult{
						Passed:           false,
						Message:          "VSA validation failed",
						PredicateOutcome: status,
					},
					ImageValidationResult: &ImageValidationResult{
						Passed: true,
						Successes: []evaluator.Result{
							{
								Message: "Image validation passed",
							},
						},
					},
					OverallSuccess: true,
					UsedFallback:   true,
					ImageRef:       "registry.com/image:latest",
				}

				// Test console output
				var buf bytes.Buffer
				err := result.PrintConsole(&buf)
				assert.NoError(t, err)
				output := buf.String()
				assert.Contains(t, output, "❌ VSA validation failed")
				assert.Contains(t, output, "Predicate Outcome: "+status)
				assert.Contains(t, output, "🔄 Using image validation")
				assert.Contains(t, output, "✅ Image validation passed")
			})
		}
	})
}

// TestVSAValidationResult_JSON tests the JSON output format
func TestVSAValidationResult_JSON(t *testing.T) {
	t.Run("complete result with all fields", func(t *testing.T) {
		result := &VSAValidationResult{
			VSAPhaseResult: &VSAPhaseResult{
				Passed:           false,
				Message:          "VSA validation failed",
				Failed:           "VSA validation failed",
				Reason:           "VSA validation failed",
				PredicateOutcome: "failed",
			},
			ImageValidationResult: &ImageValidationResult{
				Passed: true,
				Violations: []evaluator.Result{
					{
						Message: "Test violation",
					},
				},
				Warnings: []evaluator.Result{
					{
						Message: "Test warning",
					},
				},
				Successes: []evaluator.Result{
					{
						Message: "Test success",
					},
				},
			},
			OverallSuccess: true,
			UsedFallback:   true,
			ImageRef:       "registry.com/image:latest",
		}

		// Test JSON output
		var buf bytes.Buffer
		err := result.PrintJSON(&buf)
		assert.NoError(t, err)

		// Parse JSON to verify structure
		var parsed map[string]interface{}
		err = json.Unmarshal(buf.Bytes(), &parsed)
		assert.NoError(t, err)

		// Verify required fields
		assert.Equal(t, true, parsed["overall_success"])
		assert.Equal(t, true, parsed["used_fallback"])
		assert.Equal(t, "registry.com/image:latest", parsed["image_ref"])

		// Verify VSA result
		vsaResult, ok := parsed["vsa_phase_result"].(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, false, vsaResult["passed"])
		assert.Equal(t, "VSA validation failed", vsaResult["message"])
		assert.Equal(t, "failed", vsaResult["predicate_outcome"])

		// Verify fallback result
		fallbackResult, ok := parsed["image_validation_result"].(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, true, fallbackResult["passed"])
	})

	t.Run("minimal result with only VSA", func(t *testing.T) {
		result := &VSAValidationResult{
			VSAPhaseResult: &VSAPhaseResult{
				Passed:           true,
				Message:          "VSA validation passed",
				PredicateOutcome: "passed",
			},
			ImageValidationResult: nil,
			OverallSuccess:        true,
			UsedFallback:          false,
			ImageRef:              "registry.com/image:latest",
		}

		// Test JSON output
		var buf bytes.Buffer
		err := result.PrintJSON(&buf)
		assert.NoError(t, err)

		// Parse JSON to verify structure
		var parsed map[string]interface{}
		err = json.Unmarshal(buf.Bytes(), &parsed)
		assert.NoError(t, err)

		// Verify required fields
		assert.Equal(t, true, parsed["overall_success"])
		assert.Equal(t, false, parsed["used_fallback"])
		assert.Equal(t, "registry.com/image:latest", parsed["image_ref"])

		// Verify VSA result exists
		vsaResult, ok := parsed["vsa_phase_result"].(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, true, vsaResult["passed"])

		// Verify fallback result is nil
		_, ok = parsed["image_validation_result"]
		assert.False(t, ok)
	})
}

// TestVSAValidationResult_EdgeCases tests edge cases for the unified result
func TestVSAValidationResult_EdgeCases(t *testing.T) {
	t.Run("nil VSA result", func(t *testing.T) {
		result := &VSAValidationResult{
			VSAPhaseResult:        nil,
			ImageValidationResult: nil,
			OverallSuccess:        false,
			UsedFallback:          false,
			ImageRef:              "registry.com/image:latest",
		}

		// Test console output
		var buf bytes.Buffer
		err := result.PrintConsole(&buf)
		assert.NoError(t, err)
		output := buf.String()
		assert.NotContains(t, output, "✅ VSA validation passed")
		assert.NotContains(t, output, "❌ VSA validation failed")
		assert.NotContains(t, output, "🔄 Using image validation")
	})

	t.Run("empty predicate status", func(t *testing.T) {
		result := &VSAValidationResult{
			VSAPhaseResult: &VSAPhaseResult{
				Passed:           true,
				Message:          "VSA validation passed",
				PredicateOutcome: "", // Empty status
			},
			ImageValidationResult: nil,
			OverallSuccess:        true,
			UsedFallback:          false,
			ImageRef:              "registry.com/image:latest",
		}

		// Test console output
		var buf bytes.Buffer
		err := result.PrintConsole(&buf)
		assert.NoError(t, err)
		output := buf.String()
		assert.Contains(t, output, "✅ VSA validation passed")
		assert.NotContains(t, output, "Predicate Outcome:")
	})

	t.Run("fallback with empty violations and warnings", func(t *testing.T) {
		result := &VSAValidationResult{
			VSAPhaseResult: &VSAPhaseResult{
				Passed:           false,
				Message:          "VSA validation failed",
				PredicateOutcome: "failed",
			},
			ImageValidationResult: &ImageValidationResult{
				Passed:     true,
				Violations: []evaluator.Result{}, // Empty
				Warnings:   []evaluator.Result{}, // Empty
				Successes: []evaluator.Result{
					{
						Message: "Image validation passed",
					},
				},
			},
			OverallSuccess: true,
			UsedFallback:   true,
			ImageRef:       "registry.com/image:latest",
		}

		// Test console output
		var buf bytes.Buffer
		err := result.PrintConsole(&buf)
		assert.NoError(t, err)
		output := buf.String()
		assert.Contains(t, output, "❌ VSA validation failed")
		assert.Contains(t, output, "🔄 Using image validation")
		assert.Contains(t, output, "✅ Image validation passed")
		assert.NotContains(t, output, "Violations:")
		assert.NotContains(t, output, "Warnings:")
	})
}

// TestVSAValidationResult_OutputOrder tests the output order is correct
func TestVSAValidationResult_OutputOrder(t *testing.T) {
	t.Run("predicate status appears before VSA validation result", func(t *testing.T) {
		result := &VSAValidationResult{
			VSAPhaseResult: &VSAPhaseResult{
				Passed:           false,
				Message:          "VSA validation failed",
				PredicateOutcome: "failed",
			},
			ImageValidationResult: &ImageValidationResult{
				Passed: true,
				Successes: []evaluator.Result{
					{
						Message: "Image validation passed",
					},
				},
			},
			OverallSuccess: true,
			UsedFallback:   true,
			ImageRef:       "registry.com/image:latest",
		}

		// Test console output
		var buf bytes.Buffer
		err := result.PrintConsole(&buf)
		assert.NoError(t, err)
		output := buf.String()

		// Find positions of key elements
		predicateStatusPos := bytes.Index([]byte(output), []byte("Predicate Outcome: failed"))
		vsaFailedPos := bytes.Index([]byte(output), []byte("❌ VSA validation failed"))
		fallbackPos := bytes.Index([]byte(output), []byte("🔄 Using image validation"))

		// Predicate status should appear before VSA validation result
		assert.True(t, predicateStatusPos < vsaFailedPos, "Predicate status should appear before VSA validation result")
		// VSA validation result should appear before fallback message
		assert.True(t, vsaFailedPos < fallbackPos, "VSA validation result should appear before fallback message")
	})
}

func TestVSAValidationResult_PrintJSON(t *testing.T) {
	tests := []struct {
		name     string
		result   *VSAValidationResult
		expected string
	}{
		{
			name: "VSA success, no fallback",
			result: &VSAValidationResult{
				VSAPhaseResult: &VSAPhaseResult{
					Passed:  true,
					Message: "VSA validation successful",
				},
				ImageValidationResult: nil,
				OverallSuccess:        true,
				UsedFallback:          false,
				ImageRef:              "registry.com/image:tag",
				Summary:               nil,
			},
			expected: `{
  "vsa_phase_result": {
    "passed": true,
    "message": "VSA validation successful"
  },
  "overall_success": true,
  "used_fallback": false,
  "image_ref": "registry.com/image:tag"
}`,
		},
		{
			name: "VSA failure, fallback success",
			result: &VSAValidationResult{
				VSAPhaseResult: &VSAPhaseResult{
					Passed:  false,
					Message: "VSA not found",
					Failed:  "VSA not found",
					Reason:  "VSA validation failed",
				},
				ImageValidationResult: &ImageValidationResult{
					Passed:     true,
					Violations: []evaluator.Result{},
					Warnings:   []evaluator.Result{},
					Successes: []evaluator.Result{
						{
							Message: "Policy check passed",
							Metadata: map[string]interface{}{
								"code": "policy.success.1",
							},
						},
					},
					Summary: &ImageValidationSummary{
						TotalViolations: 0,
						TotalWarnings:   0,
						TotalSuccesses:  1,
					},
				},
				OverallSuccess: true,
				UsedFallback:   true,
				ImageRef:       "registry.com/image:tag",
				Summary: &ResultSummary{
					TotalViolations: 0,
					TotalWarnings:   0,
					TotalSuccesses:  1,
				},
			},
			expected: `{
  "vsa_phase_result": {
    "passed": false,
    "message": "VSA not found",
    "failed": "VSA not found",
    "reason": "VSA validation failed"
  },
  "image_validation_result": {
    "passed": true,
    "successes": [
      {
        "msg": "Policy check passed",
        "metadata": {
          "code": "policy.success.1"
        }
      }
    ],
    "summary": {
      "total_violations": 0,
      "total_warnings": 0,
      "total_successes": 1
    }
  },
  "overall_success": true,
  "used_fallback": true,
  "image_ref": "registry.com/image:tag",
  "summary": {
    "total_violations": 0,
    "total_warnings": 0,
    "total_successes": 1
  }
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tt.result.PrintJSON(&buf)
			assert.NoError(t, err)

			// Parse both JSON strings to compare structure
			var actual, expected map[string]interface{}
			err = json.Unmarshal(buf.Bytes(), &actual)
			assert.NoError(t, err)

			err = json.Unmarshal([]byte(tt.expected), &expected)
			assert.NoError(t, err)

			assert.Equal(t, expected, actual)
		})
	}
}

func TestVSAValidationResult_PrintConsole(t *testing.T) {
	tests := []struct {
		name     string
		result   *VSAValidationResult
		expected string
	}{
		{
			name: "VSA success, no fallback",
			result: &VSAValidationResult{
				VSAPhaseResult: &VSAPhaseResult{
					Passed:  true,
					Message: "VSA validation successful",
				},
				ImageValidationResult: nil,
				OverallSuccess:        true,
				UsedFallback:          false,
				ImageRef:              "registry.com/image:tag",
			},
			expected: `✅ VSA validation passed
   VSA validation successful

Summary:
  VSA Status: Passed
  Overall Status: ✅ PASSED
`,
		},
		{
			name: "VSA failure, fallback success",
			result: &VSAValidationResult{
				VSAPhaseResult: &VSAPhaseResult{
					Passed:  false,
					Message: "VSA not found",
				},
				ImageValidationResult: &ImageValidationResult{
					Passed:     true,
					Violations: []evaluator.Result{},
					Warnings:   []evaluator.Result{},
					Successes: []evaluator.Result{
						{
							Message: "Policy check passed",
						},
					},
				},
				OverallSuccess: true,
				UsedFallback:   true,
				ImageRef:       "registry.com/image:tag",
			},
			expected: `❌ VSA validation failed
   VSA not found
🔄 Using image validation...
✅ Image validation passed

Summary:
  VSA Status: Failed
  Image Validation Status: Passed
  Overall Status: ✅ PASSED (used fallback)
`,
		},
		{
			name: "VSA failure, fallback failure with violations",
			result: &VSAValidationResult{
				VSAPhaseResult: &VSAPhaseResult{
					Passed:  false,
					Message: "VSA not found",
				},
				ImageValidationResult: &ImageValidationResult{
					Passed: false,
					Violations: []evaluator.Result{
						{
							Message: "Policy violation",
						},
					},
					Warnings:  []evaluator.Result{},
					Successes: []evaluator.Result{},
				},
				OverallSuccess: false,
				UsedFallback:   true,
				ImageRef:       "registry.com/image:tag",
			},
			expected: `❌ VSA validation failed
   VSA not found
🔄 Using image validation...
❌ Image validation failed
   Violations: 1

Summary:
  VSA Status: Failed
  Image Validation Status: Failed
  Overall Status: ❌ FAILED (fallback also failed)
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tt.result.PrintConsole(&buf)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, buf.String())
		})
	}
}
