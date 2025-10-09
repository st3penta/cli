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

package vsa

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/evaluator"
)

func TestValidationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		error    *ValidationError
		expected string
	}{
		{
			name:     "nil error",
			error:    nil,
			expected: "",
		},
		{
			name: "single cause",
			error: &ValidationError{
				Message: "VSA validation failed",
				Causes: []Cause{
					{
						Type:    ErrorTypeVSA,
						Message: "VSA validation failed",
						Details: "Signature verification failed",
					},
				},
			},
			expected: "VSA validation failed\n- vsa: VSA validation failed\n  Details: Signature verification failed",
		},
		{
			name: "multiple causes",
			error: &ValidationError{
				Message: "Both VSA and fallback validation failed",
				Causes: []Cause{
					{
						Type:    ErrorTypeVSA,
						Message: "VSA validation failed",
						Details: "Network timeout",
					},
					{
						Type:    ErrorTypeFallback,
						Message: "Fallback validation failed",
						Details: "Policy violations found",
					},
				},
			},
			expected: "Both VSA and fallback validation failed\n- vsa: VSA validation failed\n  Details: Network timeout\n- fallback: Fallback validation failed\n  Details: Policy violations found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.error.Error()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidationError_HumanReadable(t *testing.T) {
	tests := []struct {
		name     string
		error    *ValidationError
		expected string
	}{
		{
			name:     "nil error",
			error:    nil,
			expected: "",
		},
		{
			name: "single cause with sub-causes",
			error: &ValidationError{
				Message: "VSA validation failed",
				Causes: []Cause{
					{
						Type:      ErrorTypeVSA,
						Message:   "VSA validation failed",
						Details:   "Signature verification failed",
						Timestamp: "2023-01-01T00:00:00Z",
						SubCauses: []Cause{
							{
								Type:    ErrorTypeSignature,
								Message: "Invalid signature",
								Details: "Public key mismatch",
							},
						},
					},
				},
			},
			expected: `❌ VSA validation failed

Vsa Failure
  Message: VSA validation failed
  Details: Signature verification failed
  Time: 2023-01-01T00:00:00Z
  Violations:
    - Invalid signature
`,
		},
		{
			name: "multiple causes",
			error: &ValidationError{
				Message: "Both VSA and fallback validation failed",
				Causes: []Cause{
					{
						Type:      ErrorTypeVSA,
						Message:   "VSA validation failed",
						Details:   "Network timeout",
						Timestamp: "2023-01-01T00:00:00Z",
					},
					{
						Type:      ErrorTypeFallback,
						Message:   "Fallback validation failed",
						Details:   "Policy violations found",
						Timestamp: "2023-01-01T00:00:00Z",
						SubCauses: []Cause{
							{
								Type:    ErrorTypePolicy,
								Message: "High severity vulnerability found",
								Details: "CVE-2023-1234",
							},
						},
					},
				},
			},
			expected: `❌ Both VSA and fallback validation failed

Vsa Failure
  Message: VSA validation failed
  Details: Network timeout
  Time: 2023-01-01T00:00:00Z

Fallback Failure
  Message: Fallback validation failed
  Details: Policy violations found
  Time: 2023-01-01T00:00:00Z
  Violations:
    - High severity vulnerability found
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.error.HumanReadable()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildValidationError(t *testing.T) {
	tests := []struct {
		name           string
		vsaResult      *ValidationResult
		fallbackResult *ImageValidationResult
		vsaErr         error
		fallbackErr    error
		expected       *ValidationError
	}{
		{
			name:           "no errors",
			vsaResult:      &ValidationResult{Passed: true},
			fallbackResult: &ImageValidationResult{Passed: true},
			expected:       nil,
		},
		{
			name: "VSA error only",
			vsaResult: &ValidationResult{
				Passed:           false,
				Message:          "Signature verification failed",
				PredicateOutcome: "failed",
			},
			fallbackResult: &ImageValidationResult{Passed: true},
			expected: &ValidationError{
				Message: "Vsa validation failed",
				Causes: []Cause{
					{
						Type:      ErrorTypeVSA,
						Message:   "VSA validation failed",
						Details:   "Signature verification failed",
						Timestamp: "", // Will be set by function
						Severity:  SeverityError,
						SubCauses: []Cause{
							{
								Type:    ErrorTypePolicy,
								Message: "Predicate status: failed",
								Details: "Signature verification failed",
							},
						},
					},
				},
			},
		},
		{
			name:   "VSA network error",
			vsaErr: errors.New("network timeout: failed to connect to rekor"),
			expected: &ValidationError{
				Message: "Vsa validation failed",
				Causes: []Cause{
					{
						Type:      ErrorTypeVSA,
						Message:   "VSA validation failed",
						Details:   "network timeout: failed to connect to rekor",
						Timestamp: "", // Will be set by function
						Severity:  SeverityError,
						SubCauses: []Cause{
							{
								Type:    ErrorTypeTimeout,
								Message: "VSA retrieval timeout",
								Details: "network timeout: failed to connect to rekor",
							},
						},
					},
				},
			},
		},
		{
			name:   "VSA signature error",
			vsaErr: errors.New("signature verification failed: invalid signature"),
			expected: &ValidationError{
				Message: "Vsa validation failed",
				Causes: []Cause{
					{
						Type:      ErrorTypeVSA,
						Message:   "VSA validation failed",
						Details:   "signature verification failed: invalid signature",
						Timestamp: "", // Will be set by function
						Severity:  SeverityError,
						SubCauses: []Cause{
							{
								Type:    ErrorTypeSignature,
								Message: "Signature verification failed",
								Details: "signature verification failed: invalid signature",
							},
						},
					},
				},
			},
		},
		{
			name: "fallback error only",
			fallbackResult: &ImageValidationResult{
				Passed: false,
				Violations: []evaluator.Result{
					{
						Message: "High severity vulnerability found",
					},
				},
			},
			expected: &ValidationError{
				Message: "Fallback validation failed",
				Causes: []Cause{
					{
						Type:      ErrorTypeFallback,
						Message:   "Fallback validation failed",
						Details:   "1 policy violations found",
						Timestamp: "", // Will be set by function
						Severity:  SeverityError,
						SubCauses: []Cause{
							{
								Type:    ErrorTypePolicy,
								Message: "High severity vulnerability found",
								Details: "Policy violation",
							},
						},
					},
				},
			},
		},
		{
			name: "both VSA and fallback errors",
			vsaResult: &ValidationResult{
				Passed:           false,
				Message:          "VSA validation failed",
				PredicateOutcome: "failed",
			},
			fallbackResult: &ImageValidationResult{
				Passed: false,
				Violations: []evaluator.Result{
					{
						Message: "Policy violation",
					},
				},
			},
			expected: &ValidationError{
				Message: "Both VSA and fallback validation failed",
				Causes: []Cause{
					{
						Type:      ErrorTypeVSA,
						Message:   "VSA validation failed",
						Details:   "VSA validation failed",
						Timestamp: "", // Will be set by function
						Severity:  SeverityError,
						SubCauses: []Cause{
							{
								Type:    ErrorTypePolicy,
								Message: "Predicate status: failed",
								Details: "VSA validation failed",
							},
						},
					},
					{
						Type:      ErrorTypeFallback,
						Message:   "Fallback validation failed",
						Details:   "1 policy violations found",
						Timestamp: "", // Will be set by function
						Severity:  SeverityError,
						SubCauses: []Cause{
							{
								Type:    ErrorTypePolicy,
								Message: "Policy violation",
								Details: "Policy violation",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildValidationError(tt.vsaResult, tt.fallbackResult, tt.vsaErr, tt.fallbackErr)

			if tt.expected == nil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			assert.Equal(t, tt.expected.Message, result.Message)
			assert.Len(t, result.Causes, len(tt.expected.Causes))

			for i, expectedCause := range tt.expected.Causes {
				actualCause := result.Causes[i]
				assert.Equal(t, expectedCause.Type, actualCause.Type)
				assert.Equal(t, expectedCause.Message, actualCause.Message)
				assert.Equal(t, expectedCause.Details, actualCause.Details)
				assert.Equal(t, expectedCause.Severity, actualCause.Severity)
				assert.NotEmpty(t, actualCause.Timestamp) // Should be set

				// Check sub-causes
				assert.Len(t, actualCause.SubCauses, len(expectedCause.SubCauses))
				for j, expectedSubCause := range expectedCause.SubCauses {
					actualSubCause := actualCause.SubCauses[j]
					assert.Equal(t, expectedSubCause.Type, actualSubCause.Type)
					assert.Equal(t, expectedSubCause.Message, actualSubCause.Message)
					assert.Equal(t, expectedSubCause.Details, actualSubCause.Details)
				}
			}
		})
	}
}

func TestBuildNetworkError(t *testing.T) {
	err := errors.New("connection refused")
	validationErr := BuildNetworkError("fetch VSA", err)

	require.NotNil(t, validationErr)
	assert.Equal(t, "Network operation failed: fetch VSA", validationErr.Message)
	assert.Len(t, validationErr.Causes, 1)

	cause := validationErr.Causes[0]
	assert.Equal(t, ErrorTypeNetwork, cause.Type)
	assert.Equal(t, "Failed to fetch VSA", cause.Message)
	assert.Equal(t, "connection refused", cause.Details)
	assert.Equal(t, SeverityError, cause.Severity)
	assert.NotEmpty(t, cause.Timestamp)
}

func TestBuildTimeoutError(t *testing.T) {
	timeout := 30 * time.Second
	validationErr := BuildTimeoutError("VSA retrieval", timeout)

	require.NotNil(t, validationErr)
	assert.Equal(t, "Operation timed out: VSA retrieval", validationErr.Message)
	assert.Len(t, validationErr.Causes, 1)

	cause := validationErr.Causes[0]
	assert.Equal(t, ErrorTypeTimeout, cause.Type)
	assert.Equal(t, "Timeout after 30s", cause.Message)
	assert.Contains(t, cause.Details, "Operation 'VSA retrieval' exceeded timeout of 30s")
	assert.Equal(t, SeverityError, cause.Severity)
	assert.NotEmpty(t, cause.Timestamp)
}

func TestBuildVSACause_ErrorCategorization(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected []Cause
	}{
		{
			name: "signature error",
			err:  errors.New("signature verification failed: invalid key"),
			expected: []Cause{
				{
					Type:    ErrorTypeSignature,
					Message: "Signature verification failed",
					Details: "signature verification failed: invalid key",
				},
			},
		},
		{
			name: "timeout error",
			err:  errors.New("context deadline exceeded: timeout"),
			expected: []Cause{
				{
					Type:    ErrorTypeTimeout,
					Message: "VSA retrieval timeout",
					Details: "context deadline exceeded: timeout",
				},
			},
		},
		{
			name: "network error",
			err:  errors.New("network error: connection refused"),
			expected: []Cause{
				{
					Type:    ErrorTypeNetwork,
					Message: "Network error during VSA retrieval",
					Details: "network error: connection refused",
				},
			},
		},
		{
			name: "connection error",
			err:  errors.New("connection failed: dial tcp"),
			expected: []Cause{
				{
					Type:    ErrorTypeNetwork,
					Message: "Network error during VSA retrieval",
					Details: "connection failed: dial tcp",
				},
			},
		},
		{
			name:     "generic error",
			err:      errors.New("some other error"),
			expected: []Cause{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cause := buildVSACause(nil, tt.err)
			assert.Equal(t, ErrorTypeVSA, cause.Type)
			assert.Equal(t, "VSA validation failed", cause.Message)
			assert.Equal(t, tt.err.Error(), cause.Details)
			assert.Len(t, cause.SubCauses, len(tt.expected))

			for i, expectedSubCause := range tt.expected {
				actualSubCause := cause.SubCauses[i]
				assert.Equal(t, expectedSubCause.Type, actualSubCause.Type)
				assert.Equal(t, expectedSubCause.Message, actualSubCause.Message)
				assert.Equal(t, expectedSubCause.Details, actualSubCause.Details)
			}
		})
	}
}

func TestBuildFallbackCause_WithViolations(t *testing.T) {
	fallbackResult := &ImageValidationResult{
		Passed: false,
		Violations: []evaluator.Result{
			{
				Message: "High severity vulnerability",
			},
			{
				Message: "Medium severity issue",
			},
		},
		Warnings: []evaluator.Result{
			{
				Message: "Low severity warning",
			},
		},
	}

	cause := buildFallbackCause(fallbackResult, nil)

	assert.Equal(t, ErrorTypeFallback, cause.Type)
	assert.Equal(t, "Fallback validation failed", cause.Message)
	assert.Equal(t, "2 policy violations found", cause.Details)
	assert.Len(t, cause.SubCauses, 3) // 2 violations + 1 warning

	// Check violations
	assert.Equal(t, ErrorTypePolicy, cause.SubCauses[0].Type)
	assert.Equal(t, "High severity vulnerability", cause.SubCauses[0].Message)
	assert.Equal(t, "Policy violation", cause.SubCauses[0].Details)
	assert.Equal(t, SeverityError, cause.SubCauses[0].Severity)

	assert.Equal(t, ErrorTypePolicy, cause.SubCauses[1].Type)
	assert.Equal(t, "Medium severity issue", cause.SubCauses[1].Message)
	assert.Equal(t, "Policy violation", cause.SubCauses[1].Details)
	assert.Equal(t, SeverityError, cause.SubCauses[1].Severity)

	// Check warnings
	assert.Equal(t, ErrorTypePolicy, cause.SubCauses[2].Type)
	assert.Equal(t, "Low severity warning", cause.SubCauses[2].Message)
	assert.Equal(t, "Policy warning", cause.SubCauses[2].Details)
	assert.Equal(t, SeverityWarning, cause.SubCauses[2].Severity)
}

func TestValidationError_JSONSerialization(t *testing.T) {
	validationErr := &ValidationError{
		Message: "Both VSA and fallback validation failed",
		Causes: []Cause{
			{
				Type:      ErrorTypeVSA,
				Message:   "VSA validation failed",
				Details:   "Signature verification failed",
				Timestamp: "2023-01-01T00:00:00Z",
				Severity:  SeverityError,
				SubCauses: []Cause{
					{
						Type:    ErrorTypeSignature,
						Message: "Invalid signature",
						Details: "Public key mismatch",
					},
				},
			},
		},
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(validationErr)
	require.NoError(t, err)

	// Verify JSON contains expected fields
	jsonStr := string(jsonData)
	assert.Contains(t, jsonStr, `"message":"Both VSA and fallback validation failed"`)
	assert.Contains(t, jsonStr, `"type":"vsa"`)
	assert.Contains(t, jsonStr, `"type":"signature"`)
	assert.Contains(t, jsonStr, `"severity":"error"`)
}
