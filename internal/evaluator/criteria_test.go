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

package evaluator

import (
	"testing"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/policy"
)

func TestLen(t *testing.T) {
	tests := []struct {
		name        string
		criteria    *Criteria
		expectedLen int
	}{
		{
			name: "Empty Criteria",
			criteria: &Criteria{
				digestItems:  map[string][]string{},
				defaultItems: []string{},
			},
			expectedLen: 0,
		},
		{
			name: "Only Default Items",
			criteria: &Criteria{
				digestItems:  map[string][]string{},
				defaultItems: []string{"default1", "default2"},
			},
			expectedLen: 2,
		},
		{
			name: "Only Digest Items",
			criteria: &Criteria{
				digestItems: map[string][]string{
					"key1": {"value1", "value2"},
					"key2": {"value3"},
				},
				defaultItems: []string{},
			},
			expectedLen: 3,
		},
		{
			name: "Both Default and Digest Items",
			criteria: &Criteria{
				digestItems: map[string][]string{
					"key1": {"value1", "value2"},
					"key2": {"value3"},
				},
				defaultItems: []string{"default1", "default2"},
			},
			expectedLen: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.criteria.len(); got != tt.expectedLen {
				t.Errorf("Criteria.len() = %d, want %d", got, tt.expectedLen)
			}
		})
	}
}

func TestAddItem(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    string
		initial  *Criteria
		expected *Criteria
	}{
		{
			name:  "Add to defaultItems",
			key:   "",
			value: "defaultValue",
			initial: &Criteria{
				defaultItems: []string{},
				digestItems:  make(map[string][]string),
			},
			expected: &Criteria{
				defaultItems: []string{"defaultValue"},
				digestItems:  make(map[string][]string),
			},
		},
		{
			name:  "Add to digestItems",
			key:   "key1",
			value: "digestValue1",
			initial: &Criteria{
				defaultItems: []string{},
				digestItems:  make(map[string][]string),
			},
			expected: &Criteria{
				defaultItems: []string{},
				digestItems: map[string][]string{
					"key1": {"digestValue1"},
				},
			},
		},
		{
			name:  "Add to existing digestItems",
			key:   "key1",
			value: "digestValue2",
			initial: &Criteria{
				defaultItems: []string{},
				digestItems: map[string][]string{
					"key1": {"digestValue1"},
				},
			},
			expected: &Criteria{
				defaultItems: []string{},
				digestItems: map[string][]string{
					"key1": {"digestValue1", "digestValue2"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.initial.addItem(tt.key, tt.value)
			require.Equal(t, tt.initial, tt.expected)
		})
	}
}

func TestAddArray(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		values   []string
		initial  *Criteria
		expected *Criteria
	}{
		{
			name:   "Add to defaultItems",
			key:    "",
			values: []string{"defaultValue1", "defaultValue2"},
			initial: &Criteria{
				defaultItems: []string{},
				digestItems:  make(map[string][]string),
			},
			expected: &Criteria{
				defaultItems: []string{"defaultValue1", "defaultValue2"},
				digestItems:  make(map[string][]string),
			},
		},
		{
			name:   "Add to digestItems",
			key:    "key1",
			values: []string{"digestValue1", "digestValue2"},
			initial: &Criteria{
				defaultItems: []string{},
				digestItems:  make(map[string][]string),
			},
			expected: &Criteria{
				defaultItems: []string{},
				digestItems: map[string][]string{
					"key1": {"digestValue1", "digestValue2"},
				},
			},
		},
		{
			name:   "Add to existing digestItems",
			key:    "key1",
			values: []string{"digestValue2", "digestValue3"},
			initial: &Criteria{
				defaultItems: []string{},
				digestItems: map[string][]string{
					"key1": {"digestValue1"},
				},
			},
			expected: &Criteria{
				defaultItems: []string{},
				digestItems: map[string][]string{
					"key1": {"digestValue1", "digestValue2", "digestValue3"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.initial.addArray(tt.key, tt.values)
			require.Equal(t, tt.initial, tt.expected)
		})
	}
}

func TestGet(t *testing.T) {
	c := &Criteria{
		digestItems: map[string][]string{
			"quay.io/test/ec-test": {"item"},
			"sha256:2c5e3b2f1e2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c": {"item-digest"},
		},
		defaultItems: []string{"default1", "default2"},
	}
	tests := []struct {
		name     string
		key      string
		expected []string
	}{
		{
			name:     "test with image ref",
			key:      "quay.io/test/ec-test",
			expected: []string{"item", "default1", "default2"},
		},
		{
			name:     "test with image ref and tag",
			key:      "quay.io/test/ec-test:latest",
			expected: []string{"item", "default1", "default2"},
		},
		{
			name:     "test with image digest",
			key:      "quay.io/test/ec@sha256:2c5e3b2f1e2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c",
			expected: []string{"item-digest", "default1", "default2"},
		},
		{
			name:     "test key doesn't exist",
			key:      "unknown",
			expected: []string{"default1", "default2"},
		},
		{
			name:     "test with image and bad digest",
			key:      "quay.io/test/ec-test@sha256:2c5e3b2f1e2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d",
			expected: []string{"default1", "default2"},
		},
		{
			name:     "test with image not set",
			expected: []string{"default1", "default2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, c.get(tt.key))
		})
	}
}

// MockConfigProvider implements ConfigProvider interface for testing
type MockConfigProvider struct {
	effectiveTime time.Time
}

func (m *MockConfigProvider) EffectiveTime() time.Time {
	return m.effectiveTime
}

func (m *MockConfigProvider) SigstoreOpts() (policy.SigstoreOpts, error) {
	return policy.SigstoreOpts{}, nil
}

func (m *MockConfigProvider) Spec() ecc.EnterpriseContractPolicySpec {
	return ecc.EnterpriseContractPolicySpec{}
}

func TestCollectVolatileConfigItems(t *testing.T) {
	// Create a fixed time for testing
	fixedTime := time.Date(2025, 8, 18, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name             string
		items            *Criteria
		volatileCriteria []ecc.VolatileCriteria
		configProvider   ConfigProvider
		expectedItems    *Criteria
		expectedSuccess  bool
	}{
		{
			name: "Successful scenario - criteria within time range",
			items: &Criteria{
				digestItems:  make(map[string][]string),
				defaultItems: []string{"existing-item"},
			},
			volatileCriteria: []ecc.VolatileCriteria{
				{
					Value:          "volatile-item-1",
					EffectiveOn:    "2025-08-01T00:00:00Z",
					EffectiveUntil: "2025-08-31T23:59:59Z",
					ImageRef:       "quay.io/test/image:latest",
				},
				{
					Value:          "volatile-item-2",
					EffectiveOn:    "2025-08-10T00:00:00Z",
					EffectiveUntil: "2025-08-20T23:59:59Z",
					ImageDigest:    "sha256:abc123",
				},
			},
			configProvider: &MockConfigProvider{effectiveTime: fixedTime},
			expectedItems: &Criteria{
				digestItems: map[string][]string{
					"quay.io/test/image:latest": {"volatile-item-1"},
					"sha256:abc123":             {"volatile-item-2"},
				},
				defaultItems: []string{"existing-item"},
			},
			expectedSuccess: true,
		},
		{
			name: "Failed scenario - criteria outside time range",
			items: &Criteria{
				digestItems:  make(map[string][]string),
				defaultItems: []string{"existing-item"},
			},
			volatileCriteria: []ecc.VolatileCriteria{
				{
					Value:          "expired-item",
					EffectiveOn:    "2025-07-01T00:00:00Z",
					EffectiveUntil: "2025-07-31T23:59:59Z",
					ImageUrl:       "quay.io/test/expired",
				},
				{
					Value:          "future-item",
					EffectiveOn:    "2025-09-01T00:00:00Z",
					EffectiveUntil: "2025-09-30T23:59:59Z",
					ImageRef:       "quay.io/test/future",
				},
			},
			configProvider: &MockConfigProvider{effectiveTime: fixedTime},
			expectedItems: &Criteria{
				digestItems:  make(map[string][]string),
				defaultItems: []string{"existing-item"},
			},
			expectedSuccess: true, // Function doesn't fail, just doesn't add items
		},
		{
			name: "Warning scenario - invalid time formats",
			items: &Criteria{
				digestItems:  make(map[string][]string),
				defaultItems: []string{"existing-item"},
			},
			volatileCriteria: []ecc.VolatileCriteria{
				{
					Value:          "partial-invalid-item",
					EffectiveOn:    "2025-08-01T00:00:00Z", // Valid format
					EffectiveUntil: "not-a-date",           // Invalid format
					ImageDigest:    "sha256:def456",
				},
			},
			configProvider: &MockConfigProvider{effectiveTime: fixedTime},
			expectedItems: &Criteria{
				digestItems: map[string][]string{
					"sha256:def456": {"partial-invalid-item"},
				},
				defaultItems: []string{"existing-item"},
			},
			expectedSuccess: true, // Function handles invalid times gracefully
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of the initial items to avoid modifying the test data
			initialItems := &Criteria{
				digestItems:  make(map[string][]string),
				defaultItems: make([]string, len(tt.items.defaultItems)),
			}
			copy(initialItems.defaultItems, tt.items.defaultItems)
			for k, v := range tt.items.digestItems {
				initialItems.digestItems[k] = make([]string, len(v))
				copy(initialItems.digestItems[k], v)
			}

			// Call the function
			result := collectVolatileConfigItems(initialItems, tt.volatileCriteria, tt.configProvider)

			// Verify the result
			if tt.expectedSuccess {
				require.Equal(t, tt.expectedItems.defaultItems, result.defaultItems, "defaultItems mismatch")
				require.Equal(t, len(tt.expectedItems.digestItems), len(result.digestItems), "digestItems count mismatch")

				for expectedKey, expectedValues := range tt.expectedItems.digestItems {
					actualValues, exists := result.digestItems[expectedKey]
					require.True(t, exists, "Expected key %s not found in result", expectedKey)
					require.Equal(t, expectedValues, actualValues, "Values mismatch for key %s", expectedKey)
				}
			}
		})
	}
}
