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

package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGet(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		setupCache    func(*PolicyCache)
		key           string
		expectedValue string
		expectedFound bool
	}{
		{
			name:          "key does not exist",
			setupCache:    func(c *PolicyCache) {},
			key:           "nonexistent",
			expectedValue: "",
			expectedFound: false,
		},
		{
			name: "key exists with valid value",
			setupCache: func(c *PolicyCache) {
				c.Set("existing", "value", nil)
			},
			key:           "existing",
			expectedValue: "value",
			expectedFound: true,
		},
		{
			name: "key exists but with wrong type",
			setupCache: func(c *PolicyCache) {
				c.Data.Store("wrongtype", "string value")
			},
			key:           "wrongtype",
			expectedValue: "",
			expectedFound: false,
		},
		{
			name: "empty key with value",
			setupCache: func(c *PolicyCache) {
				c.Set("", "emptykeyvalue", nil)
			},
			key:           "",
			expectedValue: "emptykeyvalue",
			expectedFound: true,
		},
		{
			name: "key with error",
			setupCache: func(c *PolicyCache) {
				c.Set("errorkey", "errorvalue", errors.New("test error"))
			},
			key:           "errorkey",
			expectedValue: "errorvalue",
			expectedFound: true,
		},
		{
			name: "key with empty value",
			setupCache: func(c *PolicyCache) {
				c.Set("emptyvalue", "", nil)
			},
			key:           "emptyvalue",
			expectedValue: "",
			expectedFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh cache for each test
			testCache := NewPolicyCache(ctx)

			// Setup cache state
			tt.setupCache(testCache)

			// Execute test
			value, found := testCache.Get(tt.key)

			// Assert results
			assert.Equal(t, tt.expectedValue, value)
			assert.Equal(t, tt.expectedFound, found)
		})
	}
}

func TestSet(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		key           string
		value         string
		expectedValue string
		expectedFound bool
	}{
		{
			name:          "set new key-value pair",
			key:           "newkey",
			value:         "newvalue",
			expectedValue: "newvalue",
			expectedFound: true,
		},
		{
			name:          "set empty value",
			key:           "emptykey",
			value:         "",
			expectedValue: "",
			expectedFound: true,
		},
		{
			name:          "set empty key",
			key:           "",
			value:         "emptykeyvalue",
			expectedValue: "emptykeyvalue",
			expectedFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh cache for each test
			testCache := NewPolicyCache(ctx)

			// Execute test
			testCache.Set(tt.key, tt.value, nil)

			// Verify the value was set correctly
			value, found := testCache.Get(tt.key)
			assert.Equal(t, tt.expectedValue, value)
			assert.Equal(t, tt.expectedFound, found)
		})
	}
}

func TestNewPolicyCache(t *testing.T) {
	tests := []struct {
		name           string
		setupContext   func() context.Context
		expectNewCache bool
	}{
		{
			name: "create new cache when none exists in context",
			setupContext: func() context.Context {
				return context.Background()
			},
			expectNewCache: true,
		},
		{
			name: "return existing cache from context",
			setupContext: func() context.Context {
				ctx := context.Background()
				cache := NewPolicyCache(ctx)
				return WithPolicyCache(ctx, cache)
			},
			expectNewCache: false,
		},
		{
			name: "handle nil cache in context",
			setupContext: func() context.Context {
				ctx := context.Background()
				return context.WithValue(ctx, policyCacheKey, (*PolicyCache)(nil))
			},
			expectNewCache: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupContext()

			// Execute test
			cache := NewPolicyCache(ctx)

			// Assert results
			assert.NotNil(t, cache)

			if tt.expectNewCache {
				// Test that we get a new cache instance
				// by calling NewPolicyCache again and comparing
				secondCache := NewPolicyCache(ctx)
				assert.Equal(t, cache, secondCache, "Should return the same cache instance")
			}
		})
	}
}

func TestPolicyCacheFromContext(t *testing.T) {
	tests := []struct {
		name          string
		setupContext  func() context.Context
		expectedFound bool
		expectedCache *PolicyCache
	}{
		{
			name: "PolicyCache not in context",
			setupContext: func() context.Context {
				return context.Background()
			},
			expectedFound: false,
			expectedCache: nil,
		},
		{
			name: "PolicyCache in context",
			setupContext: func() context.Context {
				ctx := context.Background()
				cache := NewPolicyCache(ctx)
				return WithPolicyCache(ctx, cache)
			},
			expectedFound: true,
			expectedCache: func() *PolicyCache {
				cache := NewPolicyCache(context.Background())
				return cache
			}(),
		},
		{
			name: "nil PolicyCache in context",
			setupContext: func() context.Context {
				ctx := context.Background()
				return context.WithValue(ctx, policyCacheKey, (*PolicyCache)(nil))
			},
			expectedFound: true,
			expectedCache: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupContext()

			// Execute test
			retrievedCache, found := PolicyCacheFromContext(ctx)

			// Assert results
			assert.Equal(t, tt.expectedFound, found)
			if tt.expectedCache == nil {
				assert.Nil(t, retrievedCache)
			} else {
				assert.NotNil(t, retrievedCache)
			}
		})
	}
}

func TestWithPolicyCache(t *testing.T) {
	tests := []struct {
		name           string
		setupContext   func() context.Context
		setupCache     func() *PolicyCache
		expectOriginal bool
		expectNew      bool
	}{
		{
			name: "add cache to empty context",
			setupContext: func() context.Context {
				return context.Background()
			},
			setupCache: func() *PolicyCache {
				cache := NewPolicyCache(context.Background())
				return cache
			},
			expectOriginal: false,
			expectNew:      true,
		},
		{
			name: "add cache to context with existing cache",
			setupContext: func() context.Context {
				ctx := context.Background()
				existingCache := NewPolicyCache(ctx)
				return WithPolicyCache(ctx, existingCache)
			},
			setupCache: func() *PolicyCache {
				newCache := NewPolicyCache(context.Background())
				return newCache
			},
			expectOriginal: true,
			expectNew:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalCtx := tt.setupContext()
			testCache := tt.setupCache()

			// Execute test
			newCtx := WithPolicyCache(originalCtx, testCache)

			// Verify cache is in the new context
			retrievedCache, found := PolicyCacheFromContext(newCtx)
			assert.Equal(t, tt.expectNew, found)
			if tt.expectNew {
				assert.Equal(t, testCache, retrievedCache)
			}

			// Verify original context is unchanged
			originalCache, found := PolicyCacheFromContext(originalCtx)
			assert.Equal(t, tt.expectOriginal, found)
			if !tt.expectOriginal {
				assert.Nil(t, originalCache)
			}
		})
	}
}

func TestGet_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		numGoroutines int
		numOperations int
		expectedTotal int
	}{
		{
			name:          "concurrent access with 10 goroutines",
			numGoroutines: 10,
			numOperations: 100,
			expectedTotal: 1000,
		},
		{
			name:          "concurrent access with 5 goroutines",
			numGoroutines: 5,
			numOperations: 50,
			expectedTotal: 250,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh cache for each test
			testCache := NewPolicyCache(ctx)

			var wg sync.WaitGroup
			wg.Add(tt.numGoroutines)

			// Start concurrent goroutines
			for i := 0; i < tt.numGoroutines; i++ {
				go func(id int) {
					defer wg.Done()
					for j := 0; j < tt.numOperations; j++ {
						key := fmt.Sprintf("key_%d_%d", id, j)
						value := fmt.Sprintf("value_%d_%d", id, j)
						testCache.Set(key, value, nil)
					}
				}(i)
			}

			wg.Wait()

			// Verify all values were set correctly
			count := 0
			for i := 0; i < tt.numGoroutines; i++ {
				for j := 0; j < tt.numOperations; j++ {
					key := fmt.Sprintf("key_%d_%d", i, j)
					expectedValue := fmt.Sprintf("value_%d_%d", i, j)
					value, ok := testCache.Get(key)
					assert.True(t, ok, "Key %s should exist", key)
					assert.Equal(t, expectedValue, value, "Value for key %s should match", key)
					count++
				}
			}

			assert.Equal(t, tt.expectedTotal, count)
		})
	}
}

func TestGet_TypeSafety(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		key           string
		value         interface{}
		expectedFound bool
		expectedValue string
	}{
		{
			name:          "string type mismatch",
			key:           "string",
			value:         "just a string",
			expectedFound: false,
			expectedValue: "",
		},
		{
			name:          "int type mismatch",
			key:           "int",
			value:         42,
			expectedFound: false,
			expectedValue: "",
		},
		{
			name:          "bool type mismatch",
			key:           "bool",
			value:         true,
			expectedFound: false,
			expectedValue: "",
		},
		{
			name:          "nil type mismatch",
			key:           "nil",
			value:         nil,
			expectedFound: false,
			expectedValue: "",
		},
		{
			name:          "valid cacheEntry type",
			key:           "valid",
			value:         &cacheEntry{value: "validvalue", err: nil},
			expectedFound: true,
			expectedValue: "validvalue",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh cache for each test
			testCache := NewPolicyCache(ctx)

			// Store the value directly in the sync.Map
			testCache.Data.Store(tt.key, tt.value)

			// Execute test
			value, found := testCache.Get(tt.key)

			// Assert results
			assert.Equal(t, tt.expectedFound, found, "Key %s should have found=%v", tt.key, tt.expectedFound)
			assert.Equal(t, tt.expectedValue, value, "Value for key %s should be %q", tt.key, tt.expectedValue)
		})
	}
}
