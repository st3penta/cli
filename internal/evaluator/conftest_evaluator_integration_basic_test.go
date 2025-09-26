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

// This file contains integration tests for the Conftest Evaluator that test
// the complete evaluation flow with real policy sources and file systems.
// It includes tests for:
// - Basic integration functionality (TestConftestEvaluatorIntegrationBasic)
// - Integration with test data and file systems (TestConftestEvaluatorIntegrationWithTestData)
// These tests verify that the evaluator works correctly in real-world scenarios
// with actual policy files and data sources.

//go:build integration

package evaluator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/policy/source"
)

func TestConftestEvaluatorIntegrationBasic(t *testing.T) {
	ctx := context.Background()

	// Create a simple policy source
	policySource := &source.PolicyUrl{
		Url:  "file://testdata/policies",
		Kind: source.PolicyKind,
	}

	// Create config provider
	configProvider := &mockConfigProvider{}
	configProvider.On("EffectiveTime").Return(time.Now())
	configProvider.On("SigstoreOpts").Return(policy.SigstoreOpts{}, nil)
	configProvider.On("Spec").Return(ecc.EnterpriseContractPolicySpec{
		Sources: []ecc.Source{
			{
				Policy: []string{"file://testdata/policies"},
			},
		},
	})

	// Create evaluator
	evaluator, err := NewConftestEvaluator(ctx, []source.PolicySource{policySource}, configProvider, ecc.Source{})
	require.NoError(t, err)
	defer evaluator.Destroy()

	// Test that evaluator is created successfully
	assert.NotNil(t, evaluator)
	assert.NotEmpty(t, evaluator.CapabilitiesPath())
}

func TestConftestEvaluatorIntegrationWithTestData(t *testing.T) {
	ctx := context.Background()

	// Create a temporary directory for the test
	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policy")
	err := os.MkdirAll(policyDir, 0o755)
	require.NoError(t, err)

	// Create a simple policy file for testing
	policyContent := `package main

import rego.v1

deny contains result if {
	result := {
		"code": "main.test",
		"msg": "Test value found",
	}
}`
	err = os.WriteFile(filepath.Join(policyDir, "policy.rego"), []byte(policyContent), 0o600)
	require.NoError(t, err)

	// Create policy source
	policySource := &source.PolicyUrl{
		Url:  "file://" + policyDir,
		Kind: source.PolicyKind,
	}

	// Create config provider
	configProvider := &mockConfigProvider{}
	configProvider.On("EffectiveTime").Return(time.Now())
	configProvider.On("SigstoreOpts").Return(policy.SigstoreOpts{}, nil)
	configProvider.On("Spec").Return(ecc.EnterpriseContractPolicySpec{
		Sources: []ecc.Source{
			{
				Policy: []string{"file://" + policyDir},
			},
		},
	})

	// Create evaluator
	evaluator, err := NewConftestEvaluator(ctx, []source.PolicySource{policySource}, configProvider, ecc.Source{})
	require.NoError(t, err)
	defer evaluator.Destroy()

	// Test evaluation with simple input
	target := EvaluationTarget{
		Inputs: []string{filepath.Join(tmpDir, "input.json")},
		Target: "test",
	}

	// Create a simple input file
	inputData := map[string]interface{}{
		"test": "value",
	}
	inputBytes, err := json.Marshal(inputData)
	require.NoError(t, err)
	err = os.WriteFile(target.Inputs[0], inputBytes, 0o600)
	require.NoError(t, err)

	// Run evaluation
	result, err := evaluator.Evaluate(ctx, target)
	require.NoError(t, err)
	assert.NotNil(t, result)
}
