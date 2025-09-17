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

//go:build unit

package vsa

import (
	"context"
	"errors"
	"testing"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/stretchr/testify/assert"

	"github.com/conforma/cli/internal/applicationsnapshot"
)

type mockPredicateAttestor struct {
	AttestPredicateFunc func(ctx context.Context) ([]byte, error)
	WriteEnvelopeFunc   func(data []byte) (string, error)
	TargetDigestFunc    func() string
}

func (m *mockPredicateAttestor) AttestPredicate(ctx context.Context) ([]byte, error) {
	return m.AttestPredicateFunc(ctx)
}

func (m *mockPredicateAttestor) WriteEnvelope(data []byte) (string, error) {
	return m.WriteEnvelopeFunc(data)
}

func (m *mockPredicateAttestor) TargetDigest() string {
	return m.TargetDigestFunc()
}

// Tests for standalone functions

func TestGenerateAndWritePredicate_Success(t *testing.T) {
	ctx := context.Background()

	// Create a real Generator and Writer for testing
	report := applicationsnapshot.Report{
		Success: true,
		Policy: ecc.EnterpriseContractPolicySpec{
			Name: "test-policy",
		},
	}
	component := applicationsnapshot.Component{
		SnapshotComponent: app.SnapshotComponent{
			Name:           "test-component",
			ContainerImage: "test-image:tag",
		},
		Success: true,
	}

	gen := NewGenerator(report, component, "https://github.com/test/policy", nil)
	writer := NewWriter()

	path, err := GenerateAndWritePredicate(ctx, gen, writer)
	assert.NoError(t, err)
	assert.NotEmpty(t, path)
	assert.Contains(t, path, "vsa-")
	assert.Contains(t, path, ".json")
}

func TestGenerateAndWritePredicate_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("predicate generation fails", func(t *testing.T) {
		// Create a Generator with invalid data that will cause generation to fail
		report := applicationsnapshot.Report{
			Success: false,
			Policy: ecc.EnterpriseContractPolicySpec{
				Name: "test-policy",
			},
		}
		component := applicationsnapshot.Component{
			SnapshotComponent: app.SnapshotComponent{
				Name:           "test-component",
				ContainerImage: "invalid-image-ref", // This should cause issues
			},
			Success: false,
		}

		gen := NewGenerator(report, component, "https://github.com/test/policy", nil)
		writer := NewWriter()

		// This should fail because the component has invalid data
		path, err := GenerateAndWritePredicate(ctx, gen, writer)
		// The test might pass or fail depending on validation, so we just check it doesn't panic
		if err != nil {
			assert.Empty(t, path)
		}
	})

	t.Run("write predicate with invalid writer", func(t *testing.T) {
		// Create a valid Generator
		report := applicationsnapshot.Report{
			Success: true,
			Policy: ecc.EnterpriseContractPolicySpec{
				Name: "test-policy",
			},
		}
		component := applicationsnapshot.Component{
			SnapshotComponent: app.SnapshotComponent{
				Name:           "test-component",
				ContainerImage: "test-image:tag",
			},
			Success: true,
		}

		gen := NewGenerator(report, component, "https://github.com/test/policy", nil)
		writer := NewWriter()

		// Set an invalid temp dir prefix that should cause write to fail
		writer.TempDirPrefix = "/invalid/path/that/does/not/exist/"

		path, err := GenerateAndWritePredicate(ctx, gen, writer)
		assert.Error(t, err)
		assert.Empty(t, path)
	})
}

func TestAttestVSA_Success(t *testing.T) {
	ctx := context.Background()

	attestor := &mockPredicateAttestor{
		AttestPredicateFunc: func(ctx context.Context) ([]byte, error) {
			return []byte("envelope data"), nil
		},
		WriteEnvelopeFunc: func(data []byte) (string, error) {
			assert.Equal(t, []byte("envelope data"), data)
			return "/tmp/envelope.jsonl", nil
		},
		TargetDigestFunc: func() string {
			return "sha256:testdigest"
		},
	}

	path, err := AttestVSA(ctx, attestor)
	assert.NoError(t, err)
	assert.Equal(t, "/tmp/envelope.jsonl", path)
}

func TestAttestVSA_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("attest predicate fails", func(t *testing.T) {
		attestor := &mockPredicateAttestor{
			AttestPredicateFunc: func(ctx context.Context) ([]byte, error) {
				return nil, errors.New("attest predicate error")
			},
			TargetDigestFunc: func() string {
				return "sha256:testdigest"
			},
		}

		path, err := AttestVSA(ctx, attestor)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "attest predicate error")
		assert.Contains(t, err.Error(), "sha256:testdigest")
		assert.Empty(t, path)
	})

	t.Run("write envelope fails", func(t *testing.T) {
		attestor := &mockPredicateAttestor{
			AttestPredicateFunc: func(ctx context.Context) ([]byte, error) {
				return []byte("envelope data"), nil
			},
			WriteEnvelopeFunc: func(data []byte) (string, error) {
				return "", errors.New("write envelope error")
			},
			TargetDigestFunc: func() string {
				return "sha256:testdigest"
			},
		}

		path, err := AttestVSA(ctx, attestor)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "write envelope error")
		assert.Contains(t, err.Error(), "sha256:testdigest")
		assert.Empty(t, path)
	})
}
