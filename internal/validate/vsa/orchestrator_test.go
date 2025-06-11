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

	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/stretchr/testify/assert"

	"github.com/conforma/cli/internal/applicationsnapshot"
)

// Mock implementations for testing

type mockPredicateGenerator struct {
	GeneratePredicateFunc func(ctx context.Context, comp applicationsnapshot.Component) (*Predicate, error)
}

func (m *mockPredicateGenerator) GeneratePredicate(ctx context.Context, comp applicationsnapshot.Component) (*Predicate, error) {
	return m.GeneratePredicateFunc(ctx, comp)
}

type mockPredicateWriter struct {
	WritePredicateFunc func(pred *Predicate) (string, error)
}

func (m *mockPredicateWriter) WritePredicate(pred *Predicate) (string, error) {
	return m.WritePredicateFunc(pred)
}

type mockPredicateAttestor struct {
	AttestPredicateFunc func(ctx context.Context) ([]byte, error)
	WriteEnvelopeFunc   func(data []byte) (string, error)
}

func (m *mockPredicateAttestor) AttestPredicate(ctx context.Context) ([]byte, error) {
	return m.AttestPredicateFunc(ctx)
}

func (m *mockPredicateAttestor) WriteEnvelope(data []byte) (string, error) {
	return m.WriteEnvelopeFunc(data)
}

// Tests for AttestVSA

func TestAttestVSA_Success(t *testing.T) {
	ctx := context.Background()
	comp := applicationsnapshot.Component{
		SnapshotComponent: app.SnapshotComponent{
			ContainerImage: "test-image",
		},
	}

	attestor := &mockPredicateAttestor{
		AttestPredicateFunc: func(ctx context.Context) ([]byte, error) {
			return []byte("envelope"), nil
		},
		WriteEnvelopeFunc: func(data []byte) (string, error) {
			if string(data) != "envelope" {
				t.Errorf("unexpected data passed to WriteEnvelope")
			}
			return "/tmp/envelope.json", nil
		},
	}

	path, err := AttestVSA(ctx, attestor, comp)
	assert.NoError(t, err)
	assert.Equal(t, "/tmp/envelope.json", path)
}

func TestAttestVSA_Errors(t *testing.T) {
	ctx := context.Background()
	comp := applicationsnapshot.Component{
		SnapshotComponent: app.SnapshotComponent{
			ContainerImage: "test-image",
		},
	}

	t.Run("attest predicate fails", func(t *testing.T) {
		attestor := &mockPredicateAttestor{
			AttestPredicateFunc: func(ctx context.Context) ([]byte, error) {
				return nil, errors.New("attest error")
			},
		}
		path, err := AttestVSA(ctx, attestor, comp)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Error attesting VSA")
		assert.Empty(t, path)
	})

	t.Run("write envelope fails", func(t *testing.T) {
		attestor := &mockPredicateAttestor{
			AttestPredicateFunc: func(ctx context.Context) ([]byte, error) {
				return []byte("envelope"), nil
			},
			WriteEnvelopeFunc: func(data []byte) (string, error) {
				return "", errors.New("envelope error")
			},
		}
		path, err := AttestVSA(ctx, attestor, comp)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Error writing envelope")
		assert.Empty(t, path)
	})
}

// Tests for GenerateAndWriteVSA

func TestGenerateAndWriteVSA_Success(t *testing.T) {
	ctx := context.Background()
	comp := applicationsnapshot.Component{
		SnapshotComponent: app.SnapshotComponent{
			ContainerImage: "test-image",
		},
	}
	pred := &Predicate{ImageRef: "test-image"}

	gen := &mockPredicateGenerator{
		GeneratePredicateFunc: func(ctx context.Context, c applicationsnapshot.Component) (*Predicate, error) {
			return pred, nil
		},
	}
	writer := &mockPredicateWriter{
		WritePredicateFunc: func(p *Predicate) (string, error) {
			if p != pred {
				t.Errorf("unexpected predicate passed to WritePredicate")
			}
			return "/tmp/vsa.json", nil
		},
	}

	path, err := GenerateAndWriteVSA(ctx, gen, writer, comp)
	assert.NoError(t, err)
	assert.Equal(t, "/tmp/vsa.json", path)
}

func TestGenerateAndWriteVSA_Errors(t *testing.T) {
	ctx := context.Background()
	comp := applicationsnapshot.Component{
		SnapshotComponent: app.SnapshotComponent{
			ContainerImage: "test-image",
		},
	}
	pred := &Predicate{ImageRef: "test-image"}

	t.Run("predicate generation fails", func(t *testing.T) {
		gen := &mockPredicateGenerator{
			GeneratePredicateFunc: func(ctx context.Context, c applicationsnapshot.Component) (*Predicate, error) {
				return nil, errors.New("predicate generation error")
			},
		}
		writer := &mockPredicateWriter{}

		path, err := GenerateAndWriteVSA(ctx, gen, writer, comp)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "predicate generation error")
		assert.Empty(t, path)
	})

	t.Run("write VSA fails", func(t *testing.T) {
		gen := &mockPredicateGenerator{
			GeneratePredicateFunc: func(ctx context.Context, c applicationsnapshot.Component) (*Predicate, error) {
				return pred, nil
			},
		}
		writer := &mockPredicateWriter{
			WritePredicateFunc: func(p *Predicate) (string, error) {
				return "", errors.New("write VSA error")
			},
		}

		path, err := GenerateAndWriteVSA(ctx, gen, writer, comp)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "write VSA error")
		assert.Empty(t, path)
	})
}
