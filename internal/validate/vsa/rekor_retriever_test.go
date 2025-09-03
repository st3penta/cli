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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/stretchr/testify/assert"
)

// MockRekorClient implements RekorClient for testing
type MockRekorClient struct {
	entries []models.LogEntryAnon
}

func (m *MockRekorClient) SearchIndex(ctx context.Context, query *models.SearchIndex) ([]models.LogEntryAnon, error) {
	// Return all entries for any hash query
	return m.entries, nil
}

func (m *MockRekorClient) SearchLogQuery(ctx context.Context, query *models.SearchLogQuery) ([]models.LogEntryAnon, error) {
	return m.entries, nil
}

func (m *MockRekorClient) GetLogEntryByIndex(ctx context.Context, index int64) (*models.LogEntryAnon, error) {
	for _, entry := range m.entries {
		if entry.LogIndex != nil && *entry.LogIndex == index {
			return &entry, nil
		}
	}
	return nil, fmt.Errorf("entry not found")
}

func (m *MockRekorClient) GetLogEntryByUUID(ctx context.Context, uuid string) (*models.LogEntryAnon, error) {
	for _, entry := range m.entries {
		if entry.LogID != nil && *entry.LogID == uuid {
			return &entry, nil
		}
	}
	return nil, fmt.Errorf("entry not found")
}

func TestRekorVSARetriever_FindByPayloadHash(t *testing.T) {
	// Create a mock client with dual entries
	// The payload "dGVzdA==" decodes to "test" and has SHA256 hash "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	expectedPayloadHash := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

	mockClient := &MockRekorClient{
		entries: []models.LogEntryAnon{
			{
				LogIndex: &[]int64{123}[0],
				LogID:    &[]string{"intoto-uuid"}[0],
				Body:     base64.StdEncoding.EncodeToString([]byte(`{"intoto": "v0.0.1", "content": {"envelope": {"payload": "dGVzdA==", "signatures": [{"sig": "dGVzdA=="}]}}}`)),
				Attestation: &models.LogEntryAnonAttestation{
					Data: strfmt.Base64("ZXlKd2NtVmthV05oZEdWVWVYQmxJam9pYUhSMGNITTZMeTlqYjI1bWIzSnRZUzVrWlhZdmRtVnlhV1pwWTJGMGFXOXVYM04xYlcxaGNua3ZkakVpTENKemRXSnFaV04wSWpwYmV5SnVZVzFsSWpvaWNYVmhlUzVwYnk5MFpYTjBMMmx0WVdkbElpd2laR2xuWlhOMElqcDdJbk5vWVRJMU5pSTZJbUZpWXpFeU15SjlmVjE5"),
				},
			},
			{
				LogIndex: &[]int64{124}[0],
				LogID:    &[]string{"dsse-uuid"}[0],
				Body:     base64.StdEncoding.EncodeToString([]byte(`{"dsse": "v0.0.1", "content": {"envelope": {"payload": "dGVzdA==", "signatures": [{"sig": "dGVzdA=="}]}}}`)),
			},
		},
	}

	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	// Test successful retrieval
	dualPair, err := retriever.FindByPayloadHash(context.Background(), expectedPayloadHash)
	assert.NoError(t, err)
	assert.NotNil(t, dualPair)
	assert.Equal(t, expectedPayloadHash, dualPair.PayloadHash)
	assert.NotNil(t, dualPair.IntotoEntry)
	assert.NotNil(t, dualPair.DSSEEntry)
	assert.Equal(t, int64(123), *dualPair.IntotoEntry.LogIndex)
	assert.Equal(t, "intoto-uuid", *dualPair.IntotoEntry.LogID)
	assert.Equal(t, int64(124), *dualPair.DSSEEntry.LogIndex)
	assert.Equal(t, "dsse-uuid", *dualPair.DSSEEntry.LogID)
}

func TestRekorVSARetriever_FindByPayloadHash_EmptyHash(t *testing.T) {
	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	_, err := retriever.FindByPayloadHash(context.Background(), "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "payload hash cannot be empty")
}

func TestRekorVSARetriever_FindByPayloadHash_InvalidHash(t *testing.T) {
	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	_, err := retriever.FindByPayloadHash(context.Background(), "invalid-hex!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid payload hash format")
}

func TestRekorVSARetriever_FindByPayloadHash_NoEntries(t *testing.T) {
	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	_, err := retriever.FindByPayloadHash(context.Background(), "abcdef1234567890")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no entries found for payload hash")
}

func TestRekorVSARetriever_FindByPayloadHash_MultipleEntries(t *testing.T) {
	// Create a mock client with multiple entries for the same payload hash
	// The test should select the latest entries based on IntegratedTime
	// The payload "dGVzdA==" decodes to "test" and has SHA256 hash "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	expectedPayloadHash := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

	mockClient := &MockRekorClient{
		entries: []models.LogEntryAnon{
			// Older in-toto entry
			{
				LogIndex:       &[]int64{123}[0],
				LogID:          &[]string{"intoto-old"}[0],
				IntegratedTime: int64Ptr(1234567890), // Older time
				Body:           base64.StdEncoding.EncodeToString([]byte(`{"intoto": "v0.0.1", "content": {"envelope": {"payload": "dGVzdA==", "signatures": [{"sig": "dGVzdA=="}]}}}`)),
				Attestation: &models.LogEntryAnonAttestation{
					Data: strfmt.Base64("ZXlKd2NtVmthV05oZEdWVWVYQmxJam9pYUhSMGNITTZMeTlqYjI1bWIzSnRZUzVrWlhZdmRtVnlhV1pwWTJGMGFXOXVYM04xYlcxaGNua3ZkakVpTENKemRXSnFaV04wSWpwYmV5SnVZVzFsSWpvaWNYVmhlUzVwYnk5MFpYTjBMMmx0WVdkbElpd2laR2xuWlhOMElqcDdJbk5vWVRJMU5pSTZJbUZpWXpFeU15SjlmVjE5"),
				},
			},
			// Newer in-toto entry
			{
				LogIndex:       &[]int64{125}[0],
				LogID:          &[]string{"intoto-new"}[0],
				IntegratedTime: int64Ptr(1234567892), // Newer time
				Body:           base64.StdEncoding.EncodeToString([]byte(`{"intoto": "v0.0.1", "content": {"envelope": {"payload": "dGVzdA==", "signatures": [{"sig": "dGVzdA=="}]}}}`)),
				Attestation: &models.LogEntryAnonAttestation{
					Data: strfmt.Base64("ZXlKd2NtVmthV05oZEdWVWVYQmxJam9pYUhSMGNITTZMeTlqYjI1bWIzSnRZUzVrWlhZdmRtVnlhV1pwWTJGMGFXOXVYM04xYlcxaGNua3ZkakVpTENKemRXSnFaV04wSWpwYmV5SnVZVzFsSWpvaWNYVmhlUzVwYnk5MFpYTjBMMmx0WVdkbElpd2laR2xuWlhOMElqcDdJbk5vWVRJMU5pSTZJbUZpWXpFeU15SjlmVjE5"),
				},
			},
			// Older DSSE entry
			{
				LogIndex:       &[]int64{124}[0],
				LogID:          &[]string{"dsse-old"}[0],
				IntegratedTime: int64Ptr(1234567891), // Older time
				Body:           base64.StdEncoding.EncodeToString([]byte(`{"dsse": "v0.0.1", "content": {"envelope": {"payload": "dGVzdA==", "signatures": [{"sig": "dGVzdA=="}]}}}`)),
			},
			// Newer DSSE entry
			{
				LogIndex:       &[]int64{126}[0],
				LogID:          &[]string{"dsse-new"}[0],
				IntegratedTime: int64Ptr(1234567893), // Newest time
				Body:           base64.StdEncoding.EncodeToString([]byte(`{"dsse": "v0.0.1", "content": {"envelope": {"payload": "dGVzdA==", "signatures": [{"sig": "dGVzdA=="}]}}}`)),
			},
		},
	}

	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	// Test successful retrieval - should select the latest entries
	dualPair, err := retriever.FindByPayloadHash(context.Background(), expectedPayloadHash)
	assert.NoError(t, err)
	assert.NotNil(t, dualPair)
	assert.Equal(t, expectedPayloadHash, dualPair.PayloadHash)
	assert.NotNil(t, dualPair.IntotoEntry)
	assert.NotNil(t, dualPair.DSSEEntry)

	// Verify that the latest in-toto entry was selected (LogIndex 125, IntegratedTime 1234567892)
	assert.Equal(t, int64(125), *dualPair.IntotoEntry.LogIndex)
	assert.Equal(t, "intoto-new", *dualPair.IntotoEntry.LogID)
	assert.Equal(t, int64(1234567892), *dualPair.IntotoEntry.IntegratedTime)

	// Verify that the latest DSSE entry was selected (LogIndex 126, IntegratedTime 1234567893)
	assert.Equal(t, int64(126), *dualPair.DSSEEntry.LogIndex)
	assert.Equal(t, "dsse-new", *dualPair.DSSEEntry.LogID)
	assert.Equal(t, int64(1234567893), *dualPair.DSSEEntry.IntegratedTime)
}

func TestRekorVSARetriever_ExtractStatementFromIntoto(t *testing.T) {
	// Create a mock in-toto entry with DSSE envelope
	dsseEnvelope := `{
		"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInN1YmplY3QiOlt7Im5hbWUiOiJ0ZXN0LWltYWdlIiwiaGFzaGVzIjp7InNoYTI1NiI6ImFiYzEyMyJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2NvbmZvcm1hLmRldi92ZXJpZmljYXRpb25fc3VtbWFyeS92MSIsInByZWRpY2F0ZSI6eyJ0ZXN0IjoiZGF0YSJ9fQ==",
		"signatures": [{"sig": "dGVzdA=="}]
	}`

	entry := models.LogEntryAnon{
		LogIndex: &[]int64{123}[0],
		LogID:    &[]string{"intoto-uuid"}[0],
		Body:     base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"intoto": "v0.0.1", "content": {"envelope": %s}}`, dsseEnvelope))),
		Attestation: &models.LogEntryAnonAttestation{
			Data: strfmt.Base64(base64.StdEncoding.EncodeToString([]byte(dsseEnvelope))),
		},
	}

	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{entry}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	// Test successful extraction
	statementBytes, err := retriever.ExtractStatementFromIntoto(&entry)
	assert.NoError(t, err)
	assert.NotNil(t, statementBytes)

	// Verify the extracted statement
	var statement map[string]interface{}
	err = json.Unmarshal(statementBytes, &statement)
	assert.NoError(t, err)
	assert.Equal(t, "https://in-toto.io/Statement/v0.1", statement["_type"])
	assert.Equal(t, "https://conforma.dev/verification_summary/v1", statement["predicateType"])
}

func TestRekorVSARetriever_ExtractStatementFromIntoto_NilEntry(t *testing.T) {
	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	_, err := retriever.ExtractStatementFromIntoto(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entry cannot be nil")
}

func TestRekorVSARetriever_ExtractStatementFromIntoto_NotIntotoEntry(t *testing.T) {
	entry := models.LogEntryAnon{
		LogIndex: &[]int64{123}[0],
		LogID:    &[]string{"dsse-uuid"}[0],
		Body:     base64.StdEncoding.EncodeToString([]byte(`{"dsse": "v0.0.1"}`)),
	}

	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{entry}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	_, err := retriever.ExtractStatementFromIntoto(&entry)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entry is not an in-toto entry")
}

func TestRekorVSARetriever_ClassifyEntryKind(t *testing.T) {
	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	tests := []struct {
		name     string
		entry    models.LogEntryAnon
		expected string
	}{
		{
			name: "intoto entry by body",
			entry: models.LogEntryAnon{
				Body: base64.StdEncoding.EncodeToString([]byte(`{"intoto": "v0.0.1"}`)),
			},
			expected: "intoto",
		},
		{
			name: "dsse entry by body",
			entry: models.LogEntryAnon{
				Body: base64.StdEncoding.EncodeToString([]byte(`{"dsse": "v0.0.1"}`)),
			},
			expected: "dsse",
		},
		{
			name: "intoto entry by attestation",
			entry: models.LogEntryAnon{
				Attestation: &models.LogEntryAnonAttestation{
					Data: strfmt.Base64(base64.StdEncoding.EncodeToString([]byte(`{"predicateType":"https://conforma.dev/verification_summary/v1"}`))),
				},
			},
			expected: "intoto",
		},
		{
			name: "unknown entry",
			entry: models.LogEntryAnon{
				Body: base64.StdEncoding.EncodeToString([]byte(`{"unknown": "type"}`)),
			},
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := retriever.classifyEntryKind(tt.entry)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRekorVSARetriever_IsValidHexHash(t *testing.T) {
	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	tests := []struct {
		name     string
		hash     string
		expected bool
	}{
		{"valid hex", "abcdef1234567890", true},
		{"valid hex with uppercase", "ABCDEF1234567890", true},
		{"empty string", "", false},
		{"invalid hex", "invalid-hex!", false},
		{"partial hex", "abcd", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := retriever.IsValidHexHash(tt.hash)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRekorVSARetriever_GetPairedVSAWithSignatures(t *testing.T) {
	// Create mock entries that share the same payloadHash
	dsseEnvelope := `{
		"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInN1YmplY3QiOlt7Im5hbWUiOiJ0ZXN0LWltYWdlIiwiaGFzaGVzIjp7InNoYTI1NiI6ImFiYzEyMyJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2NvbmZvcm1hLmRldi92ZXJpZmljYXRpb25fc3VtbWFyeS92MSIsInByZWRpY2F0ZSI6eyJ0ZXN0IjoiZGF0YSJ9fQ==",
		"signatures": [{"sig": "dGVzdA==", "publicKey": "dGVzdC1wdWJsaWMta2V5"}]
	}`

	intotoEntry := models.LogEntryAnon{
		LogIndex: &[]int64{123}[0],
		LogID:    &[]string{"intoto-uuid"}[0],
		Body:     base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"intoto": "v0.0.1", "content": {"envelope": %s}}`, dsseEnvelope))),
		Attestation: &models.LogEntryAnonAttestation{
			Data: strfmt.Base64(base64.StdEncoding.EncodeToString([]byte(dsseEnvelope))),
		},
	}

	dsseEntry := models.LogEntryAnon{
		LogIndex: &[]int64{124}[0],
		LogID:    &[]string{"dsse-uuid"}[0],
		Body:     base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"dsse": "v0.0.1", "content": {"envelope": %s}}`, dsseEnvelope))),
		Attestation: &models.LogEntryAnonAttestation{
			Data: strfmt.Base64(base64.StdEncoding.EncodeToString([]byte(dsseEnvelope))),
		},
	}

	// Create a mock client that returns both entries
	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{intotoEntry, dsseEntry}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	// Calculate the expected payload hash
	payloadBytes, _ := base64.StdEncoding.DecodeString("eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInN1YmplY3QiOlt7Im5hbWUiOiJ0ZXN0LWltYWdlIiwiaGFzaGVzIjp7InNoYTI1NiI6ImFiYzEyMyJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2NvbmZvcm1hLmRldi92ZXJpZmljYXRpb25fc3VtbWFyeS92MSIsInByZWRpY2F0ZSI6eyJ0ZXN0IjoiZGF0YSJ9fQ==")
	hash := sha256.Sum256(payloadBytes)
	expectedPayloadHash := fmt.Sprintf("%x", hash[:])

	// Test successful pairing
	result, err := retriever.GetPairedVSAWithSignatures(context.Background(), expectedPayloadHash)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Verify the result structure
	assert.Equal(t, expectedPayloadHash, result.PayloadHash)
	assert.Equal(t, "https://conforma.dev/verification_summary/v1", result.PredicateType)
	assert.NotNil(t, result.VSAStatement)
	assert.NotNil(t, result.Signatures)
	assert.NotNil(t, result.IntotoEntry)
	assert.NotNil(t, result.DSSEEntry)

	// Verify the VSA Statement content
	var statement map[string]interface{}
	err = json.Unmarshal(result.VSAStatement, &statement)
	assert.NoError(t, err)
	assert.Equal(t, "https://in-toto.io/Statement/v0.1", statement["_type"])
	assert.Equal(t, "https://conforma.dev/verification_summary/v1", statement["predicateType"])

	// Verify the signatures
	assert.Len(t, result.Signatures, 1)
	signature := result.Signatures[0]
	assert.Equal(t, "dGVzdA==", signature["sig"])
	assert.Equal(t, "dGVzdC1wdWJsaWMta2V5", signature["publicKey"])
}

func TestRekorVSARetriever_GetPairedVSAWithSignatures_IncompletePair(t *testing.T) {
	// Test case: Only in-toto entry found
	t.Run("only_intoto_entry", func(t *testing.T) {
		dsseEnvelope := `{
			"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInN1YmplY3QiOlt7Im5hbWUiOiJ0ZXN0LWltYWdlIiwiaGFzaGVzIjp7InNoYTI1NiI6ImFiYzEyMyJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2NvbmZvcm1hLmRldi92ZXJpZmljYXRpb25fc3VtbWFyeS92MSIsInByZWRpY2F0ZSI6eyJ0ZXN0IjoiZGF0YSJ9fQ==",
			"signatures": [{"sig": "dGVzdA=="}]
		}`

		intotoEntry := models.LogEntryAnon{
			LogIndex: &[]int64{123}[0],
			LogID:    &[]string{"intoto-uuid"}[0],
			Body:     base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"intoto": "v0.0.1", "content": {"envelope": %s}}`, dsseEnvelope))),
			Attestation: &models.LogEntryAnonAttestation{
				Data: strfmt.Base64(base64.StdEncoding.EncodeToString([]byte(dsseEnvelope))),
			},
		}

		// Create a mock client that returns only the in-toto entry
		mockClient := &MockRekorClient{entries: []models.LogEntryAnon{intotoEntry}}
		retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

		// Calculate the expected payload hash
		payloadBytes, _ := base64.StdEncoding.DecodeString("eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInN1YmplY3QiOlt7Im5hbWUiOiJ0ZXN0LWltYWdlIiwiaGFzaGVzIjp7InNoYTI1NiI6ImFiYzEyMyJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2NvbmZvcm1hLmRldi92ZXJpZmljYXRpb25fc3VtbWFyeS92MSIsInByZWRpY2F0ZSI6eyJ0ZXN0IjoiZGF0YSJ9fQ==")
		hash := sha256.Sum256(payloadBytes)
		expectedPayloadHash := fmt.Sprintf("%x", hash[:])

		// Test that it correctly rejects incomplete pairs
		_, err := retriever.GetPairedVSAWithSignatures(context.Background(), expectedPayloadHash)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "incomplete dual upload: found in-toto entry but no DSSE entry")
	})

	// Test case: Only DSSE entry found
	t.Run("only_dsse_entry", func(t *testing.T) {
		dsseEnvelope := `{
			"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInN1YmplY3QiOlt7Im5hbWUiOiJ0ZXN0LWltYWdlIiwiaGFzaGVzIjp7InNoYTI1NiI6ImFiYzEyMyJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2NvbmZvcm1hLmRldi92ZXJpZmljYXRpb25fc3VtbWFyeS92MSIsInByZWRpY2F0ZSI6eyJ0ZXN0IjoiZGF0YSJ9fQ==",
			"signatures": [{"sig": "dGVzdA=="}]
		}`

		dsseEntry := models.LogEntryAnon{
			LogIndex: &[]int64{124}[0],
			LogID:    &[]string{"dsse-uuid"}[0],
			Body:     base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"dsse": "v0.0.1", "content": {"envelope": %s}}`, dsseEnvelope))),
			Attestation: &models.LogEntryAnonAttestation{
				Data: strfmt.Base64(base64.StdEncoding.EncodeToString([]byte(dsseEnvelope))),
			},
		}

		// Create a mock client that returns only the DSSE entry
		mockClient := &MockRekorClient{entries: []models.LogEntryAnon{dsseEntry}}
		retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

		// Calculate the expected payload hash
		payloadBytes, _ := base64.StdEncoding.DecodeString("eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInN1YmplY3QiOlt7Im5hbWUiOiJ0ZXN0LWltYWdlIiwiaGFzaGVzIjp7InNoYTI1NiI6ImFiYzEyMyJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2NvbmZvcm1hLmRldi92ZXJpZmljYXRpb25fc3VtbWFyeS92MSIsInByZWRpY2F0ZSI6eyJ0ZXN0IjoiZGF0YSJ9fQ==")
		hash := sha256.Sum256(payloadBytes)
		expectedPayloadHash := fmt.Sprintf("%x", hash[:])

		// Test that it correctly rejects incomplete pairs
		_, err := retriever.GetPairedVSAWithSignatures(context.Background(), expectedPayloadHash)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "incomplete dual upload: found DSSE entry but no in-toto entry")
	})
}

func TestRekorVSARetriever_FindLatestEntryByIntegratedTime(t *testing.T) {
	retriever := &RekorVSARetriever{}

	// Test with entries having different IntegratedTime values
	entries := []models.LogEntryAnon{
		{
			LogIndex:       &[]int64{1}[0],
			IntegratedTime: int64Ptr(1000),
		},
		{
			LogIndex:       &[]int64{2}[0],
			IntegratedTime: int64Ptr(2000), // Latest
		},
		{
			LogIndex:       &[]int64{3}[0],
			IntegratedTime: int64Ptr(1500),
		},
	}

	latest := retriever.findLatestEntryByIntegratedTime(entries)
	assert.NotNil(t, latest)
	assert.Equal(t, int64(2), *latest.LogIndex)
	assert.Equal(t, int64(2000), *latest.IntegratedTime)

	// Test with entries having some nil IntegratedTime values
	entriesWithNil := []models.LogEntryAnon{
		{
			LogIndex:       &[]int64{1}[0],
			IntegratedTime: nil,
		},
		{
			LogIndex:       &[]int64{2}[0],
			IntegratedTime: int64Ptr(2000), // Latest
		},
		{
			LogIndex:       &[]int64{3}[0],
			IntegratedTime: int64Ptr(1500),
		},
	}

	latestWithNil := retriever.findLatestEntryByIntegratedTime(entriesWithNil)
	assert.NotNil(t, latestWithNil)
	assert.Equal(t, int64(2), *latestWithNil.LogIndex)
	assert.Equal(t, int64(2000), *latestWithNil.IntegratedTime)

	// Test with all nil IntegratedTime values
	entriesAllNil := []models.LogEntryAnon{
		{
			LogIndex:       &[]int64{1}[0],
			IntegratedTime: nil,
		},
		{
			LogIndex:       &[]int64{2}[0],
			IntegratedTime: nil,
		},
	}

	latestAllNil := retriever.findLatestEntryByIntegratedTime(entriesAllNil)
	assert.NotNil(t, latestAllNil)
	assert.Equal(t, int64(1), *latestAllNil.LogIndex) // Should return first entry

	// Test with empty slice
	emptyEntries := []models.LogEntryAnon{}
	latestEmpty := retriever.findLatestEntryByIntegratedTime(emptyEntries)
	assert.Nil(t, latestEmpty)

	// Test with single entry
	singleEntry := []models.LogEntryAnon{
		{
			LogIndex:       &[]int64{1}[0],
			IntegratedTime: int64Ptr(1000),
		},
	}

	latestSingle := retriever.findLatestEntryByIntegratedTime(singleEntry)
	assert.NotNil(t, latestSingle)
	assert.Equal(t, int64(1), *latestSingle.LogIndex)
	assert.Equal(t, int64(1000), *latestSingle.IntegratedTime)
}
