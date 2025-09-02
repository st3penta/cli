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
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"time"

	"github.com/sigstore/rekor/pkg/client"
	gen_client "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	_ "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	log "github.com/sirupsen/logrus"
)

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// RekorBackend implements VSA storage in Rekor transparency log
type RekorBackend struct {
	serverURL string
	timeout   time.Duration
	retries   int
}

// NewRekorBackend creates a new Rekor storage backend
func NewRekorBackend(config *StorageConfig) (StorageBackend, error) {
	backend := &RekorBackend{
		serverURL: "https://rekor.sigstore.dev", // Default
		timeout:   30 * time.Second,             // Default timeout
		retries:   3,                            // Default retries
	}

	// Use base URL if provided
	if config.BaseURL != "" {
		backend.serverURL = config.BaseURL
	}

	// Parse parameters
	for key, value := range config.Parameters {
		switch key {
		case "server", "url":
			backend.serverURL = value
		case "timeout":
			if timeout, err := time.ParseDuration(value); err == nil {
				backend.timeout = timeout
			} else {
				return nil, fmt.Errorf("invalid timeout format '%s': %w", value, err)
			}
		case "retries":
			if retries, err := strconv.Atoi(value); err == nil {
				backend.retries = retries
			} else {
				return nil, fmt.Errorf("invalid retries format '%s': %w", value, err)
			}
		default:
			log.Warnf("[VSA] Rekor backend: ignoring unknown parameter '%s'", key)
		}
	}

	return backend, nil
}

// Name returns the backend name
func (r *RekorBackend) Name() string {
	return fmt.Sprintf("Rekor (%s)", r.serverURL)
}

// Upload is not supported for Rekor backend - use UploadWithSigner instead
func (r *RekorBackend) Upload(ctx context.Context, envelopeContent []byte) error {
	return fmt.Errorf("Rekor backend requires signer access for public key. Use UploadWithSigner instead")
}

// UploadWithSigner uploads a VSA envelope to the Rekor transparency log with access to the signer for public key extraction
func (r *RekorBackend) UploadWithSigner(ctx context.Context, envelopeContent []byte, signer *Signer) (string, error) {
	// Safely convert retries to uint
	var retryCount uint
	if r.retries < 0 {
		retryCount = 0
	} else {
		retryCount = uint(r.retries)
	}

	rekorClient, err := client.GetRekorClient(r.serverURL,
		client.WithUserAgent("conforma-cli"),
		client.WithRetryCount(retryCount),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create Rekor client for %s: %w", r.serverURL, err)
	}

	log.WithFields(log.Fields{
		"server_url":  r.serverURL,
		"retry_count": retryCount,
		"timeout":     r.timeout,
	}).Info("[VSA] Created Rekor client")

	uploadCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Extract the public key from the signer
	pubKeyBytes, err := r.extractPublicKeyFromSigner(signer)
	if err != nil {
		return "", fmt.Errorf("failed to extract public key from signer: %w", err)
	}

	// Use dual uploader to upload as both DSSE and in-toto entries
	return r.uploadBoth(uploadCtx, rekorClient, envelopeContent, pubKeyBytes)
}

// uploadBoth uploads the same envelope as both DSSE and in-toto entries
func (r *RekorBackend) uploadBoth(ctx context.Context, rekorClient *gen_client.Rekor, envelopeContent []byte, pubKeyBytes []byte) (string, error) {
	// Prepare the DSSE envelope for Rekor - canonicalize once for both uploads
	preparedEnvelope, payloadHash, err := r.prepareDSSEForRekor(envelopeContent, pubKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to prepare DSSE envelope for Rekor: %w", err)
	}

	log.WithFields(log.Fields{
		"payload_hash":     payloadHash,
		"original_size":    len(envelopeContent),
		"prepared_size":    len(preparedEnvelope),
		"payload_preview":  string(envelopeContent[:min(100, len(envelopeContent))]),
		"prepared_preview": string(preparedEnvelope[:min(100, len(preparedEnvelope))]),
	}).Info("[VSA] Prepared DSSE envelope for dual upload")

	// Upload as in-toto entry first using the canonicalized envelope
	log.Info("[VSA] Starting in-toto entry upload")
	intotoEntry, err := r.uploadIntotoEnvelope(ctx, rekorClient, preparedEnvelope, pubKeyBytes)
	if err != nil {
		log.WithError(err).Error("[VSA] Failed to upload in-toto entry")
		return "", fmt.Errorf("failed to upload in-toto entry: %w", err)
	}
	log.Info("[VSA] Completed in-toto entry upload")

	// Upload as DSSE entry using the same canonicalized envelope
	log.Info("[VSA] Starting DSSE entry upload")
	dsseEntry, err := r.uploadDSSE(ctx, rekorClient, preparedEnvelope, pubKeyBytes)
	if err != nil {
		log.WithError(err).Error("[VSA] Failed to upload DSSE entry")
		return "", fmt.Errorf("failed to upload DSSE entry: %w", err)
	}
	log.Info("[VSA] Completed DSSE entry upload")

	// Log successful dual upload
	log.WithFields(log.Fields{
		"payload_hash": payloadHash,
		"intoto_uuid":  intotoEntry.LogID,
		"intoto_index": intotoEntry.LogIndex,
		"dsse_uuid":    dsseEntry.LogID,
		"dsse_index":   dsseEntry.LogIndex,
		"intoto_url":   fmt.Sprintf("%s/api/v1/log/entries/%s", r.serverURL, *intotoEntry.LogID),
		"dsse_url":     fmt.Sprintf("%s/api/v1/log/entries/%s", r.serverURL, *dsseEntry.LogID),
	}).Info("[VSA] Successfully uploaded VSA to Rekor as dual entries")

	return payloadHash, nil
}

// uploadIntotoEnvelope uploads the envelope as an in-toto entry
func (r *RekorBackend) uploadIntotoEnvelope(ctx context.Context, rekorClient *gen_client.Rekor, envelopeContent []byte, pubKeyBytes []byte) (*models.LogEntryAnon, error) {
	log.Info("[VSA] Creating artifact properties for in-toto entry")

	// Log the envelope content for debugging (now canonicalized)
	log.WithFields(log.Fields{
		"envelope_size":    len(envelopeContent),
		"envelope_preview": string(envelopeContent[:min(200, len(envelopeContent))]),
		"pubkey_size":      len(pubKeyBytes),
		"note":             "envelope is now canonicalized for consistency with DSSE entry",
	}).Info("[VSA] Canonicalized envelope content for in-toto upload")

	// Create artifact properties for in-toto entry
	artifactProps := types.ArtifactProperties{
		ArtifactBytes:  envelopeContent,
		PublicKeyBytes: [][]byte{pubKeyBytes},
	}

	// Create the proposed in-toto entry
	log.Info("[VSA] Creating proposed in-toto entry")
	proposedEntry, err := types.NewProposedEntry(ctx, "intoto", "0.0.1", artifactProps)
	if err != nil {
		log.WithError(err).Error("[VSA] Failed to create proposed in-toto entry")
		return nil, fmt.Errorf("failed to create proposed in-toto entry: %w", err)
	}

	// Create the upload parameters
	log.Info("[VSA] Creating upload parameters for in-toto")
	params := entries.NewCreateLogEntryParams()
	params.SetContext(ctx)
	params.SetProposedEntry(proposedEntry)

	// Upload to Rekor
	log.Info("[VSA] Calling CreateLogEntry for in-toto")
	resp, err := rekorClient.Entries.CreateLogEntry(params)
	if err != nil {
		log.WithError(err).Error("[VSA] CreateLogEntry for in-toto failed")
		return nil, fmt.Errorf("failed to create in-toto log entry: %w", err)
	}

	// Extract the created entry
	var logEntry models.LogEntryAnon
	for _, entry := range resp.Payload {
		logEntry = entry
		break
	}

	log.WithFields(log.Fields{
		"entry_type": "in-toto",
		"uuid":       logEntry.LogID,
		"index":      logEntry.LogIndex,
	}).Info("[VSA] Successfully uploaded in-toto entry")

	return &logEntry, nil
}

// uploadDSSE uploads the envelope as a DSSE entry
func (r *RekorBackend) uploadDSSE(ctx context.Context, rekorClient *gen_client.Rekor, envelopeContent []byte, pubKeyBytes []byte) (*models.LogEntryAnon, error) {
	log.Info("[VSA] Creating artifact properties for DSSE entry")
	// Create artifact properties for DSSE entry
	artifactProps := types.ArtifactProperties{
		ArtifactBytes:  envelopeContent,
		PublicKeyBytes: [][]byte{pubKeyBytes},
	}

	// Create the proposed DSSE entry
	log.Info("[VSA] Creating proposed DSSE entry")
	log.WithFields(log.Fields{
		"envelope_size":    len(envelopeContent),
		"envelope_preview": string(envelopeContent[:min(len(envelopeContent), 200)]),
		"pubkey_size":      len(pubKeyBytes),
	}).Info("[VSA] DSSE envelope details for upload")

	proposedEntry, err := types.NewProposedEntry(ctx, "dsse", "0.0.1", artifactProps)
	if err != nil {
		log.WithError(err).Error("[VSA] Failed to create proposed DSSE entry")
		return nil, fmt.Errorf("failed to create proposed DSSE entry: %w", err)
	}

	// Create the upload parameters
	log.Info("[VSA] Creating upload parameters")
	params := entries.NewCreateLogEntryParams()
	params.SetContext(ctx)
	params.SetProposedEntry(proposedEntry)

	// Upload to Rekor
	log.Info("[VSA] Calling CreateLogEntry")
	resp, err := rekorClient.Entries.CreateLogEntry(params)
	if err != nil {
		log.WithError(err).Error("[VSA] CreateLogEntry failed")
		return nil, fmt.Errorf("failed to create DSSE log entry: %w", err)
	}

	// Extract the created entry
	var logEntry models.LogEntryAnon
	for _, entry := range resp.Payload {
		logEntry = entry
		break
	}

	log.WithFields(log.Fields{
		"entry_type": "dsse",
		"uuid":       logEntry.LogID,
		"index":      logEntry.LogIndex,
	}).Info("[VSA] Successfully uploaded DSSE entry")

	return &logEntry, nil
}

// prepareDSSEForRekor prepares the DSSE envelope for Rekor by injecting public keys.
// This envelope is used for both DSSE and in-toto uploads to ensure consistency between the two entries.
// The payload hash is calculated from the decoded payload bytes, not the envelope JSON, to ensure
// a stable join key between DSSE and in-toto entries.
func (r *RekorBackend) prepareDSSEForRekor(envelopeContent []byte, pubKeyBytes []byte) ([]byte, string, error) {
	// Strongly-typed DSSE envelope to avoid map gymnastics
	type dsseSig struct {
		KeyID     string  `json:"keyid,omitempty"`
		Sig       string  `json:"sig"`
		PublicKey *string `json:"publicKey,omitempty"`
	}
	type dsseEnvelope struct {
		Payload     string    `json:"payload"`
		PayloadType string    `json:"payloadType"`
		Signatures  []dsseSig `json:"signatures"`
	}

	var env dsseEnvelope
	if err := json.Unmarshal(envelopeContent, &env); err != nil {
		return nil, "", fmt.Errorf("failed to parse DSSE envelope: %w", err)
	}
	if env.Payload == "" || env.PayloadType == "" || len(env.Signatures) == 0 {
		return nil, "", fmt.Errorf("invalid DSSE envelope: missing payload/payloadType/signatures")
	}

	// Decode payload bytes (try URL-safe no-pad first, then std no-pad, then std)
	decodeB64 := func(s string) ([]byte, error) {
		if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
			return b, nil
		}
		if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
			return b, nil
		}
		return base64.StdEncoding.DecodeString(s)
	}

	payloadBytes, err := decodeB64(env.Payload)
	if err != nil {
		// include a short prefix to aid debugging, but avoid dumping entire payload
		prefix := env.Payload
		if len(prefix) > 16 {
			prefix = prefix[:16] + "..."
		}
		return nil, "", fmt.Errorf("could not base64-decode DSSE payload (tried RawURL, RawStd, Std): prefix=%q: %w", prefix, err)
	}

	// Hash = sha256(decoded payload bytes) - this is the stable join key
	sum := sha256.Sum256(payloadBytes)
	payloadHashHex := fmt.Sprintf("%x", sum[:])

	// Inject PEM public key into each signature if missing
	pub := string(pubKeyBytes) // must be PEM with BEGIN/END PUBLIC KEY
	for i := range env.Signatures {
		if env.Signatures[i].PublicKey == nil || *env.Signatures[i].PublicKey == "" {
			env.Signatures[i].PublicKey = &pub
		}
	}

	// Re-marshal envelope **only** with publicKey additions (no payload/sig changes)
	out, err := json.Marshal(env)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal DSSE envelope with public keys: %w", err)
	}

	return out, payloadHashHex, nil
}

// extractPublicKeyFromSigner extracts the public key from the signer and converts it to PEM format
func (r *RekorBackend) extractPublicKeyFromSigner(signer *Signer) ([]byte, error) {
	// Check if signer is nil
	if signer == nil {
		return nil, fmt.Errorf("signer is nil")
	}

	// Get the public key from the signer
	pubKey, err := signer.SignerVerifier.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from signer: %w", err)
	}

	// Convert the public key to PEM format (same logic as in attest.go)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return pubKeyPEM, nil
}
