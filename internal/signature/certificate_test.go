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

package signature

import (
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	cosignTypes "github.com/sigstore/cosign/v3/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddCertificateMetadata(t *testing.T) {
	cases := []struct {
		name string
		cert []byte
	}{
		{name: "Chainguard Cosign release", cert: ChainguardReleaseCert},
		{name: "OtherName SAN", cert: OtherNameSAN},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, _ := pem.Decode(c.cert)
			cer, err := x509.ParseCertificate(p.Bytes)
			require.NoError(t, err)

			metadata := map[string]string{}
			err = addCertificateMetadataTo(&metadata, cer)
			assert.NoError(t, err)

			snaps.MatchSnapshot(t, metadata)
		})
	}
}

func TestNewEntitySignature(t *testing.T) {
	signature, err := static.NewSignature(
		[]byte(`image`),
		"signature",
		static.WithLayerMediaType(types.MediaType((cosignTypes.DssePayloadType))),
		static.WithCertChain(
			ChainguardReleaseCert,
			SigstoreChainCert,
		),
	)
	require.NoError(t, err)

	es, err := NewEntitySignature(signature)
	require.NoError(t, err)

	snaps.MatchSnapshot(t, es)
}

func TestNameFrom(t *testing.T) {
	tests := []struct {
		name      string
		cert      []byte
		extractor func(*x509.Certificate) pkix.Name
		contains  string
	}{
		{
			name:      "extracts subject name successfully",
			cert:      ChainguardReleaseCert,
			extractor: func(c *x509.Certificate) pkix.Name { return c.Subject },
			contains:  "", // Subject is empty in this cert
		},
		{
			name:      "extracts issuer name successfully",
			cert:      ChainguardReleaseCert,
			extractor: func(c *x509.Certificate) pkix.Name { return c.Issuer },
			contains:  "sigstore-intermediate",
		},
		{
			name:      "handles empty name gracefully",
			cert:      ChainguardReleaseCert,
			extractor: func(c *x509.Certificate) pkix.Name { return pkix.Name{} },
			contains:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := pem.Decode(tt.cert)
			cert, err := x509.ParseCertificate(p.Bytes)
			require.NoError(t, err)

			nameExtractor := nameFrom(tt.extractor)
			result, err := nameExtractor(cert)

			assert.NoError(t, err)
			if tt.contains != "" {
				assert.Contains(t, result, tt.contains)
			}
		})
	}
}

func TestSan(t *testing.T) {
	tests := []struct {
		name     string
		cert     []byte
		expected []string
	}{
		{
			name:     "extracts SAN from Chainguard cert successfully",
			cert:     ChainguardReleaseCert,
			expected: []string{"URIs:https://github.com"},
		},
		{
			name:     "extracts OtherName SAN successfully",
			cert:     OtherNameSAN,
			expected: []string{"OtherName:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := pem.Decode(tt.cert)
			cert, err := x509.ParseCertificate(p.Bytes)
			require.NoError(t, err)

			result, err := san(cert)

			assert.NoError(t, err)
			for _, expectedPart := range tt.expected {
				if expectedPart != "" {
					assert.Contains(t, result, expectedPart)
				}
			}
		})
	}
}

func TestExtensionFrom(t *testing.T) {
	tests := []struct {
		name        string
		cert        []byte
		oid         asn1.ObjectIdentifier
		expectFound bool
	}{
		{
			name:        "finds existing Fulcio extension successfully",
			cert:        ChainguardReleaseCert,
			oid:         asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}, // Fulcio Issuer
			expectFound: true,
		},
		{
			name:        "finds SAN extension successfully",
			cert:        ChainguardReleaseCert,
			oid:         asn1.ObjectIdentifier{2, 5, 29, 17}, // Subject Alternative Name
			expectFound: true,
		},
		{
			name:        "returns nil for non-existent extension",
			cert:        ChainguardReleaseCert,
			oid:         asn1.ObjectIdentifier{1, 2, 3, 4, 5}, // Non-existent OID
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := pem.Decode(tt.cert)
			cert, err := x509.ParseCertificate(p.Bytes)
			require.NoError(t, err)

			result := extensionFrom(cert, tt.oid)

			if tt.expectFound {
				assert.NotNil(t, result)
				assert.Greater(t, len(result), 0)
			} else {
				assert.Nil(t, result)
			}
		})
	}
}

func TestRawString(t *testing.T) {
	tests := []struct {
		name        string
		cert        []byte
		oid         asn1.ObjectIdentifier
		expectFound bool
	}{
		{
			name:        "extracts raw string from existing Fulcio extension successfully",
			cert:        ChainguardReleaseCert,
			oid:         asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}, // Fulcio Issuer
			expectFound: true,
		},
		{
			name:        "extracts raw string from workflow trigger extension successfully",
			cert:        ChainguardReleaseCert,
			oid:         asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2}, // Workflow Trigger
			expectFound: true,
		},
		{
			name:        "returns empty string for non-existent extension",
			cert:        ChainguardReleaseCert,
			oid:         asn1.ObjectIdentifier{1, 2, 3, 4, 5}, // Non-existent OID
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := pem.Decode(tt.cert)
			cert, err := x509.ParseCertificate(p.Bytes)
			require.NoError(t, err)

			rawExtractor := rawString(tt.oid)
			result, err := rawExtractor(cert)

			assert.NoError(t, err)
			if tt.expectFound {
				assert.NotEmpty(t, result)
			} else {
				assert.Empty(t, result)
			}
		})
	}
}

func TestUtf8String(t *testing.T) {
	fulcioIssuerOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8} // Fulcio Issuer (V2)

	tests := []struct {
		name        string
		cert        []byte
		oid         asn1.ObjectIdentifier
		expectValid bool
		expectEmpty bool
	}{
		{
			name:        "extracts UTF8 string from Fulcio extension successfully",
			cert:        ChainguardReleaseCert,
			oid:         fulcioIssuerOID,
			expectValid: true,
			expectEmpty: false,
		},
		{
			name:        "returns empty string for non-existent extension gracefully",
			cert:        ChainguardReleaseCert,
			oid:         asn1.ObjectIdentifier{1, 2, 3, 4, 5}, // Non-existent OID
			expectValid: true,
			expectEmpty: true,
		},
		{
			name:        "handles invalid UTF8 extension with error",
			cert:        ChainguardReleaseCert,
			oid:         asn1.ObjectIdentifier{2, 5, 29, 15}, // Key Usage (not UTF8)
			expectValid: false,
			expectEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := pem.Decode(tt.cert)
			cert, err := x509.ParseCertificate(p.Bytes)
			require.NoError(t, err)

			utf8Extractor := utf8String(tt.oid)
			result, err := utf8Extractor(cert)

			if tt.expectValid {
				assert.NoError(t, err)
				if tt.expectEmpty {
					assert.Empty(t, result)
				} else {
					assert.NotEmpty(t, result)
				}
			} else {
				assert.Error(t, err)
			}
		})
	}
}
