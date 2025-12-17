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

package utils

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/afero"
)

// PrivateKeyFromKeyRef resolves a private key from either a file path or a Kubernetes secret reference.
// This follows the same pattern as cosignSig.PublicKeyFromKeyRef but for private keys.
// Supported formats:
// - File path: "/path/to/private-key.pem"
// - Kubernetes secret: "k8s://namespace/secret-name"
// - Kubernetes secret: "k8s://namespace/secret-name/key-field"
func PrivateKeyFromKeyRef(ctx context.Context, keyRef string, fs afero.Fs) ([]byte, error) {
	// If the key-field is not specified assume it is "cosign.key"
	adjustedKeyRef := keyRef
	if strings.HasPrefix(keyRef, "k8s://") {
		parts := strings.Split(strings.TrimPrefix(keyRef, "k8s://"), "/")
		if len(parts) == 2 {
			adjustedKeyRef = fmt.Sprintf("%s/cosign.key", keyRef)
		}
	}
	return KeyFromKeyRef(ctx, adjustedKeyRef, fs)
}

// PasswordFromKeyRef resolves a password from either environment variable or a Kubernetes secret reference.
// This provides a unified interface for password resolution similar to PrivateKeyFromKeyRef.
// Supported formats:
// - Environment variable: "" (empty string uses COSIGN_PASSWORD env var)
// - Kubernetes secret: "k8s://namespace/secret-name" (assumes "cosign.password" key)
// - Kubernetes secret: "k8s://namespace/secret-name/key-field" (explicit key field)
func PasswordFromKeyRef(ctx context.Context, keyRef string) ([]byte, error) {
	// If keyRef is empty, use environment variable (backward compatibility)
	if keyRef == "" {
		return []byte(os.Getenv("COSIGN_PASSWORD")), nil
	}

	// If it's a Kubernetes secret reference
	if strings.HasPrefix(keyRef, "k8s://") {
		// If the key-field is not specified assume it is "cosign.password"
		adjustedKeyRef := keyRef
		parts := strings.Split(strings.TrimPrefix(keyRef, "k8s://"), "/")
		if len(parts) == 2 {
			adjustedKeyRef = fmt.Sprintf("%s/cosign.password", keyRef)
		}
		return KeyFromKeyRef(ctx, adjustedKeyRef, nil) // fs not needed for k8s secrets
	}

	// For any other format, treat it as environment variable name
	return []byte(os.Getenv(keyRef)), nil
}
