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
	"strings"

	"github.com/spf13/afero"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const K8sClientKey contextKey = "k8s.client"

// KeyFromKeyRef resolves a key from either a file path or a Kubernetes secret reference.
// This provides a unified interface for both public and private key resolution.
// Supported formats:
// - File path: "/path/to/key.pem"
// - Kubernetes secret: "k8s://namespace/secret-name/key-field" (explicit key field)
// - Kubernetes secret: "k8s://namespace/secret-name" (auto-select if single key exists)
func KeyFromKeyRef(ctx context.Context, keyRef string, fs afero.Fs) ([]byte, error) {
	if strings.HasPrefix(keyRef, "k8s://") {
		return keyFromKubernetesSecret(ctx, keyRef)
	}
	return keyFromFile(keyRef, fs)
}

// PublicKeyFromKeyRef resolves a public key from either a file path or a Kubernetes secret reference.
// This provides a consistent interface with PrivateKeyFromKeyRef.
// Supported formats:
// - File path: "/path/to/public-key.pem"
// - Kubernetes secret: "k8s://namespace/secret-name/key-field" (explicit key field)
// - Kubernetes secret: "k8s://namespace/secret-name" (auto-select if single key exists)
func PublicKeyFromKeyRef(ctx context.Context, keyRef string, fs afero.Fs) ([]byte, error) {
	return KeyFromKeyRef(ctx, keyRef, fs)
}

// keyFromFile reads a key from the filesystem
func keyFromFile(keyPath string, fs afero.Fs) ([]byte, error) {
	keyBytes, err := afero.ReadFile(fs, keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key from file %q: %w", keyPath, err)
	}
	return keyBytes, nil
}

// keyFromKubernetesSecret reads a key from a Kubernetes secret
// Supported formats:
// - k8s://namespace/secret-name/key-field (explicit key field)
// - k8s://namespace/secret-name (auto-select if single key exists)
func keyFromKubernetesSecret(ctx context.Context, keyRef string) ([]byte, error) {
	// Validate format first before attempting to create client
	parts := strings.Split(strings.TrimPrefix(keyRef, "k8s://"), "/")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, fmt.Errorf("invalid k8s key reference format %q, expected k8s://namespace/secret-name or k8s://namespace/secret-name/key-field", keyRef)
	}

	namespace := parts[0]
	secretName := parts[1]
	var keyField string
	if len(parts) == 3 {
		keyField = parts[2]
	}

	if namespace == "" || secretName == "" {
		return nil, fmt.Errorf("invalid k8s key reference %q: namespace and secret name must be specified", keyRef)
	}

	k8sClient, err := getKubernetesClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("get kubernetes client: %w", err)
	}

	secret, err := k8sClient.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("fetch secret %s/%s: %w", namespace, secretName, err)
	}

	// If key field is specified, use it directly
	if keyField != "" {
		keyData, exists := secret.Data[keyField]
		if !exists {
			return nil, fmt.Errorf("key field %q not found in secret %s/%s", keyField, namespace, secretName)
		}
		return keyData, nil
	}

	// No key field specified - auto-select if single key exists
	keyCount := len(secret.Data)
	if keyCount == 0 {
		return nil, fmt.Errorf("secret %s/%s contains no keys", namespace, secretName)
	}
	if keyCount == 1 {
		// Get the single key
		for _, keyData := range secret.Data {
			return keyData, nil
		}
	}

	// Multiple keys exist - return error without exposing key names
	return nil, fmt.Errorf("secret %s/%s contains multiple keys, please specify the key field: k8s://%s/%s/<key-field>",
		namespace, secretName, namespace, secretName)
}

// getKubernetesClient retrieves a Kubernetes client from the context or creates a new one
func getKubernetesClient(ctx context.Context) (kubernetes.Interface, error) {
	// Try to get from context first (for testing)
	if client, ok := ctx.Value(K8sClientKey).(kubernetes.Interface); ok {
		return client, nil
	}

	// Create a new client using the same pattern as the existing kubernetes package
	// This follows the same pattern as used in the policy package
	config, err := getKubernetesConfig()
	if err != nil {
		return nil, fmt.Errorf("get kubernetes config: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}

	return client, nil
}

// getKubernetesConfig creates a Kubernetes config following the same pattern as the existing code
func getKubernetesConfig() (*rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, nil)
	return clientConfig.ClientConfig()
}
