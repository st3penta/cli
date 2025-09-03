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

package retrieve

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/sigstore/rekor/pkg/generated/models"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/conforma/cli/internal/image"
	"github.com/conforma/cli/internal/validate/vsa"
)

type vsaParams struct {
	image       string
	rekorURL    string
	timeout     time.Duration
	payloadHash string
}

func retrieveVSACmd() *cobra.Command {
	params := &vsaParams{
		rekorURL: "https://rekor.sigstore.dev",
		timeout:  30 * time.Second,
	}

	cmd := &cobra.Command{
		Use:   "vsa",
		Short: "Retrieve and display VSA entries with corresponding intoto and DSSE data",
		Long: hd.Doc(`
			Retrieve and display VSA entries with corresponding intoto and DSSE data from Rekor.

			This command searches for VSA records associated with a specific image digest
			or payload hash and displays the latest intoto entry along with its corresponding DSSE entry.

			The command will:
			- Parse the image reference to extract the digest (if using --image)
			- Search Rekor for VSA records containing the digest or payload hash
			- Find the corresponding intoto and DSSE entries
			- Display the entries in a readable format
			- Test the entry classification logic

			This is useful for testing the Rekor entry classification changes and debugging
			VSA retrieval issues.
		`),

		Example: hd.Doc(`
			Retrieve VSA by image digest:
			  ec retrieve vsa --image quay.io/redhat-user-workloads/rhtap-contract-tenant/golden-container/golden-container@sha256:185f6c39e5544479863024565bb7e63c6f2f0547c3ab4ddf99ac9b5755075cc9

			Retrieve VSA by payload hash directly:
			  ec retrieve vsa --payload-hash 185f6c39e5544479863024565bb7e63c6f2f0547c3ab4ddf99ac9b5755075cc9

			Use custom Rekor server:
			  ec retrieve vsa --image quay.io/test/image@sha256:abc123 --rekor-url https://rekor.example.com
		`),

		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if params.image == "" && params.payloadHash == "" {
				return fmt.Errorf("either --image or --payload-hash must be specified")
			}

			if params.image != "" && params.payloadHash != "" {
				return fmt.Errorf("cannot specify both --image and --payload-hash")
			}

			return runRetrieveVSA(cmd.Context(), params)
		},
	}

	cmd.Flags().StringVar(&params.image, "image", "", "Image reference with digest")
	cmd.Flags().StringVar(&params.payloadHash, "payload-hash", "", "Payload hash to search for (alternative to --image)")
	cmd.Flags().StringVar(&params.rekorURL, "rekor-url", params.rekorURL, "Rekor server URL")
	cmd.Flags().DurationVar(&params.timeout, "timeout", params.timeout, "Timeout for Rekor operations")

	return cmd
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func runRetrieveVSA(ctx context.Context, params *vsaParams) error {
	var payloadHash string

	if params.image != "" {
		// Use proper image parsing utilities
		ref, err := image.NewImageReference(params.image)
		if err != nil {
			return fmt.Errorf("failed to parse image reference: %w", err)
		}
		if ref.Digest == "" {
			return fmt.Errorf("image reference does not contain a digest: %s", params.image)
		}
		// The digest from the image reference is already in the correct format (sha256:hash)
		payloadHash = ref.Digest
		log.Infof("Extracted payload hash from image: %s", payloadHash)
	} else {
		payloadHash = params.payloadHash
		log.Infof("Using provided payload hash: %s", payloadHash)
	}

	// Create Rekor retriever
	opts := vsa.DefaultRetrievalOptions()
	opts.URL = params.rekorURL
	opts.Timeout = params.timeout

	retriever, err := vsa.NewRekorVSARetriever(opts)
	if err != nil {
		return fmt.Errorf("failed to create Rekor retriever: %w", err)
	}

	// Set timeout context
	ctx, cancel := context.WithTimeout(ctx, params.timeout)
	defer cancel()

	log.Infof("Searching Rekor for VSA entries with payload hash: %s", payloadHash)

	// Search for entries using RetrieveVSA which will find all entries for the image digest
	var entries []models.LogEntryAnon

	// For image digests, find the latest matching pair
	if strings.HasPrefix(payloadHash, "sha256:") {
		log.Infof("Searching for image digest: %s", payloadHash)

		// Get all entries without VSA filtering
		allEntries, err := retriever.GetAllEntriesForImageDigest(ctx, payloadHash)
		if err != nil {
			return fmt.Errorf("failed to get all entries: %w", err)
		}

		log.Infof("Found %d total entries for image digest", len(allEntries))

		// Find the latest matching pair where intoto has attestation and DSSE matches
		latestPair := retriever.FindLatestMatchingPair(ctx, allEntries)
		if latestPair != nil && latestPair.IntotoEntry != nil && latestPair.DSSEEntry != nil {
			log.Infof("Found latest matching pair: intoto LogIndex=%v, DSSE LogIndex=%v",
				latestPair.IntotoEntry.LogIndex, latestPair.DSSEEntry.LogIndex)
			entries = []models.LogEntryAnon{*latestPair.IntotoEntry, *latestPair.DSSEEntry}
		} else {
			log.Infof("No matching pair found, showing first 3 entries as fallback")
			entries = allEntries
			if len(entries) > 3 {
				entries = allEntries[:3]
			}
		}
	} else {
		// For raw payload hashes, use FindByPayloadHash
		dualPair, err := retriever.FindByPayloadHash(ctx, payloadHash)
		if err != nil {
			return fmt.Errorf("failed to find entries by payload hash: %w", err)
		}

		// Collect all entries from the dual pair
		if dualPair.IntotoEntry != nil {
			entries = append(entries, *dualPair.IntotoEntry)
		}
		if dualPair.DSSEEntry != nil {
			entries = append(entries, *dualPair.DSSEEntry)
		}
	}

	if len(entries) == 0 {
		log.Info("No VSA entries found for the given payload hash")
		return nil
	}

	log.Infof("Found %d entries", len(entries))

	// Display entries and test classification
	for i, entry := range entries {
		fmt.Printf("\n=== Entry %d ===\n", i+1)

		// Display basic entry information
		fmt.Printf("Log Index: %v\n", entry.LogIndex)
		fmt.Printf("Log ID: %v\n", entry.LogID)
		fmt.Printf("Integrated Time: %v\n", entry.IntegratedTime)

		// Show entry body structure (decoded)
		if entry.Body != nil {
			if bodyStr, ok := entry.Body.(string); ok && bodyStr != "" {
				// Try to decode and show the body structure
				if raw, err := base64.StdEncoding.DecodeString(bodyStr); err == nil {
					var body map[string]any
					if err := json.Unmarshal(raw, &body); err == nil {
						fmt.Printf("Body Structure: %+v\n", body)
					} else {
						fmt.Printf("Body (raw): %s\n", string(raw))
					}
				} else {
					fmt.Printf("Body (base64): %s\n", bodyStr)
				}
			}
		}

		// Show attestation info if present
		if entry.Attestation != nil && entry.Attestation.Data != nil {
			fmt.Printf("Has Attestation: Yes\n")
			if attBytes, err := base64.StdEncoding.DecodeString(string(entry.Attestation.Data)); err == nil {
				fmt.Printf("Attestation Preview: %s...\n", string(attBytes)[:min(len(attBytes), 100)])
			}
		} else {
			fmt.Printf("Has Attestation: No\n")
		}
	}

	return nil
}
