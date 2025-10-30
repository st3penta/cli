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

package validate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	hd "github.com/MakeNowJust/heredoc"
	ecapi "github.com/conforma/crds/api/v1alpha1"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/image"
	"github.com/conforma/cli/internal/output"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/utils"
	validate_utils "github.com/conforma/cli/internal/validate"
	"github.com/conforma/cli/internal/validate/vsa"
)

// Constants for default values
const (
	DefaultWorkers         = 5
	DefaultVSAExpiration   = "168h" // 7 days
	DefaultEffectiveTime   = "now"
	DefaultStrictMode      = true
	DefaultFallbackEnabled = true
	DefaultTimeoutDuration = 30 * time.Minute
)

// Constants for validation status
const (
	unknownReason = "unknown"
)

// Reason code mappings
var reasonCodeToDisplay = map[string]string{
	"policy_mismatch":  "policy mismatch",
	"predicate_failed": "predicate failed",
	"no_vsa":           "no vsa",
	"expired":          "expired",
	"retrieval_failed": "retrieval failed",
}

// Helper function for color-aware output
func printVSAInfo(w io.Writer, message string) {
	fmt.Fprintf(w, "[INFO] %s\n", message)
}

// validateVSAData holds the command data
type validateVSAData struct {
	// Input options
	vsaIdentifier string // Single VSA identifier (image digest, file path)
	images        string // Application snapshot file
	policyConfig  string // Policy configuration

	// VSA retrieval options
	vsaRetrieval []string // VSA retrieval backends (rekor@, file@)

	// Policy comparison options
	effectiveTime string // Effective time for comparison
	// Note: imageDigest, imageRef, imageURL will be extracted from vsaIdentifier or images

	// VSA options
	vsaExpirationStr string        // VSA expiration threshold as string
	vsaExpiration    time.Duration // VSA expiration threshold as duration

	// Signature verification options
	ignoreSignatureVerification bool   // Whether to ignore signature verification (default: false, so signature is verified by default)
	publicKeyPath               string // Path to public key for verification

	// Fallback options
	fallbackToImageValidation bool   // Enable fallback to image validation (computed from noFallback)
	noFallback                bool   // Disable fallback to image validation
	fallbackPublicKey         string // Public key for fallback image validation

	// Output options
	output []string // Output formats
	strict bool     // Strict mode (fail on any error)

	// Parallel processing options
	workers int // Number of worker threads for parallel processing

	// Output formatting options
	noColor    bool // Disable color output
	forceColor bool // Force color output

	// Internal state
	policySpec ecapi.EnterpriseContractPolicySpec
	retriever  vsa.VSARetriever
	info       bool // Detailed output flag

	// Precomputed fallback validation context (created once, reused for all fallbacks)
	fallbackContext *vsa.FallbackValidationContext

	// Snapshot spec for fallback validation
	snapshot *app.SnapshotSpec
}

func NewValidateVSACmd() *cobra.Command {
	data := &validateVSAData{
		strict:                    DefaultStrictMode,
		effectiveTime:             DefaultEffectiveTime,
		vsaExpirationStr:          DefaultVSAExpiration,
		vsaExpiration:             168 * time.Hour, // 7 days default
		workers:                   DefaultWorkers,
		fallbackToImageValidation: DefaultFallbackEnabled,
	}

	cmd := &cobra.Command{
		Use:   "vsa <vsa-identifier>",
		Short: "Validate VSA (Verification Summary Attestation)",
		Long: hd.Doc(`
			Validate VSA by comparing the embedded policy against a supplied policy configuration.
			
			By default, VSA signature verification is enabled and requires a public key.
			Use --ignore-signature-verification to disable signature verification.
			
			By default, fallback to image validation is enabled when VSA validation fails.
			Use --no-fallback to disable this behavior.
			
			Supports validation of:
			- Single VSA by identifier (image digest, file path)
			- Multiple VSAs from application snapshot
			
			VSA retrieval supports:
			- Rekor transparency log
			- Local filesystem storage
			- Multiple backends with fallback
		`),
		// Check positional arguments
		// Example: ec validate vsa image1@sha256:abc123 --policy policy.yaml --vsa-public-key key.pub
		Args: func(cmd *cobra.Command, args []string) error {
			// Custom argument validation using Cobra's Args field
			if len(args) > 1 {
				return fmt.Errorf("too many arguments provided")
			}

			// Validate VSA identifier format if provided
			if len(args) == 1 {
				identifier := args[0]
				if !vsa.IsValidVSAIdentifier(identifier) {
					return fmt.Errorf("invalid VSA identifier format: %s", identifier)
				}
			}

			return nil
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Compute fallback behavior: enabled by default, disabled if --no-fallback is set
			data.fallbackToImageValidation = !data.noFallback

			return validateVSAInput(data, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runValidateVSA(cmd, data, args, afero.NewOsFs())
		},
	}

	// Add flags
	addVSAFlags(cmd, data)
	return cmd
}

// addVSAFlags adds all the command flags with Cobra's built-in validation
func addVSAFlags(cmd *cobra.Command, data *validateVSAData) {
	// Input options
	cmd.Flags().StringVarP(&data.vsaIdentifier, "vsa", "v", "", "VSA identifier (image digest, file path)")
	cmd.Flags().StringVar(&data.images, "images", "", "Application snapshot file")
	cmd.Flags().StringVarP(&data.policyConfig, "policy", "p", "", "Policy configuration")

	// VSA retrieval options
	cmd.Flags().StringSliceVar(&data.vsaRetrieval, "vsa-retrieval", []string{}, "VSA retrieval backends (rekor@, file@)")

	// Policy comparison options
	cmd.Flags().StringVar(&data.effectiveTime, "effective-time", "now", "Effective time for comparison")

	// VSA options
	cmd.Flags().StringVar(&data.vsaExpirationStr, "vsa-expiration", DefaultVSAExpiration, "VSA expiration threshold (e.g., 24h, 7d, 1w, 1m)")

	// Signature verification options
	cmd.Flags().BoolVar(&data.ignoreSignatureVerification, "ignore-signature-verification", false, "Ignore VSA signature verification (signature verification is enabled by default)")
	cmd.Flags().StringVar(&data.publicKeyPath, "vsa-public-key", "", "Path to public key for VSA signature verification (required by default)")

	// Fallback options
	cmd.Flags().BoolVar(&data.noFallback, "no-fallback", false, "Disable fallback to image validation when VSA validation fails (fallback is enabled by default)")
	cmd.Flags().StringVar(&data.fallbackPublicKey, "fallback-public-key", "", "Public key to use for fallback image validation (different from VSA verification key)")
	// Output options
	cmd.Flags().StringSliceVar(&data.output, "output", []string{}, "Output formats (e.g., json, yaml, text)")
	cmd.Flags().BoolVar(&data.strict, "strict", DefaultStrictMode, "Exit with non-zero code if validation fails")

	// Parallel processing options
	cmd.Flags().IntVar(&data.workers, "workers", DefaultWorkers, "Number of worker threads for parallel processing")

	// Output formatting options
	cmd.Flags().BoolVar(&data.noColor, "no-color", false, "Disable color when using text output even when the current terminal supports it")
	cmd.Flags().BoolVar(&data.forceColor, "color", false, "Enable color when using text output even when the current terminal does not support it")

	// ===== COBRA BUILT-IN VALIDATION =====

	// 1. Required flags
	if err := cmd.MarkFlagRequired("policy"); err != nil {
		log.Warnf("Failed to mark policy flag as required: %v", err)
	}

	// 2. Mutual exclusivity: --vsa and --images are mutually exclusive
	cmd.MarkFlagsMutuallyExclusive("vsa", "images")

}

// runValidateVSA is the main command execution function
func runValidateVSA(cmd *cobra.Command, data *validateVSAData, args []string, fs afero.Fs) error {
	ctx := cmd.Context()

	// Set color support based on flags
	utils.SetColorEnabled(data.noColor, data.forceColor)

	// Parse VSA expiration
	if err := parseVSAExpiration(data); err != nil {
		return err
	}

	// Load policy configuration
	if err := loadPolicyConfig(ctx, data); err != nil {
		return err
	}

	// Precompute fallback validation context if fallback is enabled
	if data.fallbackToImageValidation {
		// Use the same resolved policy configuration as the main validation
		policyConfiguration, err := validate_utils.GetPolicyConfig(ctx, data.policyConfig)
		if err != nil {
			return fmt.Errorf("failed to get policy configuration for fallback: %w", err)
		}

		fallbackConfig := &vsa.FallbackConfig{
			FallbackToImageValidation: data.fallbackToImageValidation,
			FallbackPublicKey:         data.fallbackPublicKey,
			PolicyConfig:              policyConfiguration, // Use resolved policy configuration
			EffectiveTime:             data.effectiveTime,
			Info:                      data.info,
		}
		fallbackContext, err := vsa.CreateFallbackValidationContext(ctx, fallbackConfig)
		if err != nil {
			return fmt.Errorf("failed to create fallback validation context: %w", err)
		}
		data.fallbackContext = fallbackContext
	}

	// Create VSA retriever
	retriever, err := vsa.CreateVSARetriever(data.vsaRetrieval, data.vsaIdentifier, data.images)
	if err != nil {
		return err
	}
	data.retriever = retriever

	// Process validation
	// Normalize input to SnapshotSpec using DetermineInputSpec (same as validate image)
	// This unifies --images and single identifier handling
	identifier := extractVSAIdentifier(data, args)

	// Use DetermineInputSpec to normalize input (supports both --images and single identifier)
	snapshot, _, err := applicationsnapshot.DetermineInputSpec(ctx, applicationsnapshot.Input{
		Image:  identifier,  // Single VSA identifier
		Images: data.images, // Snapshot file/JSON string
	})
	if err != nil {
		return fmt.Errorf("failed to parse input: %w", err)
	}

	if len(snapshot.Components) == 0 {
		return fmt.Errorf("no components found in input")
	}

	// Print appropriate message based on input type
	if data.images != "" {
		printVSAInfo(os.Stdout, fmt.Sprintf("Validating VSAs from snapshot: %s", data.images))
	} else {
		printVSAInfo(os.Stdout, fmt.Sprintf("Validating VSA: %s", identifier))
	}
	printVSAInfo(os.Stdout, fmt.Sprintf("Policy: %s", data.policyConfig))

	return validateSnapshotVSAsFromSpec(ctx, snapshot, data, fs, cmd)
}

// validateVSAInput validates the command input using Cobra's validation patterns
func validateVSAInput(data *validateVSAData, args []string) error {
	// Set VSA identifier from args if provided
	if len(args) > 0 {
		data.vsaIdentifier = args[0]
	}

	// Check if we have either VSA identifier, --vsa, or --images
	if data.vsaIdentifier == "" && data.images == "" {
		return fmt.Errorf("either --vsa, --images, or VSA identifier must be provided")
	}

	// Validate VSA expiration format early
	if err := parseVSAExpiration(data); err != nil {
		return fmt.Errorf("invalid --vsa-expiration: %w", err)
	}

	// Validate signature verification flags
	// By default, signature verification is enabled, so vsa-public-key is required unless --ignore-signature-verification is set
	if !data.ignoreSignatureVerification && data.publicKeyPath == "" {
		return fmt.Errorf("--vsa-public-key is required for signature verification (use --ignore-signature-verification to disable signature verification)")
	}

	// Validate fallback flags
	if data.fallbackToImageValidation && data.fallbackPublicKey == "" {
		return fmt.Errorf("--fallback-public-key is required when --fallback-to-image-validation is enabled")
	}

	// Validate that fallback only works with image references
	if data.fallbackToImageValidation && data.vsaIdentifier != "" {
		identifierType := vsa.DetectIdentifierType(data.vsaIdentifier)

		// Check if it's actually a file path (even if detected as image reference due to name.ParseReference bug)
		if vsa.IsFilePathLike(data.vsaIdentifier) {
			return fmt.Errorf("fallback not supported for file paths (identifier: %s)", data.vsaIdentifier)
		}

		if identifierType != vsa.IdentifierImageReference && identifierType != vsa.IdentifierImageDigest {
			return fmt.Errorf("fallback only supported for image references and digests, not %v (identifier: %s)", identifierType, data.vsaIdentifier)
		}
	}

	return nil
}

// parseVSAExpiration parses the VSA expiration string into a duration
func parseVSAExpiration(data *validateVSAData) error {
	expiration, err := vsa.ParseVSAExpirationDuration(data.vsaExpirationStr)
	if err != nil {
		return fmt.Errorf("invalid VSA expiration: %w", err)
	}
	data.vsaExpiration = expiration
	return nil
}

// loadPolicyConfig loads the policy configuration from multiple sources
func loadPolicyConfig(ctx context.Context, data *validateVSAData) error {
	// Resolve policy configuration using the standard utility function
	policyConfiguration, err := validate_utils.GetPolicyConfig(ctx, data.policyConfig)
	if err != nil {
		return fmt.Errorf("failed to get policy configuration: %w", err)
	}

	// Use the standard policy processing like other validation commands
	policyOptions := policy.Options{
		EffectiveTime: data.effectiveTime,
		PolicyRef:     policyConfiguration, // Use the resolved policy configuration
		PublicKey:     data.publicKeyPath,  // Use the available publicKeyPath field
		// Note: RekorURL is not available in VSA command, will use default
	}

	// Process policy using the standard PreProcessPolicy function
	processedPolicy, _, err := policy.PreProcessPolicy(ctx, policyOptions)
	if err != nil {
		return fmt.Errorf("failed to process policy: %w", err)
	}

	// Store the policy spec for comparison
	data.policySpec = processedPolicy.Spec()

	return nil
}

// extractVSAIdentifier extracts the VSA identifier from args or data
func extractVSAIdentifier(data *validateVSAData, args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return data.vsaIdentifier
}

// worker processes components from the jobs channel and sends results to the results channel
func worker(jobs <-chan app.SnapshotComponent, results chan<- vsa.ComponentResult, ctx context.Context, data *validateVSAData) {
	// Create worker-specific fallback context once per worker
	var workerFallbackContext *vsa.WorkerFallbackContext
	var ctxErr error

	if data.fallbackToImageValidation && data.fallbackContext != nil {
		var err error
		workerFallbackContext, err = vsa.CreateWorkerFallbackContext(ctx, data.fallbackContext.FallbackPolicy)
		if err != nil {
			// Store the error but don't drain the channel - let other workers continue
			ctxErr = fmt.Errorf("failed to create worker fallback context: %w", err)
		}
	}

	// Process jobs with error handling that doesn't starve other workers
	for component := range jobs {
		var result vsa.ComponentResult

		if ctxErr != nil {
			// If we have a context error, emit error for this specific job and continue
			// Other workers can still process their share of jobs
			result = vsa.ComponentResult{
				ComponentName: component.Name,
				ImageRef:      component.ContainerImage,
				Error:         ctxErr,
			}
		} else {
			// Normal processing with worker context
			result = processSnapshotComponentWithWorkerContext(ctx, component, data, workerFallbackContext)
		}

		results <- result
	}
}

// validateSnapshotVSAsFromSpec processes components from a SnapshotSpec in parallel
// This is the unified processing path used by both --images and single identifier cases
func validateSnapshotVSAsFromSpec(ctx context.Context, snapshot *app.SnapshotSpec, data *validateVSAData, fs afero.Fs, cmd *cobra.Command) error {
	// Store snapshot spec for use in fallback validation
	data.snapshot = snapshot

	// Process components in parallel
	allResults, err := processComponentsInParallel(ctx, snapshot.Components, data)
	if err != nil {
		return err
	}

	// Display results
	if err := displayComponentResults(allResults, data, cmd); err != nil {
		return err
	}

	// Handle output formatting
	if err := handleSnapshotOutput(allResults, data, fs, cmd); err != nil {
		return err
	}

	// Check strict mode
	return checkStrictMode(allResults, data)
}

// processComponentsInParallel processes all components using parallel workers
func processComponentsInParallel(ctx context.Context, components []app.SnapshotComponent, data *validateVSAData) ([]vsa.ComponentResult, error) {
	numComponents := len(components)
	numWorkers := data.workers

	printVSAInfo(os.Stdout, fmt.Sprintf("Found %d components in snapshot", numComponents))
	printVSAInfo(os.Stdout, fmt.Sprintf("=== Processing Components in Parallel (%d workers) ===", numWorkers))

	// Add timeout for parallel processing to prevent hanging
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeoutDuration)
	defer cancel()

	// Set up parallel processing infrastructure
	jobs := make(chan app.SnapshotComponent, numComponents)
	results := make(chan vsa.ComponentResult, numComponents)

	// Use WaitGroup to track worker completion
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(jobs, results, ctx, data)
		}()
	}

	// Close results channel after all workers finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Send all components to workers
	for _, component := range components {
		select {
		case jobs <- component:
			// Component sent successfully
		case <-ctx.Done():
			close(jobs)
			// Don't wait for workers - context cancellation will signal them to stop
			// and the results channel will be closed by the goroutine after workers finish
			return nil, fmt.Errorf("parallel processing timeout after %v: %w", DefaultTimeoutDuration, ctx.Err())
		}
	}
	close(jobs)

	// Collect results with timeout handling
	var allResults []vsa.ComponentResult
	for i := 0; i < numComponents; i++ {
		select {
		case result, ok := <-results:
			if !ok {
				// Channel closed, but we haven't received all results
				// This shouldn't happen normally, but handle gracefully
				return allResults, fmt.Errorf("results channel closed prematurely (received %d/%d results)", len(allResults), numComponents)
			}
			allResults = append(allResults, result)
		case <-ctx.Done():
			// Timeout during collection - return with partial results
			// Don't wait for workers as they may be blocked trying to send to a full buffer
			// The context cancellation will signal workers to stop processing
			return nil, fmt.Errorf("parallel processing timeout after %v: %w", DefaultTimeoutDuration, ctx.Err())
		}
	}

	// Sort results by component name for consistent display
	sort.Slice(allResults, func(i, j int) bool {
		return allResults[i].ComponentName < allResults[j].ComponentName
	})

	return allResults, nil
}

// Data structures for aggregated section data
type ImageStatus struct {
	Index          int
	Digest         string // Shortened digest
	VSAStatus      string // "PASSED" or "FAILED(reason=...)"
	FallbackStatus string // "PASSED", "FAILED", or ""
}

type PolicyDiffCounts struct {
	Added   int
	Removed int
	Changed int
}

// AllSectionsData - Aggregated data for all sections in one structure
// Collected in a single pass for efficiency
type AllSectionsData struct {
	// Result section data
	OverallPassed bool
	FallbackUsed  bool
	FallbackCount int
	TotalImages   int
	ImageStatuses []ImageStatus

	// VSA Summary data
	SignatureStatus  string
	PredicatePassed  int
	PredicateFailed  int
	PolicyMatches    int
	PolicyMismatches int
	PolicyDiffCounts map[string]PolicyDiffCounts // keyed by short digest
	FallbackReasons  map[string]bool             // deduplicated reasons

	// Policy Diff data
	HasPolicyDiff  bool
	AffectedImages []string

	// Final Summary data
	VSAPassed       int
	VSAFailed       int
	FallbackPassed  int
	FallbackFailed  int
	FallbackNotUsed int

	// Fallback results (already processed, no re-processing needed)
	FallbackResults []validate_utils.Result
}

// Helper functions

// shortenImageDigest extracts and shortens image digest to 8 characters
func shortenImageDigest(imageRef string) string {
	// Extract digest from image reference (format: registry/repo@sha256:digest)
	parts := strings.Split(imageRef, "@")
	if len(parts) < 2 {
		// No digest, return first 8 chars of image ref
		if len(imageRef) > 8 {
			return "…" + imageRef[len(imageRef)-8:]
		}
		return imageRef
	}

	digest := parts[1]
	// Remove sha256: prefix if present
	digest = strings.TrimPrefix(digest, "sha256:")
	// Return first 8 characters
	if len(digest) >= 8 {
		return digest[:8]
	}
	return digest
}

// extractFallbackReason extracts the reason for fallback from ValidationResult
// Prefers structured ReasonCode field, falls back to message parsing for backward compatibility
func extractFallbackReason(result *vsa.ValidationResult) string {
	if result == nil {
		return unknownReason
	}

	// Prefer structured ReasonCode field if available
	if result.ReasonCode != "" {
		if display, ok := reasonCodeToDisplay[result.ReasonCode]; ok {
			return display
		}
		// Unknown reason code, fall through to message parsing
	}

	// Fallback to message parsing for backward compatibility (e.g., old ValidationResult without ReasonCode)
	return extractReasonFromMessage(result.Message)
}

// extractReasonFromMessage parses reason from message text (fallback for old ValidationResult)
func extractReasonFromMessage(message string) string {
	if strings.Contains(message, "Policy mismatch") {
		return "policy mismatch"
	}
	if strings.Contains(message, "predicate") || strings.Contains(message, "Predicate") {
		return "predicate failed"
	}
	if strings.Contains(message, "No VSA found") || strings.Contains(message, "no VSA") {
		return "no vsa"
	}
	if strings.Contains(message, "expired") {
		return "expired"
	}
	if strings.Contains(message, "failed to check existing VSA") || strings.Contains(message, "retrieval failed") {
		return "retrieval failed"
	}
	return unknownReason
}

// parsePolicyDiffFromMessage extracts policy diff counts from ValidationResult
// Prefers structured PolicyDiff field, falls back to message parsing for backward compatibility
func parsePolicyDiffFromMessage(result *vsa.ValidationResult) (added, removed, changed int, hasDiff bool) {
	if result == nil {
		return 0, 0, 0, false
	}

	// Prefer structured PolicyDiff field if available
	if result.PolicyDiff != nil {
		return result.PolicyDiff.Added, result.PolicyDiff.Removed, result.PolicyDiff.Changed, true
	}

	// Fallback to message parsing for backward compatibility (e.g., old ValidationResult without PolicyDiff)
	message := result.Message
	if !strings.Contains(message, "Policy mismatch") {
		return 0, 0, 0, false
	}

	// Look for pattern: "X added, Y removed, Z changed"
	// Example: "❌ Policy mismatch detected — 1 added, 0 removed, 0 changed; 1 differences"
	// Note: Uses em dash (—) not hyphen (-)
	parts := strings.Split(message, "—")
	if len(parts) < 2 {
		// Try with regular dash as fallback
		parts = strings.Split(message, "-")
		if len(parts) < 2 {
			return 0, 0, 0, true
		}
	}

	diffPart := parts[1]
	// Extract numbers - handle both "1 added, 0 removed, 0 changed" and "1 added, 0 removed, 0 changed;"
	_, err := fmt.Sscanf(diffPart, "%d added, %d removed, %d changed", &added, &removed, &changed)
	if err != nil {
		// If parsing fails, still return hasDiff=true to indicate policy mismatch exists
		return 0, 0, 0, true
	}
	return added, removed, changed, true
}

// processVSAResult processes a VSA validation result and updates the image status and aggregated data
func processVSAResult(vsaResult *vsa.ValidationResult, imgStatus *ImageStatus, data *AllSectionsData, shortDigest string) {
	if vsaResult.Passed {
		imgStatus.VSAStatus = "PASSED"
		data.VSAPassed++
	} else {
		reason := extractFallbackReason(vsaResult)
		imgStatus.VSAStatus = fmt.Sprintf("FAILED(reason=%s)", reason)
		data.VSAFailed++
		data.FallbackReasons[reason] = true
	}

	// Aggregate signature status
	// When SignatureVerified is false, mark as NOT VERIFIED
	// This covers both cases: signature verification failure and retrieval failure (no VSA to verify)
	if !vsaResult.SignatureVerified {
		data.SignatureStatus = "NOT VERIFIED"
	}

	// Aggregate predicate status
	if vsaResult.PredicateOutcome == "passed" {
		data.PredicatePassed++
	} else if vsaResult.PredicateOutcome != "" {
		data.PredicateFailed++
	}

	// Check for policy diff using structured fields (preferred) or message parsing (fallback)
	added, removed, changed, hasDiff := parsePolicyDiffFromMessage(vsaResult)
	if hasDiff {
		data.HasPolicyDiff = true
		data.AffectedImages = append(data.AffectedImages, shortDigest)
		data.PolicyDiffCounts[shortDigest] = PolicyDiffCounts{
			Added: added, Removed: removed, Changed: changed,
		}
		data.PolicyMismatches++
	} else if vsaResult.Passed {
		data.PolicyMatches++
	}
}

// aggregateAllSectionsData - Single pass aggregation, collects all data needed
func aggregateAllSectionsData(allResults []vsa.ComponentResult) AllSectionsData {
	data := AllSectionsData{
		TotalImages:      len(allResults),
		FallbackReasons:  make(map[string]bool),
		PolicyDiffCounts: make(map[string]PolicyDiffCounts),
		SignatureStatus:  "VERIFIED", // Default, will be overridden if any not verified
	}

	// Single iteration - collect everything at once
	for i, result := range allResults {
		shortDigest := shortenImageDigest(result.ImageRef)

		// Collect image status
		imgStatus := ImageStatus{
			Index:  i + 1,
			Digest: shortDigest,
		}

		// Process VSA result (always process if available, even if there's an error)
		if result.Result != nil {
			processVSAResult(result.Result, &imgStatus, &data, shortDigest)
		} else if result.Error != nil {
			// If there's an error but no Result, create a status from the error
			reason := extractReasonFromMessage(result.Error.Error())
			imgStatus.VSAStatus = fmt.Sprintf("FAILED(reason=%s)", reason)
			data.VSAFailed++
			data.FallbackReasons[reason] = true
			// When VSA retrieval fails, signature cannot be verified
			data.SignatureStatus = "NOT VERIFIED"
		}

		// Handle fallback
		if result.FallbackResult != nil {
			data.FallbackUsed = true
			data.FallbackCount++
			data.FallbackResults = append(data.FallbackResults, *result.FallbackResult)

			if result.FallbackResult.Component.Success {
				imgStatus.FallbackStatus = "PASSED"
				data.FallbackPassed++
			} else {
				imgStatus.FallbackStatus = "FAILED"
				data.FallbackFailed++
			}
		} else {
			data.FallbackNotUsed++
		}

		data.ImageStatuses = append(data.ImageStatuses, imgStatus)
	}

	// Determine overall result
	// Overall passes if: all VSA passed, OR fallback was used and at least one fallback passed
	data.OverallPassed = (data.VSAPassed == data.TotalImages) ||
		(data.FallbackUsed && data.FallbackPassed > 0)

	return data
}

// displayHeaderSection - Displays header with timestamp
func displayHeaderSection(timestamp time.Time) {
	fmt.Printf("=== VALIDATE VSA RESULT — %s ===\n", timestamp.Format(time.RFC3339))
}

// displayResultSection - Displays Result section
func displayResultSection(data AllSectionsData) {
	fmt.Println("Result")
	if data.OverallPassed {
		fmt.Println("  Overall: ✅ PASSED")
	} else {
		fmt.Println("  Overall: ❌ FAILED")
	}

	if data.FallbackUsed {
		if data.FallbackCount == data.TotalImages {
			fmt.Println("  Fallback: used for all images")
		} else {
			fmt.Println("  Fallback: used for some images")
		}
	}

	fmt.Printf("  Images (%d):\n", data.TotalImages)
	for _, img := range data.ImageStatuses {
		statusLine := fmt.Sprintf("    [%d] …%s  VSA=%s", img.Index, img.Digest, img.VSAStatus)
		if img.FallbackStatus != "" {
			statusLine += fmt.Sprintf("  Fallback=%s", img.FallbackStatus)
		}
		fmt.Println(statusLine)
	}
}

// displayVSASummarySection - Displays VSA Summary section
func displayVSASummarySection(data AllSectionsData) {
	fmt.Println("VSA Summary")
	fmt.Printf("  Signature: %s\n", data.SignatureStatus)

	// Predicate status
	totalPredicates := data.PredicatePassed + data.PredicateFailed
	if totalPredicates == 0 {
		fmt.Println("  Predicate: (no predicate data)")
	} else if data.PredicateFailed == 0 {
		fmt.Printf("  Predicate: passed (%d/%d)\n", data.PredicatePassed, totalPredicates)
	} else if data.PredicatePassed == 0 {
		fmt.Printf("  Predicate: failed (%d/%d)\n", data.PredicateFailed, totalPredicates)
	} else {
		fmt.Printf("  Predicate: mixed (passed: %d, failed: %d)\n", data.PredicatePassed, data.PredicateFailed)
	}

	// Policy status
	totalPolicyChecks := data.PolicyMatches + data.PolicyMismatches
	if totalPolicyChecks == 0 {
		fmt.Println("  Policy: (no policy data)")
	} else if data.PolicyMismatches == 0 {
		fmt.Println("  Policy: matches (no differences)")
	} else {
		// Aggregate policy diff counts
		totals := aggregatePolicyDiffTotals(data.PolicyDiffCounts)
		fmt.Printf("  Policy: mismatches on %d/%d images (adds=%d, removes=%d, changes=%d)\n",
			data.PolicyMismatches, totalPolicyChecks, totals.Added, totals.Removed, totals.Changed)
	}

	// Fallback reasons
	if len(data.FallbackReasons) > 0 {
		var reasons []string
		for reason := range data.FallbackReasons {
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		fmt.Printf("  Fallback reason(s): %s\n", strings.Join(reasons, ", "))
	}
}

// displayPolicyDiffSection - Displays Policy Diff section (only if policy diff exists)
func displayPolicyDiffSection(data AllSectionsData) {
	if !data.HasPolicyDiff {
		return
	}

	fmt.Println("Policy Diff (summary)")
	fmt.Printf("  Affected images: [%s]\n", strings.Join(data.AffectedImages, ", "))

	// Aggregate policy diff counts across all affected images
	totals := aggregatePolicyDiffTotals(data.PolicyDiffCounts)

	// Display summary
	if totals.Added > 0 {
		// Show added rules - for now just show count, could be enhanced to show rule names
		fmt.Printf("  Added:   [include] %d\n", totals.Added)
	} else {
		fmt.Println("  Added:   none")
	}

	if totals.Removed > 0 {
		fmt.Printf("  Removed: %d\n", totals.Removed)
	} else {
		fmt.Println("  Removed: none")
	}

	if totals.Changed > 0 {
		fmt.Printf("  Changed: %d\n", totals.Changed)
	} else {
		fmt.Println("  Changed: none")
	}
}

// aggregatePolicyDiffTotals aggregates policy diff counts across all images
func aggregatePolicyDiffTotals(diffCounts map[string]PolicyDiffCounts) PolicyDiffCounts {
	var totals PolicyDiffCounts
	for _, counts := range diffCounts {
		totals.Added += counts.Added
		totals.Removed += counts.Removed
		totals.Changed += counts.Changed
	}
	return totals
}

// collectFallbackResults extracts fallback results from component results
func collectFallbackResults(allResults []vsa.ComponentResult) []validate_utils.Result {
	var fallbackResults []validate_utils.Result
	for _, result := range allResults {
		if result.FallbackResult != nil {
			fallbackResults = append(fallbackResults, *result.FallbackResult)
		}
	}
	return fallbackResults
}

// buildFallbackReportData builds report data for fallback validation results
func buildFallbackReportData(fallbackResults []validate_utils.Result, vsaData *validateVSAData) (validate_utils.ReportData, error) {
	components, manyPolicyInput, err := validate_utils.CollectComponentResults(
		fallbackResults,
		func(r validate_utils.Result) error {
			return fmt.Errorf("error validating image %s of component %s: %w",
				r.Component.ContainerImage, r.Component.Name, r.Err)
		},
	)
	if err != nil {
		return validate_utils.ReportData{}, fmt.Errorf("failed to collect fallback components: %w", err)
	}

	return validate_utils.ReportData{
		Snapshot:      vsaData.images,
		Components:    components,
		Policy:        vsaData.fallbackContext.FallbackPolicy,
		PolicyInputs:  manyPolicyInput,
		Expansion:     nil,
		ShowSuccesses: false,
		ShowWarnings:  true,
	}, nil
}

// displayFallbackImageSection - Displays fallback validate image output using WriteReport
// Only displays to console if no output formats are specified (to avoid duplication with handleSnapshotOutput)
func displayFallbackImageSection(allData AllSectionsData, vsaData *validateVSAData, cmd *cobra.Command) error {
	// Only display to console if no output formats specified
	// If output formats are specified, handleSnapshotOutput will write to files
	if len(vsaData.output) > 0 {
		return nil
	}

	fmt.Println("=== FALLBACK: VALIDATE IMAGE ===")

	reportData, err := buildFallbackReportData(allData.FallbackResults, vsaData)
	if err != nil {
		return err
	}

	// Output options - empty Output means write to stdout
	outputOpts := validate_utils.ReportOutputOptions{
		Output:     []string{}, // Empty = stdout (via cmd.OutOrStdout())
		NoColor:    vsaData.noColor,
		ForceColor: vsaData.forceColor,
	}

	// WriteReport generates the verbatim validate image output
	_, err = validate_utils.WriteReport(reportData, outputOpts, cmd)
	return err
}

// displayComponentResults displays the validation results for each component
// Uses the new modular section-based approach
func displayComponentResults(allResults []vsa.ComponentResult, data *validateVSAData, cmd *cobra.Command) error {
	// Single aggregation pass - collect everything once
	allData := aggregateAllSectionsData(allResults)

	// Display sections in order (each is self-contained)
	displayHeaderSection(time.Now())
	fmt.Println()

	displayResultSection(allData)
	fmt.Println()

	displayVSASummarySection(allData)
	fmt.Println()

	// Conditional sections
	if allData.HasPolicyDiff {
		displayPolicyDiffSection(allData)
		fmt.Println()
	}

	if allData.FallbackUsed {
		if err := displayFallbackImageSection(allData, data, cmd); err != nil {
			return err
		}
		fmt.Println()
	}

	if allData.FallbackUsed {
		fmt.Println("=== Fallback Summary (validate image) ===")
	}

	return nil
}

// handleSnapshotOutput handles output formatting for snapshot validation
// When fallback components exist, it uses WriteReport (same format as validate image command)
// Otherwise, it uses the VSA report format to avoid conflicts
func handleSnapshotOutput(allResults []vsa.ComponentResult, data *validateVSAData, fs afero.Fs, cmd *cobra.Command) error {
	if len(data.output) == 0 {
		return nil
	}

	fallbackResults := collectFallbackResults(allResults)
	hasFallbackComponents := len(fallbackResults) > 0

	// If we have fallback components, use WriteReport for them (same format as validate image)
	// This ensures consistency between validate image and validate vsa fallback results
	if hasFallbackComponents && data.fallbackContext != nil {
		reportData, err := buildFallbackReportData(fallbackResults, data)
		if err != nil {
			return err
		}

		outputOpts := validate_utils.ReportOutputOptions{
			Output:     data.output,
			NoColor:    data.noColor,
			ForceColor: data.forceColor,
		}

		// Use WriteReport for fallback components - this writes in the same format as validate image
		_, err = validate_utils.WriteReport(reportData, outputOpts, cmd)
		if err != nil {
			return fmt.Errorf("failed to write fallback report: %w", err)
		}

		// Don't write VSA report when we have fallback components to avoid conflicts
		// The fallback results are what matter when fallback is used
		return nil
	}

	// No fallback components - use VSA report format
	report := createVSAReport(allResults)
	return writeOutputToFormats(report, data, fs)
}

// isFailureResult determines if a result represents a failure
func isFailureResult(result vsa.ComponentResult) bool {
	resultType := classifyResult(result)
	switch resultType {
	case ResultTypeError, ResultTypeVSAFailure, ResultTypeUnexpected:
		return true
	case ResultTypeFallback:
		return result.FallbackResult == nil || !result.FallbackResult.Component.Success
	default:
		return false
	}
}

// checkStrictMode checks if validation should fail based on strict mode
func checkStrictMode(allResults []vsa.ComponentResult, data *validateVSAData) error {
	if !data.strict {
		return nil
	}

	var failureCount int
	var allErrors error

	for _, result := range allResults {
		if isFailureResult(result) {
			failureCount++
			if result.Error != nil {
				allErrors = errors.Join(allErrors, result.Error)
			}
		}
	}

	if failureCount == 0 {
		return nil
	}

	if allErrors != nil {
		return fmt.Errorf("snapshot validation failed for %d components: %w", failureCount, allErrors)
	}
	return fmt.Errorf("snapshot validation failed for %d components", failureCount)
}

// validateImageFallbackWithWorkerContext performs image validation using worker-specific evaluators
// This ensures thread safety while reusing evaluators within the worker
func validateImageFallbackWithWorkerContext(ctx context.Context, data *validateVSAData, comp app.SnapshotComponent, workerFallbackContext *vsa.WorkerFallbackContext) (*output.Output, error) {
	log.Debugf("🔄 Starting fallback validation for image: %s", comp.ContainerImage)

	log.Debugf("🔄 Fallback: Using component name: %s", comp.Name)

	// Use precomputed fallback context and worker-specific evaluators
	if data.fallbackContext == nil {
		return nil, fmt.Errorf("fallback context not initialized - this should not happen")
	}

	if workerFallbackContext == nil {
		return nil, fmt.Errorf("worker fallback context not initialized - this should not happen")
	}

	if data.snapshot == nil {
		return nil, fmt.Errorf("snapshot spec not available - this should not happen")
	}

	log.Debugf("🔄 Fallback: Using precomputed policy configuration: %s", data.fallbackContext.PolicyConfiguration)
	log.Debugf("🔄 Fallback: Using worker evaluators: %d", len(workerFallbackContext.Evaluators))

	// Perform image validation using precomputed context and worker-specific evaluators
	log.Debugf("🔄 Fallback: Starting image validation...")
	log.Debugf("🔄 Fallback: Using fallback policy: %s", data.fallbackContext.FallbackPolicy)
	result, err := image.ValidateImage(ctx, comp, data.snapshot, data.fallbackContext.FallbackPolicy, workerFallbackContext.Evaluators, data.info)
	if err != nil {
		log.Debugf("🔄 Fallback: Image validation failed with error: %v", err)
		return nil, err
	}

	return result, nil
}

// processSnapshotComponentWithWorkerContext processes a single component using worker-specific fallback context
func processSnapshotComponentWithWorkerContext(ctx context.Context, component app.SnapshotComponent, data *validateVSAData, workerFallbackContext *vsa.WorkerFallbackContext) vsa.ComponentResult {
	// Extract digest from ContainerImage
	digest, err := vsa.ExtractDigestFromImageRef(component.ContainerImage)
	if err != nil {
		// Extract digest errors don't trigger fallback (invalid input)
		return createErrorResult(component, fmt.Errorf("failed to extract digest: %w", err))
	}

	// Perform VSA validation
	result, err := performVSAValidation(ctx, digest, data)

	// Create ValidationResult from error if needed (for proper display)
	if err != nil {
		// Create a ValidationResult from the error for proper display
		errorResult := createValidationResultFromError(err)

		// Check if fallback should be triggered BEFORE returning error
		if data.fallbackToImageValidation && shouldTriggerFallbackForComponent(err, errorResult) {
			return handleComponentFallback(ctx, component, data, errorResult, workerFallbackContext)
		}

		// Return error result with ValidationResult for proper display
		return vsa.ComponentResult{
			ComponentName: component.Name,
			ImageRef:      component.ContainerImage,
			Result:        errorResult,
			Error:         fmt.Errorf("VSA validation failed: %w", err),
		}
	}

	// Handle fallback if enabled and needed
	if data.fallbackToImageValidation && shouldTriggerFallbackForComponent(nil, result) {
		return handleComponentFallback(ctx, component, data, result, workerFallbackContext)
	}

	// Return VSA-only result
	return vsa.ComponentResult{
		ComponentName: component.Name,
		ImageRef:      component.ContainerImage,
		Result:        result,
		Error:         nil,
	}
}

// performVSAValidation performs VSA validation for a component
func performVSAValidation(ctx context.Context, digest string, data *validateVSAData) (*vsa.ValidationResult, error) {
	validationData := &vsa.VSAValidationConfig{
		Retriever:                   data.retriever,
		VSAExpiration:               data.vsaExpiration,
		IgnoreSignatureVerification: data.ignoreSignatureVerification,
		PublicKeyPath:               data.publicKeyPath,
		PolicySpec:                  data.policySpec,
		EffectiveTime:               data.effectiveTime,
	}

	return vsa.ValidateVSAAndComparePolicy(ctx, digest, validationData)
}

// shouldTriggerFallbackForComponent determines if fallback should be triggered for a component
func shouldTriggerFallbackForComponent(err error, result *vsa.ValidationResult) bool {
	if err != nil {
		return true
	}
	if result != nil && !result.Passed {
		return true
	}
	if result != nil && result.PredicateOutcome != "" && result.PredicateOutcome != "passed" {
		return true
	}
	return false
}

// handleComponentFallback handles fallback validation for a component
func handleComponentFallback(ctx context.Context, component app.SnapshotComponent, data *validateVSAData, result *vsa.ValidationResult, workerFallbackContext *vsa.WorkerFallbackContext) vsa.ComponentResult {
	predicateStatus := ""
	if result != nil {
		predicateStatus = result.PredicateOutcome
	}

	// Use the common fallback validation logic
	fallbackResult := vsa.PerformFallbackValidation(result, predicateStatus)
	if fallbackResult.Error != nil {
		return createErrorResult(component, fallbackResult.Error)
	}

	// Perform image validation
	fallbackOutput, fallbackErr := validateImageFallbackWithWorkerContext(ctx, data, component, workerFallbackContext)
	if fallbackErr != nil {
		return createErrorResult(component, fmt.Errorf("fallback image validation failed: %w", fallbackErr))
	}

	// Set the fallback output
	fallbackResult.FallbackOutput = fallbackOutput

	// Create validate_utils.Result for fallback (same as validate image command)
	// Use defaults for showSuccesses and outputFormats to match validate image behavior
	// Note: VSA command doesn't have these flags, so we use defaults (showSuccesses=false, empty outputFormats)
	fallbackValidationResult := validate_utils.PopulateResultFromOutput(
		fallbackOutput,
		nil, // err is nil here since we already checked it above
		component,
		false,       // showSuccesses - default to false if not specified
		data.output, // outputFormats - use the same as VSA command output
	)

	return vsa.ComponentResult{
		ComponentName:  component.Name,
		ImageRef:       component.ContainerImage,
		Result:         result, // Keep original VSA result for VSA display
		Error:          nil,
		FallbackResult: &fallbackValidationResult, // Store fallback result for WriteReport compatibility
	}
}

// createErrorResult creates a ComponentResult with an error
func createErrorResult(component app.SnapshotComponent, err error) vsa.ComponentResult {
	// Create ValidationResult from error for proper display
	errorResult := createValidationResultFromError(err)
	return vsa.ComponentResult{
		ComponentName: component.Name,
		ImageRef:      component.ContainerImage,
		Result:        errorResult,
		Error:         err,
	}
}

// createValidationResultFromError creates a ValidationResult from an error
// This ensures proper display of VSA status even when validation fails
func createValidationResultFromError(err error) *vsa.ValidationResult {
	if err == nil {
		return nil
	}

	// Determine reason code from error message
	reasonCode := "retrieval_failed"
	errMsg := err.Error()

	// Check for specific error types
	if strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "exceeded allowed execution time") {
		reasonCode = "retrieval_failed"
	} else if strings.Contains(errMsg, "no entries found") || strings.Contains(errMsg, "not found") {
		reasonCode = "no_vsa"
	} else if strings.Contains(errMsg, "signature") {
		reasonCode = "retrieval_failed"
	}

	return &vsa.ValidationResult{
		Passed:            false,
		Message:           errMsg,
		SignatureVerified: false, // When retrieval fails, signature cannot be verified
		PredicateOutcome:  "",
		ReasonCode:        reasonCode,
	}
}

// OutputFormatter defines the interface for objects that can be formatted for output
type OutputFormatter interface {
	PrintJSON(writer io.Writer) error
	PrintText(writer io.Writer) error
}

// VSAReport represents the output structure for VSA validation results
type VSAReport struct {
	Timestamp      string                `json:"timestamp"`
	TotalResults   int                   `json:"total_results"`
	SuccessCount   int                   `json:"success_count"`
	FailureCount   int                   `json:"failure_count"`
	FallbackCount  int                   `json:"fallback_count,omitempty"`
	Results        []vsa.ComponentResult `json:"results"`
	OverallSuccess bool                  `json:"overall_success"`
}

// PrintJSON outputs the report in JSON format
func (r *VSAReport) PrintJSON(writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

// PrintText outputs the report in text format
func (r *VSAReport) PrintText(writer io.Writer) error {
	fmt.Fprintf(writer, "VSA Validation Report\n")
	fmt.Fprintf(writer, "====================\n")
	fmt.Fprintf(writer, "Timestamp: %s\n", r.Timestamp)
	fmt.Fprintf(writer, "Total Results: %d\n", r.TotalResults)
	fmt.Fprintf(writer, "Successful: %d\n", r.SuccessCount)
	fmt.Fprintf(writer, "Failed: %d\n", r.FailureCount)
	if r.FallbackCount > 0 {
		fmt.Fprintf(writer, "Used Fallback: %d\n", r.FallbackCount)
	}
	fmt.Fprintf(writer, "Overall Success: %t\n", r.OverallSuccess)
	fmt.Fprintf(writer, "\nDetailed Results:\n")

	for _, result := range r.Results {
		fmt.Fprintf(writer, "\nComponent: %s\n", result.ComponentName)
		fmt.Fprintf(writer, "  Image: %s\n", result.ImageRef)

		if result.Error != nil {
			fmt.Fprintf(writer, "  Error: %v\n", result.Error)
			continue
		}

		if result.FallbackResult != nil {
			fmt.Fprintf(writer, "  Fallback used\n")
			if result.FallbackResult.Component.Success {
				fmt.Fprintf(writer, "  Fallback succeeded\n")
			} else {
				fmt.Fprintf(writer, "  Fallback failed\n")
			}
			continue
		}

		if result.Result != nil {
			if result.Result.Passed {
				fmt.Fprintf(writer, "  VSA validation passed\n")
			} else {
				fmt.Fprintf(writer, "  VSA validation failed: %s\n", result.Result.Message)
			}
		}
	}

	return nil
}

// writeOutputToFormats writes the given formatter to all specified output formats
func writeOutputToFormats(formatter OutputFormatter, data *validateVSAData, fs afero.Fs) error {
	// Output to all specified formats
	for _, outputSpec := range data.output {
		parts := strings.SplitN(outputSpec, "=", 2)
		format := parts[0]
		file := ""
		if len(parts) > 1 {
			file = parts[1]
		}

		var writer io.Writer = os.Stdout
		if file != "" {
			f, err := fs.Create(file)
			if err != nil {
				return fmt.Errorf("failed to create output file %s: %w", file, err)
			}
			defer f.Close()
			writer = f
		}

		switch format {
		case "json":
			err := formatter.PrintJSON(writer)
			if err != nil {
				return fmt.Errorf("failed to output JSON: %w", err)
			}
		case "text", "console":
			err := formatter.PrintText(writer)
			if err != nil {
				return fmt.Errorf("failed to output text: %w", err)
			}
		default:
			return fmt.Errorf("unsupported output format: %s", format)
		}
	}

	return nil
}

// createVSAReport creates a report structure from VSA validation results
func createVSAReport(results []vsa.ComponentResult) *VSAReport {
	successCount := 0
	failureCount := 0
	fallbackCount := 0

	for _, result := range results {
		if result.Error != nil {
			failureCount++
			continue
		}

		if result.FallbackResult != nil {
			fallbackCount++
			if result.FallbackResult.Component.Success {
				successCount++
			} else {
				failureCount++
			}
			continue
		}

		if result.Result != nil {
			if result.Result.Passed {
				successCount++
			} else {
				failureCount++
			}
		}
	}

	return &VSAReport{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		TotalResults:   len(results),
		SuccessCount:   successCount,
		FailureCount:   failureCount,
		FallbackCount:  fallbackCount,
		Results:        results,
		OverallSuccess: failureCount == 0,
	}
}

// ResultType represents the classification of a component validation result
type ResultType int

const (
	ResultTypeError ResultType = iota
	ResultTypeFallback
	ResultTypeVSASuccess
	ResultTypeVSAFailure
	ResultTypeUnexpected
)

// classifyResult determines the type of a component validation result
func classifyResult(result vsa.ComponentResult) ResultType {
	if result.Error != nil {
		return ResultTypeError
	}
	if result.FallbackResult != nil {
		return ResultTypeFallback
	}
	if result.Result != nil && result.Result.Passed {
		return ResultTypeVSASuccess
	}
	if result.Result != nil && !result.Result.Passed {
		return ResultTypeVSAFailure
	}
	return ResultTypeUnexpected
}
