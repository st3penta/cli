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

// Package vsa provides step definitions for VSA (Verification Summary Attestation) functionality testing
package vsa

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cucumber/godog"

	"github.com/conforma/cli/acceptance/cli"
	"github.com/conforma/cli/acceptance/log"
)

// vsaEnvelopeFilesShouldExist checks that VSA envelope files exist in the specified directory
func vsaEnvelopeFilesShouldExist(ctx context.Context, directory string) (context.Context, error) {
	logger, _ := log.LoggerFor(ctx)

	// Get command status to access variables for expansion
	status, err := cli.EcStatusFrom(ctx)
	if err != nil {
		return ctx, err
	}

	// Expand variables in the directory path using the vars map
	expandedDir := os.Expand(directory, func(key string) string {
		if value, ok := status.Vars()[key]; ok {
			return value
		}
		return ""
	})

	logger.Infof("Checking for VSA envelope files in directory: %s", expandedDir)

	// Check if directory exists
	if _, err := os.Stat(expandedDir); os.IsNotExist(err) {
		return ctx, fmt.Errorf("VSA output directory does not exist: %s", expandedDir)
	}

	// Look for VSA envelope files (should have .json extension and vsa- prefix)
	files, err := filepath.Glob(filepath.Join(expandedDir, "vsa-*.json"))
	if err != nil {
		return ctx, fmt.Errorf("error searching for VSA envelope files: %v", err)
	}

	if len(files) == 0 {
		return ctx, fmt.Errorf("no VSA envelope files found in directory: %s", expandedDir)
	}

	for _, file := range files {
		logger.Infof("Found VSA envelope file: %s", file)
	}

	logger.Infof("Successfully found VSA envelope files in: %s", expandedDir)

	return ctx, nil
}

// AddStepsTo adds VSA-related step definitions to the godog ScenarioContext
func AddStepsTo(ctx *godog.ScenarioContext) {
	ctx.Step(`^VSA envelope files should exist in "([^"]*)"$`, vsaEnvelopeFilesShouldExist)
}
