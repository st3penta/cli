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
	"github.com/spf13/cobra"
)

var RetrieveCmd *cobra.Command

func init() {
	RetrieveCmd = NewRetrieveCmd()
	RetrieveCmd.AddCommand(retrieveVSACmd())
}

func NewRetrieveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "retrieve",
		Short: "Retrieve various types of data and entries",
		Long: `Retrieve various types of data and entries from different sources.

This command provides subcommands for retrieving different types of data,
such as VSA entries from Rekor, attestations, and other verification data.`,
	}
}
