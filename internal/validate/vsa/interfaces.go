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

	"github.com/conforma/cli/internal/applicationsnapshot"
)

// PredicateGenerator interface for generating VSA predicates
type PredicateGenerator interface {
	GeneratePredicate(ctx context.Context, comp applicationsnapshot.Component) (*Predicate, error)
}

// PredicateWriter interface for writing VSA predicates to files
type PredicateWriter interface {
	WritePredicate(pred *Predicate) (string, error)
}

// PredicateAttestor interface for attesting VSA predicates and writing envelopes
type PredicateAttestor interface {
	AttestPredicate(ctx context.Context) ([]byte, error)
	WriteEnvelope(data []byte) (string, error)
}
