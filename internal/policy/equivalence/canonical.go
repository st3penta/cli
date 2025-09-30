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

package equivalence

import (
	"bytes"
	"encoding/json"
	"sort"
)

// marshalCanonical creates deterministic JSON by sorting map keys at every level
func marshalCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// encodeCanonical recursively encodes JSON with sorted keys for deterministic output
func encodeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case map[string]any:
		// Sort keys to ensure deterministic output
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			// Encode key (always a string, so use standard JSON encoding)
			keyBytes, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(keyBytes)
			buf.WriteByte(':')
			// Recursively encode value
			if err := encodeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		// For scalars (numbers, strings, bool, null), use standard JSON encoding
		b, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	return nil
}
