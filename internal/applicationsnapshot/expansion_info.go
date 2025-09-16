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

package applicationsnapshot

import "sync"

// ExpansionInfo tracks the relationships between image indexes and their child manifests
// that are created when expanding multi-arch images.
type ExpansionInfo struct {
	// childrenByIndex maps an image index digest to the list of child manifest digests
	childrenByIndex map[string][]string
	// parentByChild maps a child manifest digest to its parent index digest
	parentByChild map[string]string
	// indexAliases maps image references to their pinned digest form
	indexAliases map[string]string
	// mu protects concurrent access to the maps
	mu sync.RWMutex
}

// NewExpansionInfo creates a new ExpansionInfo instance
func NewExpansionInfo() *ExpansionInfo {
	return &ExpansionInfo{
		childrenByIndex: make(map[string][]string),
		parentByChild:   make(map[string]string),
		indexAliases:    make(map[string]string),
	}
}

// SetIndexAlias safely sets an index alias
func (e *ExpansionInfo) SetIndexAlias(key, value string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.indexAliases[key] = value
}

// AddChildToIndex safely adds a child to the index
func (e *ExpansionInfo) AddChildToIndex(index, child string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.childrenByIndex[index] = append(e.childrenByIndex[index], child)
}

// SetParentByChild safely sets the parent for a child
func (e *ExpansionInfo) SetParentByChild(child, parent string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.parentByChild[child] = parent
}

// GetIndexAlias safely gets an index alias
func (e *ExpansionInfo) GetIndexAlias(key string) (string, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	value, ok := e.indexAliases[key]
	return value, ok
}

// GetChildrenByIndex safely gets children for an index
// Caller gets own slice to avoid race conditions
// Example:
//
//	go func() {
//	    e.AddChildToIndex("index1", "child3") // holds lock while writing
//	}()
//
// children, _ := e.GetChildrenByIndex("index1") // holds lock while reading
// children = append(children, "child4")        // modifies underlying slice WITHOUT lock
func (e *ExpansionInfo) GetChildrenByIndex(index string) ([]string, bool) {
	e.mu.RLock()
	children, ok := e.childrenByIndex[index]
	if !ok {
		e.mu.RUnlock()
		return nil, false
	}
	// Copy so caller gets their own slice
	copyChildren := make([]string, len(children))
	copy(copyChildren, children)
	e.mu.RUnlock()
	return copyChildren, true
}

// GetParentByChild safely gets the parent for a child
func (e *ExpansionInfo) GetParentByChild(child string) (string, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	parent, ok := e.parentByChild[child]
	return parent, ok
}
