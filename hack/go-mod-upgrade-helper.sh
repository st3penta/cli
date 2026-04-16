#!/usr/bin/env bash
# Copyright The Conforma Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

PKG="$1"
JIRA="${2:-""}"

MOD_DIRS=$(git ls-files | grep go.mod$ | xargs -n1 dirname)

# Uncomment this if you want to skip tools/kubectl
#MOD_DIRS=$(git ls-files | grep go.mod$ | xargs -n1 dirname | grep -v kubectl)

# Update module
# (If the module is not actually used, the go mod tidy should
# remove it so we can be lazy about deciding which mod files to
# update and just update them all.)
for d in $MOD_DIRS; do ( cd "$d" && go get "$PKG" && go mod tidy ); done

# Prepare commit
for d in $MOD_DIRS; do ( cd "$d" && git add go.mod go.sum ); done

JIRA_REF_OPT=()
if [ -n "$JIRA" ]; then
  JIRA_REF_OPT=(-m "Ref: https://redhat.atlassian.net/browse/$JIRA")
fi

# Make commit
# (The --no-gpg-sign is to make it easier for agents.
# If you do a rebase you'll get them all signed.)
git commit --no-gpg-sign -m"chore(deps): Update $1" "${JIRA_REF_OPT[@]}"
