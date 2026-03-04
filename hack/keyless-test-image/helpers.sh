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

set -euo pipefail

# Output a fancy heading
function h1() {
  local text="$1"
  local line=$(sed 's/./─/g' <<< "$text")
  echo "╭─$line─╮"
  echo "┝ $text ┥"
  echo "╰─$line─╯"
}

# Output some text and wait for the user to press enter
function pause() {
  local default_msg="Press Enter to continue..."
  local msg="${1:-$default_msg}"

  nl
  read -p "$msg"
  nl
}

# Output a line break
function nl() {
  printf "\n"
}
