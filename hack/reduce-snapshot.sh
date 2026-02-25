#!/usr/bin/env bash
# Copyright The Conforma Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script attempts to reduce a snapshot to a single component.
# It determines the component via a custom resource's labels.
# It requires that the following environment variables be defined:
#
# - SINGLE_COMPONENT: true if single component mode is enabled.
# - SNAPSHOT: Path to a Snapshot JSON file, or the name of a Snapshot custom
#   resource. If a valid CR name (DNS label, ≤63 chars), the Snapshot is
#   fetched from the cluster using the current kubectl context namespace (no
#   -n flag). This is intentional: in Tekton the task runs in the pipeline
#   namespace; locally the context targets the user's workspace.
# - CUSTOM_RESOURCE: Custom resource kind used for label lookup (single-component).
# - CUSTOM_RESOURCE_NAMESPACE: Namespace used for label lookup only; not used
#   when fetching the Snapshot by name (context namespace is used for that).
# - SNAPSHOT_PATH: Where the reduced Snapshot will be stored.

set -o errexit
set -o nounset
set -o pipefail


# Make sure to move snapshot contents to the WORKING_SNAPSHOT location. Then allow jq to
# work with it there. This avoids having to read SNAPSHOT to memory.
# Always use a temp file for WORKING_SNAPSHOT to avoid truncation issues when writing
# the final output to SNAPSHOT_PATH (which may be the same file as SNAPSHOT).

WORKING_SNAPSHOT="$(mktemp /tmp/snapshot.XXXXXX)"
# Kubernetes resource names: DNS label, max 63 chars, [a-z0-9]([-a-z0-9]*[a-z0-9])?
VALID_CR_NAME_PATTERN='^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
if [[ -f "$SNAPSHOT" ]]; then
  cp "$SNAPSHOT" "$WORKING_SNAPSHOT"
elif [[ ${#SNAPSHOT} -le 63 && "$SNAPSHOT" =~ $VALID_CR_NAME_PATTERN ]]; then
  # Fetch Snapshot using current kubectl context namespace only (no -n).
  # Intentional: Tekton runs in pipeline namespace; local dev uses workspace context.
  kubectl get snapshot/"${SNAPSHOT}" -o json | jq .spec > "$WORKING_SNAPSHOT" || \
    { echo "Failed to get Snapshot: $SNAPSHOT"; exit 1; }
else
  printf "%s" "$SNAPSHOT" > "$WORKING_SNAPSHOT"
fi

jq empty "$WORKING_SNAPSHOT" || { echo "JSON is invalid"; exit 1; }

echo "Single Component mode? ${SINGLE_COMPONENT}"
if [ "${SINGLE_COMPONENT}" == "true" ]; then

  CR_NAMESPACE_ARG=
  if [ "${CUSTOM_RESOURCE_NAMESPACE}" != "" ]; then
    CR_NAMESPACE_ARG="-n ${CUSTOM_RESOURCE_NAMESPACE}"
  fi

  SNAPSHOT_CREATION_TYPE=$(kubectl get "$CUSTOM_RESOURCE" ${CR_NAMESPACE_ARG:+$CR_NAMESPACE_ARG} -ojson \
      | jq -r '.metadata.labels."test.appstudio.openshift.io/type" // ""')
  SNAPSHOT_CREATION_COMPONENT=$(kubectl get "$CUSTOM_RESOURCE" ${CR_NAMESPACE_ARG:+$CR_NAMESPACE_ARG} -ojson \
      | jq -r '.metadata.labels."appstudio.openshift.io/component" // ""')

  echo "SNAPSHOT_CREATION_TYPE: ${SNAPSHOT_CREATION_TYPE}"
  echo "SNAPSHOT_CREATION_COMPONENT: ${SNAPSHOT_CREATION_COMPONENT}"
  if [ "${SNAPSHOT_CREATION_TYPE}" == "component" ] && [ "${SNAPSHOT_CREATION_COMPONENT}" != "" ]; then
    echo "Single Component mode is ${SINGLE_COMPONENT} and Snapshot type is component"

    REDUCED_SNAPSHOT="$(mktemp /tmp/snapshot_reduced.XXXXXX)"
    jq --arg component "${SNAPSHOT_CREATION_COMPONENT}" \
    'del(.components[] | select(.name != $component))' "$WORKING_SNAPSHOT" > "$REDUCED_SNAPSHOT"

    COMPONENT_COUNT=$(jq -r '[ .components[] ] | length' "$REDUCED_SNAPSHOT")
    if [ "${COMPONENT_COUNT}" == "1" ]; then
      mv "$REDUCED_SNAPSHOT" "$WORKING_SNAPSHOT"
    else
      echo "Error: Reduced Snapshot has ${COMPONENT_COUNT} components. It should contain 1"
      echo "       Verify that the Snapshot contains the built component: ${SNAPSHOT_CREATION_COMPONENT}"
      echo "Using original Snapshot"
      exit 1
    fi

  fi
fi

# we need to create snapshot file to be passed to later stages.
jq '.' "${WORKING_SNAPSHOT}" | tee "${SNAPSHOT_PATH}"
