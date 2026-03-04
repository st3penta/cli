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

source "$(dirname ${BASH_SOURCE[0]})/helpers.sh"

# This script creates two keylessly signed images that we use in our acceptance
# tests. One created with cosign v2 and one with cosign v3 using the newer
# sigstore bundle and OCI referrers

# Prereqs if you want to recreate these images:
# - A working push credential for quay.io/conforma/test
# - The ability to authenticate as the "conformacommunity@gmail.com" Google account

# Note: Ideally we would not rely on external images in the tests, but this is
# the quickest way to get some meaningful acceptance tests for the keyless
# image verification in the Tekton task. Also, we already have some other
# external images used in the tests, so I figure adding one more isn't such a
# big deal.

REPO=quay.io/conforma/test

# Todo: Maybe we can we specify these explicitly when signing
# CERT_IDENITY="conformacommunity@gmail.com"
# CERT_OIDC_ISSUER="https://accounts.google.com"

# Todo maybe: Pin the versions of cosign, (perhaps with a go.mod file?) instead
# of using @latest.

for ver in v2 v3; do
  LABEL="keyless_$ver"
  COSIGN="go run github.com/sigstore/cosign/$ver/cmd/cosign@latest"
  GIT_VER=$($COSIGN version --json | jq -r .gitVersion)
  DATE_STR=$(date)


  h1 "Creating image ($ver)"
  podman build -t "$REPO:$LABEL" -f - . <<EOF
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest
RUN echo "hello from the conforma cosign $GIT_VER keyless signing test image built on $DATE_STR" > /hello.txt
CMD ["cat", "/hello.txt"]
EOF

  h1 "Pushing image ($ver)"
  podman push "$REPO:$LABEL"

  h1 "Signing image ($ver)"
  # Use the digest otherwise cosign complains
  DIGEST=$(skopeo inspect "docker://quay.io/conforma/test:keyless_$ver" | jq -r .Digest)
  $COSIGN sign -y "$REPO@$DIGEST"

  h1 "Creating a signed attestation ($ver)"
  # Push a minimal attestation
  $COSIGN attest -y \
    --predicate - \
    --type "https://slsa.dev/provenance/v1" \
    $REPO@$DIGEST <<EOF
{
  "buildDefinition": {
    "buildType": "https://example.com/build-type/v1",
    "externalParameters": {},
    "internalParameters": {},
    "resolvedDependencies": []
  },
  "runDetails": {
    "builder": {
      "id": "https://example.com/builder"
    },
    "metadata": {}
  }
}
EOF

done
