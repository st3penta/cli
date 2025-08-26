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

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ $CURRENT_BRANCH != "main" ]]; then
  read -r -p "Not in main branch. Continue anyway? [y/N] " ans
  [[ "$ans" != "y" ]] && exit 1
fi

VERSION="$(cat VERSION)"

RELEASE_NAME="v$VERSION"
if [[ $RELEASE_NAME != *.* || $RELEASE_NAME == *.*.* ]]; then
  echo "Release name should include one dot, e.g. v0.5 or v1.1-candidate"
  exit 1
fi

# Use release name as-is for the branch name
BRANCH_NAME="release-${RELEASE_NAME}"

# Konflux disallows . chars in names so remove those
KONFLUX_APPLICATION_SUFFIX="${RELEASE_NAME/./}"

KONFLUX_APPLICATION_NAME=ec-${KONFLUX_APPLICATION_SUFFIX}
KONFLUX_CLI_COMPONENT_NAME=cli-${KONFLUX_APPLICATION_SUFFIX}

# Show some useful values
echo Release name: $RELEASE_NAME
echo Release branch name: $BRANCH_NAME
echo Konflux application name: $KONFLUX_APPLICATION_NAME
echo Konflux cli component name: $KONFLUX_CLI_COMPONENT_NAME

OLD_VERSION="0.$((${VERSION#*.} - 1))"
OLD_RELEASE_NAME="v$OLD_VERSION"
OLD_KONFLUX_APPLICATION_SUFFIX="${OLD_RELEASE_NAME/./}"
OLD_KONFLUX_APPLICATION_NAME=ec-${OLD_KONFLUX_APPLICATION_SUFFIX}

KONFLUX_URL_PREFIX=https://konflux-ui.apps.stone-prd-rh01.pg1f.p1.openshiftapps.com/ns/rhtap-contract-tenant

nice_title() {
  echo -e "\033[1m» $*\033[0m"
}

# Explain what needs to be done next
# This is like slightly interactive documentation.
# (We could make this more automated in future.)
cat <<EOT1
Next steps:

$(nice_title Create new release branch)

git fetch upstream
git push upstream refs/remotes/upstream/main:refs/heads/${BRANCH_NAME}
git checkout -b ${BRANCH_NAME} upstream/${BRANCH_NAME}

$(nice_title Bump version in main branch)

Run 'make bump-minor-version' in main branch and make a PR for that.

$(nice_title Create a PR in konflux-release-data)

This repo: https://gitlab.cee.redhat.com/releng/konflux-release-data/
This directory: tenants-config/cluster/stone-prd-rh01/tenants/rhtap-contract-tenant/

Copy overlays/${OLD_KONFLUX_APPLICATION_NAME} to overlays/${KONFLUX_APPLICATION_NAME}

Edit overlays/${KONFLUX_APPLICATION_NAME}/kustomization.yaml as required.
Useful vimdiff command:
  vimdiff overlays/${OLD_KONFLUX_APPLICATION_NAME}/kustomization.yaml overlays/${KONFLUX_APPLICATION_NAME}/kustomization.yaml

Update kustomization.yaml to add the extra row.

Run 'tenants-config/build-single.sh rhtap-contract' in that repo and git add all the changes.

Modify this file:
  config/stone-prd-rh01.pg1f.p1/product/ReleasePlanAdmission/rhtap-contract/ec-cli.yaml

Add the new release under '/spec/applications' and '/spec/data/mapping/components'.
Move the 'latest' tag so it's associated with the new component.

Create a PR with all these changes.

Example PR (but with a bad typo):
  https://gitlab.cee.redhat.com/releng/konflux-release-data/-/merge_requests/9592

$(nice_title Create Konflux pipeline definitions in the new release branch)

Check out the new release branch of the cli repo and run this script:
  hack/release-branch-pipeline-patch.sh

Use the recommended vimdiff commands to examine the diffs and make sure they look right.

Remove the main branch pipelines and make a PR.

Example PR:
  https://github.com/conforma/cli/pull/2702

Note: Konflux will also generate a PR with the default pipeline definition. Since we made the
piplines ourselves, this generated PR should be abandoned. You may wish to diff-compare the pipelines
in the generated PR with the ones you created. (You should be able to see the pipeline customizations
present in our pipelines but not present in the Konflux generated PR with the default pipelines.)

EOT1

cat <<EOT2
$(nice_title Confirming it\'s working)

Make sure builds are green in the new release branch, and sure they're passing Conforma policy:
  ${KONFLUX_URL_PREFIX}/applications/${KONFLUX_APPLICATION_NAME}/activity/pipelineruns

Check that a new release appeared in the releases tab:
  ${KONFLUX_URL_PREFIX}/applications/${KONFLUX_APPLICATION_NAME}/releases
(Note that viewing the release pipeline itself (see the Managed Pipeline column) requires permissions in the rhtap-releng workspace.)

Check that images are released. Try (one of more) of the following:
- Look at https://catalog.redhat.com/software/containers/rhtas/ec-rhel9/65f1f9dcfc649a18c6075de5 .
- Use show-latest-build-versions.sh script in the hacks repo.
- Use skopeo, e.g. 'skopeo inspect --no-tags docker://registry.redhat.io/rhtas/ec-rhel9:${VERSION} | jq'
- Use podman, e.g. 'podman run --rm registry.redhat.io/rhtas/ec-rhel9:${VERSION} version'

$(nice_title Create stable versioned branch in policy repo and corresponding config in the config repo)

For better or for worse, we create a branch in the policy repo and two config file that RHADS-SSC (formerly
RHTAP) templates can use. This may change in future if https://issues.redhat.com/browse/RHTAP-4805 is adopted.

For example (in policy repo):
  git push upstream upstream/main:refs/heads/release-${RELEASE_NAME}
You have some flexibility around what sha to use, but the current upstream/main is probably good choice.

The config PR should add one more of each of these for ${RELEASE_NAME}:
- https://github.com/conforma/config/blob/2134fcd12cdf41dc3ab65cb0ee2660cd6f983df6/src/data.yaml#L12-L22
- https://github.com/conforma/config/blob/2134fcd12cdf41dc3ab65cb0ee2660cd6f983df6/src/data.yaml#L98-L111

Don't forget to do 'make refresh' and check in the changes.
When it's merged we should see new config files at:
- https://github.com/conforma/config/blob/main/tekton-slsa3-${RELEASE_NAME}/policy.yaml
- https://github.com/conforma/config/blob/main/rhtap-${RELEASE_NAME}/policy.yaml

Deciding when to update the tssc-sample-pipelines repo is up to the RHTAP developers and may depend on their release
schedule and the release schedule of RHTAS. Here are some of the places affected IIUC:
- https://github.com/redhat-appstudio/tssc-sample-pipelines/blob/d1a4f07a34977fbf152acd94a8ef338ef7d5bbdc/hack/patches/pipelines/gitops-pull-request/patch.yaml#L9
- https://github.com/redhat-appstudio/tssc-sample-pipelines/blob/d1a4f07a34977fbf152acd94a8ef338ef7d5bbdc/pac/pipelines/gitops-pull-request-rhtap.yaml#L18
- https://github.com/redhat-appstudio/tssc-dev-multi-ci/blob/1f60115ab53d541c34c13329288b1bd23dcb4d46/rhtap/env.template.sh#L42

(Sync with RHTAP and RHTAS folks via slack or at their program call to let them know about the new version, and to
understand their plans and release schedules.)

$(nice_title File a story to get the release notes created)

The description should link to the instructions at:
https://docs.google.com/document/d/18vyZbcLQB81KW2EJeRryYh4OCvB6X8D4GK1qAYalTbo/edit

Previous example Jiras (you could clone one of these if you like):
- https://issues.redhat.com/browse/EC-1450
- https://issues.redhat.com/browse/EC-1173

$(nice_title Bump the ref in the RHTAS repo)

See https://github.com/securesign/cosign/blob/a91133b0091ebcec6b20e527dcad9e21106e995e/Dockerfile.clients.rh#L10

Update the ref and create a PR in main branch.

Note that Renovate/MintMaker PRs can and do keep this digest updated, but I don't think they will change the tag from ${OLD_VERSION} to ${VERSION}.
Either way there's no harm in creating a human authored PR for this update, linked to the relevant Jira.

(I generally also post a thread on on #team-trusted-artifact-signer on slack to mention that the PR exists and that the new version of Conforma
is now available for testing.)

EOT2
