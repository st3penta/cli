Feature: VSA generation and storage
  The ec command line should generate and store Verification Summary Attestation (VSA)

  Background:
    Given a stub cluster running
    Given stub rekord running
    Given stub registry running
    Given stub git daemon running
    Given stub tuf running

  Scenario: VSA generation with local storage backend
    Given a key pair named "vsa-test"
    Given an image named "acceptance/vsa-test-image"
    Given a valid image signature of "acceptance/vsa-test-image" image signed by the "vsa-test" key
    Given a valid Rekor entry for image signature of "acceptance/vsa-test-image"
    Given a valid attestation of "acceptance/vsa-test-image" signed by the "vsa-test" key
    Given a valid Rekor entry for attestation of "acceptance/vsa-test-image"
    Given a git repository named "vsa-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "vsa-ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/vsa-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/vsa-test-image --policy acceptance/vsa-ec-policy --public-key ${vsa-test_PUBLIC_KEY} --rekor-url ${REKOR} --vsa --vsa-signing-key ${vsa-test_PRIVATE_KEY} --vsa-upload local@${TMPDIR}/vsa-output --output json"
    Then the exit status should be 0
    Then the output should match the snapshot
    And VSA envelope files should exist in "${TMPDIR}/vsa-output"

  Scenario: VSA generation with Rekor storage backend
    Given a key pair named "vsa-rekor"
    Given an image named "acceptance/vsa-rekor-image"
    Given a valid image signature of "acceptance/vsa-rekor-image" image signed by the "vsa-rekor" key
    Given a valid Rekor entry for image signature of "acceptance/vsa-rekor-image"
    Given a valid attestation of "acceptance/vsa-rekor-image" signed by the "vsa-rekor" key
    Given a valid Rekor entry for attestation of "acceptance/vsa-rekor-image"
    Given a git repository named "vsa-rekor-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "vsa-rekor-ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/vsa-rekor-policy.git"
          ]
        }
      ]
    }
    """
    Given VSA upload to Rekor should be expected
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/vsa-rekor-image --policy acceptance/vsa-rekor-ec-policy --public-key ${vsa-rekor_PUBLIC_KEY} --rekor-url ${REKOR} --vsa --vsa-signing-key ${vsa-rekor_PRIVATE_KEY} --vsa-upload rekor@${REKOR} --output json"
    Then the exit status should be 0
    Then the output should match the snapshot
    And VSA should be uploaded to Rekor successfully

  Scenario: VSA generation with multiple storage backends
    Given a key pair named "vsa-multi"
    Given an image named "acceptance/vsa-multi-image"
    Given a valid image signature of "acceptance/vsa-multi-image" image signed by the "vsa-multi" key
    Given a valid Rekor entry for image signature of "acceptance/vsa-multi-image"
    Given a valid attestation of "acceptance/vsa-multi-image" signed by the "vsa-multi" key
    Given a valid Rekor entry for attestation of "acceptance/vsa-multi-image"
    Given a git repository named "vsa-multi-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "vsa-multi-ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/vsa-multi-policy.git"
          ]
        }
      ]
    }
    """
    Given VSA upload to Rekor should be expected
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/vsa-multi-image --policy acceptance/vsa-multi-ec-policy --public-key ${vsa-multi_PUBLIC_KEY} --rekor-url ${REKOR} --vsa --vsa-signing-key ${vsa-multi_PRIVATE_KEY} --vsa-upload local@${TMPDIR}/vsa-multi-output --vsa-upload rekor@${REKOR} --output json"
    Then the exit status should be 0
    Then the output should match the snapshot
    And VSA envelope files should exist in "${TMPDIR}/vsa-multi-output"
    And VSA should be uploaded to Rekor successfully

  Scenario: VSA generation with invalid storage backend configuration
    Given a key pair named "vsa-invalid"
    Given an image named "acceptance/vsa-invalid-image"
    Given a valid image signature of "acceptance/vsa-invalid-image" image signed by the "vsa-invalid" key
    Given a valid Rekor entry for image signature of "acceptance/vsa-invalid-image"
    Given a valid attestation of "acceptance/vsa-invalid-image" signed by the "vsa-invalid" key
    Given a valid Rekor entry for attestation of "acceptance/vsa-invalid-image"
    Given a git repository named "vsa-invalid-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "vsa-invalid-ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/vsa-invalid-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/vsa-invalid-image --policy acceptance/vsa-invalid-ec-policy --public-key ${vsa-invalid_PUBLIC_KEY} --rekor-url ${REKOR} --vsa --vsa-signing-key ${vsa-invalid_PRIVATE_KEY} --vsa-upload invalid-backend@somewhere --output json"
    Then the exit status should be 0
    Then the output should match the snapshot
