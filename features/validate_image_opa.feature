Feature: evaluate enterprise contract with OPA evaluator
  The ec command line should produce correct results using the OPA evaluator

  Background:
    Given the environment variable is set "EC_USE_OPA=1"
    Given a stub cluster running
    Given stub rekord running
    Given stub registry running
    Given stub git daemon running
    Given stub tuf running

  Scenario: OPA happy day
    Given a key pair named "known"
    Given an image named "acceptance/opa-happy-day"
    Given a valid image signature of "acceptance/opa-happy-day" image signed by the "known" key
    Given a valid attestation of "acceptance/opa-happy-day" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | main.rego | examples/happy_day.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/opa-happy-day --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: OPA rejection
    Given a key pair named "known"
    Given an image named "acceptance/opa-reject"
    Given a valid image signature of "acceptance/opa-reject" image signed by the "known" key
    Given a valid attestation of "acceptance/opa-reject" signed by the "known" key
    Given a git repository named "reject-policy" with
      | main.rego | examples/reject.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/reject-policy.git"
          ]
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/opa-reject --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: OPA multiple policy sources
    Given a key pair named "known"
    Given an image named "acceptance/opa-multiple-sources"
    Given a valid image signature of "acceptance/opa-multiple-sources" image signed by the "known" key
    Given a valid attestation of "acceptance/opa-multiple-sources" signed by the "known" key
    Given a git repository named "repository1" with
      | main.rego | examples/happy_day.rego |
    Given a git repository named "repository2" with
      | main.rego | examples/reject.rego |
    Given a git repository named "repository3" with
      | main.rego | examples/warn.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        { "policy": ["git::https://${GITHOST}/git/repository1.git"] },
        { "policy": ["git::https://${GITHOST}/git/repository2.git"] },
        { "policy": ["git::https://${GITHOST}/git/repository3.git"] }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/opa-multiple-sources --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 1
    Then the output should match the snapshot

  Scenario: OPA policy rule filtering
    Given a key pair named "known"
    Given an image named "acceptance/opa-filtering"
    Given a valid image signature of "acceptance/opa-filtering" image signed by the "known" key
    Given a valid attestation of "acceptance/opa-filtering" signed by the "known" key
    Given a git repository named "happy-day-policy" with
      | filtering.rego | examples/filtering.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "policy": [
            "git::https://${GITHOST}/git/happy-day-policy.git"
          ],
          "config": {
            "include": ["@stamps", "filtering.always_pass"],
            "exclude": ["filtering.always_fail", "filtering.always_fail_with_collection"]
          }
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/opa-filtering --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: OPA future failure is converted to a warning
    Given a key pair named "known"
    Given an image named "acceptance/opa-future-deny"
    Given a valid image signature of "acceptance/opa-future-deny" image signed by the "known" key
    Given a valid attestation of "acceptance/opa-future-deny" signed by the "known" key
    Given a git repository named "future-deny-policy" with
      | main.rego | examples/future_deny.rego |
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/opa-future-deny --policy {"sources":[{"policy":["git::https://${GITHOST}/git/future-deny-policy.git"]}]} --public-key ${known_PUBLIC_KEY} --rekor-url ${REKOR} --show-successes --output json"
    Then the exit status should be 0
    Then the output should match the snapshot

  Scenario: OPA volatile config warnings
    Given a key pair named "known"
    Given an image named "acceptance/opa-volatile-config"
    Given a valid image signature of "acceptance/opa-volatile-config" image signed by the "known" key
    Given a valid attestation of "acceptance/opa-volatile-config" signed by the "known" key
    Given a git repository named "volatile-config-policy" with
      | main.rego | examples/volatile_config_warnings.rego |
    Given policy configuration named "ec-policy" with specification
    """
    {
      "sources": [
        {
          "name": "volatile-test-source",
          "policy": [
            "git::https://${GITHOST}/git/volatile-config-policy.git"
          ],
          "volatileConfig": {
            "exclude": [
              {
                "value": "test.rule_with_no_expiration"
              },
              {
                "value": "test.rule_expiring_soon",
                "effectiveUntil": "2099-12-31T23:59:59Z"
              },
              {
                "value": "test.rule_pending_activation",
                "effectiveOn": "2099-01-01T00:00:00Z"
              },
              {
                "value": "test.component_scoped_rule",
                "componentNames": ["Unnamed"]
              }
            ]
          }
        }
      ]
    }
    """
    When ec command is run with "validate image --image ${REGISTRY}/acceptance/opa-volatile-config --policy acceptance/ec-policy --public-key ${known_PUBLIC_KEY} --ignore-rekor --output json"
    Then the exit status should be 0
    Then the output should match the snapshot
