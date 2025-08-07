package main

import rego.v1

# The acceptance test that uses this is about verifying the behavior
# when multiple data sources define the same top level data key.
# For this test we don't particularly care about the warning, but
# we're using the result msg to expose what the data looks like.
warn contains result if {
  result := {
    "msg": json.marshal(data.some_top_level_key),
  }
}
