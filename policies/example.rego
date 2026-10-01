package mcpwarden.decision

import rego.v1

# Equivalent to the example YAML in SPEC.md §5.2. Deny overrides allow.
# Unannotated tools do not match annotation conditions, so they stay on the default deny.

default allow := false
default reason := "default deny"

destructive if {
	input.action == "call"
	object.get(input.annotations, "destructiveHint", false) == true
}

analyst_catalog if {
	input.action in {"list", "call"}
	input.server == "catalog"
	object.get(input.annotations, "readOnlyHint", false) == true
	principal_has("roles", "analyst")
}

steward_catalog if {
	input.action in {"list", "call"}
	input.server == "catalog"
	object.get(input.annotations, "readOnlyHint", false) == true
	principal_has("roles", "steward")
}

allow if {
	not destructive
	analyst_catalog
}

allow if {
	not destructive
	steward_catalog
}

reason := "Destructive tools are blocked through the gateway." if {
	destructive
}

reason := "allow" if {
	allow
}

rule_ids contains "no-destructive" if {
	destructive
}

rule_ids contains "analysts-read-catalog" if {
	not destructive
	analyst_catalog
}

rule_ids contains "stewards-read-catalog" if {
	not destructive
	steward_catalog
}

obligations contains {"type": "mask_pii"} if {
	allow
	analyst_catalog
}

obligations contains {"type": "strip_inferences"} if {
	allow
	analyst_catalog
}

obligations contains {"type": "max_items", "n": 50} if {
	allow
	analyst_catalog
}

obligations contains {"type": "mask_pii"} if {
	allow
	steward_catalog
}

principal_has(attribute, value) if {
	some item in object.get(object.get(input, "principal", {}), "attributes", {})[attribute]
	item == value
}
