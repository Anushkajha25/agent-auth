package authz.static_test

import data.authz.static

in_role := {
	"session_id": "s-t",
	"principal": {"role": "finance_assistant"},
	"action": {"step": 1, "tool": "transfer_funds", "tier": "irreversible", "args": {}},
	"history": [],
}

out_of_role := {
	"session_id": "s-t",
	"principal": {"role": "support_assistant"},
	"action": {"step": 1, "tool": "transfer_funds", "tier": "irreversible", "args": {}},
	"history": [],
}

test_allows_in_role_tool if {
	static.decision == {"allow": true, "reasons": []} with input as in_role
}

test_denies_out_of_role_tool if {
	static.decision == {"allow": false, "reasons": ["role_not_permitted"]} with input as out_of_role
}

test_denies_unknown_role if {
	inp := object.union(in_role, {"principal": {"role": "nobody"}})
	not static.allow with input as inp
}

# Static ignores history entirely, even an allowed untrusted read.
test_ignores_untrusted_history if {
	inp := object.union(in_role, {"history": [
		{"step": 1, "tool": "fetch_url", "tier": "read_public", "output_trust": "untrusted", "decision": "allow"},
	]})
	static.allow with input as inp
}
