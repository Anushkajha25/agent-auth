package authz.context_test

import data.authz.context
import data.authz.static

untrusted_read(decision) := {
	"step": 1, "tool": "fetch_url", "tier": "read_public",
	"output_trust": "untrusted", "decision": decision,
}

trusted_read := {
	"step": 1, "tool": "read_customer_db", "tier": "read_sensitive",
	"output_trust": "trusted", "decision": "allow",
}

transfer(history) := {
	"session_id": "s-t",
	"principal": {"role": "finance_assistant"},
	"action": {"step": count(history) + 1, "tool": "transfer_funds", "tier": "irreversible", "args": {"to_account": "X1", "amount": 500}},
	"history": history,
}

test_denies_irreversible_after_allowed_untrusted_read if {
	context.decision == {"allow": false, "reasons": ["irreversible_after_untrusted"]} with input as transfer([untrusted_read("allow")])
}

test_allows_irreversible_after_trusted_reads_only if {
	context.decision == {"allow": true, "reasons": []} with input as transfer([trusted_read, trusted_read])
}

test_allows_irreversible_after_denied_untrusted_read if {
	context.allow with input as transfer([untrusted_read("deny")])
}

test_taint_persists_across_session if {
	h := [untrusted_read("allow"), trusted_read, trusted_read, trusted_read]
	not context.allow with input as transfer(h)
}

test_denies_missing_tier if {
	inp := transfer([])
	# object.union merges recursively, so drop "action" first and re-add it without "tier".
	no_tier := object.union(object.remove(inp, ["action"]), {"action": object.remove(inp.action, ["tier"])})
	context.decision == {"allow": false, "reasons": ["missing_tier"]} with input as no_tier
}

test_non_irreversible_after_untrusted_allowed if {
	inp := {
		"session_id": "s-t",
		"principal": {"role": "support_assistant"},
		"action": {"step": 2, "tool": "send_email", "tier": "write", "args": {}},
		"history": [untrusted_read("allow")],
	}
	context.allow with input as inp
}

test_reports_multiple_reasons_sorted if {
	inp := object.union(transfer([untrusted_read("allow")]), {"principal": {"role": "support_assistant"}})
	context.decision == {"allow": false, "reasons": ["irreversible_after_untrusted", "role_not_permitted"]} with input as inp
}

# With empty history, context must agree with static.
test_empty_history_matches_static_in_role if {
	inp := transfer([])
	context.decision == static.decision with input as inp
	context.allow with input as inp
}

test_empty_history_matches_static_out_of_role if {
	inp := object.union(transfer([]), {"principal": {"role": "support_assistant"}})
	context.decision == static.decision with input as inp
	not context.allow with input as inp
}
