# P3: memory poisoning. Writes to persistent state are blocked once the session is tainted.
package authz.memory_test

import data.authz.context
import data.authz.context_attr

read(step, tool, trust, decision) := {"step": step, "tool": tool, "tier": "read_public", "output_trust": trust, "decision": decision}

remember(history) := {
	"session_id": "s-t",
	"principal": {"role": "finance_assistant"},
	"action": {
		"step": count(history) + 1, "tool": "write_memory", "tier": "write",
		"args": {"key": "k", "value": "v"}, "arg_roles": {}, "outbound": false, "persistent": true,
	},
	"history": history,
}

test_memory_write_denied_after_untrusted if {
	context_attr.decision == {"allow": false, "reasons": ["persistent_write_after_untrusted"]} with input as remember([read(1, "fetch_url", "untrusted", "allow")])
}

test_memory_write_allowed_when_clean if {
	context_attr.allow with input as remember([read(1, "read_customer_db", "trusted", "allow")])
	context_attr.allow with input as remember([])
}

test_denied_untrusted_read_does_not_taint if {
	context_attr.allow with input as remember([read(1, "fetch_url", "untrusted", "deny")])
}

test_memory_rule_respects_history_window if {
	h := [read(1, "fetch_url", "untrusted", "allow"), read(2, "read_customer_db", "trusted", "allow"), read(3, "read_customer_db", "trusted", "allow")]
	not context_attr.allow with input as remember(h)
	context_attr.allow with input as object.union(remember(h), {"params": {"history_window": 2}})
}

test_non_persistent_write_not_affected if {
	inp := {
		"session_id": "s-t",
		"principal": {"role": "support_assistant"},
		"action": {"step": 2, "tool": "update_record", "tier": "write", "args": {"record_id": "R", "fields": {"status": "x"}}, "arg_roles": {}, "outbound": false, "persistent": false},
		"history": [read(1, "search_web", "untrusted", "allow")],
	}
	context_attr.allow with input as inp
}

test_l3_does_not_have_the_memory_rule if {
	# L3 stays the single-rule baseline: a memory write is a write, not irreversible.
	context.allow with input as object.union(remember([read(1, "fetch_url", "untrusted", "allow")]), {"principal": {"role": "finance_assistant"}})
}

# --- P5: rule switch ---

test_rule_on_by_default_and_when_listed if {
	tainted_write := remember([read(1, "fetch_url", "untrusted", "allow")])
	not context_attr.allow with input as tainted_write
	not context_attr.allow with input as object.union(tainted_write, {"params": {"enabled_rules": ["persistent_write_after_untrusted"]}})
}

test_rule_off_when_not_listed if {
	tainted_write := remember([read(1, "fetch_url", "untrusted", "allow")])
	context_attr.allow with input as object.union(tainted_write, {"params": {"enabled_rules": ["payee_not_approved"]}})
	context_attr.allow with input as object.union(tainted_write, {"params": {"enabled_rules": []}})
}

test_role_check_cannot_be_switched_off if {
	inp := object.union(remember([]), {"principal": {"role": "nobody"}, "params": {"enabled_rules": []}})
	context_attr.decision == {"allow": false, "reasons": ["role_not_permitted"]} with input as inp
}
