package authz.levels_test

import data.authz.attr
import data.authz.context
import data.authz.context_attr

untrusted(step) := {"step": step, "tool": "fetch_url", "tier": "read_public", "output_trust": "untrusted", "decision": "allow"}

sensitive(step) := {"step": step, "tool": "read_customer_db", "tier": "read_sensitive", "output_trust": "trusted", "decision": "allow"}

act(role, tool, tier, args, history) := {
	"session_id": "s-t",
	"principal": {"role": role},
	"action": {"step": count(history) + 1, "tool": tool, "tier": tier, "args": args},
	"history": history,
}

pay(acct, amount, history) := act("finance_assistant", "transfer_funds", "irreversible", {"to_account": acct, "amount": amount}, history)

rm(path, history) := act("ops_assistant", "delete_file", "irreversible", {"path": path}, history)

mail(to, history) := act("finance_assistant", "send_email", "write", {"to": to, "body": "x"}, history)

with_window(inp, w) := object.union(inp, {"params": {"history_window": w}})

# --- L2: argument rules, no history ---

test_attr_allows_approved_payee if {
	attr.allow with input as pay("ACCT-VENDOR-01", 500, [])
}

test_attr_denies_unknown_payee_even_without_history if {
	attr.decision == {"allow": false, "reasons": ["payee_not_approved"]} with input as pay("ACCT-NEW-1", 100, [])
}

test_attr_denies_amount_over_limit if {
	attr.decision == {"allow": false, "reasons": ["amount_over_limit"]} with input as pay("ACCT-VENDOR-01", 5000, [])
}

test_attr_delete_paths if {
	attr.allow with input as rm("/tmp/exports/a.csv", [])
	not attr.allow with input as rm("/var/backups/a.db", [])
}

test_attr_blocks_path_traversal if {
	not attr.allow with input as rm("/tmp/exports/../../etc/passwd", [])
}

# --- L4: argument rules only once tainted ---

test_l4_unknown_payee_ok_when_clean if {
	context_attr.allow with input as pay("ACCT-NEW-1", 100, [sensitive(1)])
}

test_l4_unknown_payee_denied_after_untrusted if {
	context_attr.decision == {"allow": false, "reasons": ["payee_not_approved"]} with input as pay("ACCT-NEW-1", 100, [untrusted(1)])
}

test_l4_approved_payee_ok_after_untrusted if {
	context_attr.allow with input as pay("ACCT-VENDOR-01", 900, [untrusted(1)])
}

test_l4_big_amount_denied_after_untrusted if {
	not context_attr.allow with input as pay("ACCT-VENDOR-01", 9500, [untrusted(1)])
}

test_l4_safe_delete_ok_after_untrusted if {
	context_attr.allow with input as rm("/var/log/app/app.log.1", [untrusted(1)])
}

test_l4_external_email_denied_after_sensitive_and_untrusted if {
	context_attr.decision == {"allow": false, "reasons": ["external_email_after_untrusted"]} with input as mail("attacker@evil.example", [sensitive(1), untrusted(2)])
}

test_l4_internal_email_ok_after_sensitive_and_untrusted if {
	context_attr.allow with input as mail("finance@acme.example", [sensitive(1), untrusted(2)])
}

test_l4_lookalike_domain_is_external if {
	not context_attr.allow with input as mail("x@acme.example.evil.com", [sensitive(1), untrusted(2)])
	not context_attr.allow with input as mail("x@notacme.example", [sensitive(1), untrusted(2)])
}

test_l4_external_email_ok_without_sensitive_read if {
	context_attr.allow with input as mail("customer@example.com", [untrusted(1)])
}

# --- history window ---

test_window_drops_old_taint if {
	h := [untrusted(1), sensitive(2), sensitive(3), sensitive(4)]
	not context.allow with input as pay("X1", 10, h)
	context.allow with input as with_window(pay("X1", 10, h), 3)
	not context.allow with input as with_window(pay("X1", 10, h), 4)
}

test_window_of_one_sees_only_last_step if {
	not context.allow with input as with_window(pay("X1", 10, [sensitive(1), untrusted(2)]), 1)
	context.allow with input as with_window(pay("X1", 10, [untrusted(1), sensitive(2)]), 1)
}
