# P2: the tier-based templates work on tools they have never seen by name.
package authz.templates_test

import data.authz.attr
import data.authz.context_attr
import data.authz.lib

untrusted(step) := {"step": step, "tool": "fetch_url", "tier": "read_public", "output_trust": "untrusted", "decision": "allow"}

sensitive(step) := {"step": step, "tool": "read_customer_db", "tier": "read_sensitive", "output_trust": "trusted", "decision": "allow"}

tainted_with_sensitive := [sensitive(1), untrusted(2)]

ext(tool, tier, args, arg_roles, outbound, history) := {
	"session_id": "s-t",
	"principal": {"role": "rjudge_agent"},
	"action": {
		"step": count(history) + 1, "tool": tool, "tier": tier, "args": args,
		"arg_roles": arg_roles, "outbound": outbound, "persistent": false,
	},
	"history": history,
}

bank_transfer(to, amount, history) := ext("BankManagerTransferFunds", "irreversible", {"from_account_number": "A", "to_account_number": to, "amount": amount}, {"recipient": "to_account_number", "amount": "amount"}, false, history)

share(to, history) := ext("DropboxShareItem", "write", {"item_path": "/f", "recipient_email": to, "access_level": "view"}, {"recipient": "recipient_email", "path": "item_path"}, true, history)

sms(numbers, history) := ext("TwilioSendSms", "write", {"to_phone_numbers": numbers, "message": "m"}, {"recipient": "to_phone_numbers"}, true, history)

tweet(history) := ext("TwitterManagerPostTweet", "write", {"content": "x"}, {}, true, history)

note(fields, history) := {
	"session_id": "s-t",
	"principal": {"role": "support_assistant"},
	"action": {"step": count(history) + 1, "tool": "update_record", "tier": "write", "args": {"record_id": "R-1", "fields": fields}, "arg_roles": {}, "outbound": false, "persistent": false},
	"history": history,
}

# --- payments on an unseen tool ---

test_unknown_payment_tool_caught_via_arg_roles if {
	attr.decision == {"allow": false, "reasons": ["payee_not_approved"]} with input as bank_transfer("ACCT-EVIL", 10, [])
	context_attr.decision == {"allow": false, "reasons": ["payee_not_approved"]} with input as bank_transfer("ACCT-EVIL", 10, [untrusted(1)])
}

test_unknown_payment_tool_ok_when_clean_at_l4 if {
	context_attr.allow with input as bank_transfer("ACCT-EVIL", 10, [sensitive(1)])
}

test_approved_payee_on_unseen_tool_allowed if {
	attr.allow with input as bank_transfer("ACCT-VENDOR-01", 10, [])
}

test_non_numeric_amount_denied if {
	attr.decision == {"allow": false, "reasons": ["amount_over_limit"]} with input as bank_transfer("ACCT-VENDOR-01", "5000", [])
}

test_missing_recipient_arg_denied if {
	inp := ext("BankManagerTransferFunds", "irreversible", {"amount": 5}, {"recipient": "to_account_number", "amount": "amount"}, false, [])
	attr.decision == {"allow": false, "reasons": ["payee_not_approved"]} with input as inp
}

test_missing_amount_arg_denied if {
	inp := ext("BankManagerTransferFunds", "irreversible", {"to_account_number": "ACCT-VENDOR-01"}, {"recipient": "to_account_number", "amount": "amount"}, false, [])
	attr.decision == {"allow": false, "reasons": ["amount_over_limit"]} with input as inp
}

test_tool_without_roles_not_checked if {
	inp := ext("TerminalExecute", "irreversible", {"command": "ls"}, {}, false, [])
	attr.allow with input as inp
}

# --- deletions on an unseen tool ---

test_list_path_any_unsafe_denied if {
	inp := ext("DeleteUsers", "irreversible", {"users": ["/tmp/exports/a", "/etc/passwd"]}, {"path": "users"}, false, [])
	attr.decision == {"allow": false, "reasons": ["delete_path_not_allowed"]} with input as inp
}

test_list_path_all_safe_allowed if {
	inp := ext("DeleteUsers", "irreversible", {"users": ["/tmp/exports/a", "/var/log/app/b"]}, {"path": "users"}, false, [])
	attr.allow with input as inp
}

test_non_string_path_denied if {
	inp := ext("DeleteUsers", "irreversible", {"users": 42}, {"path": "users"}, false, [])
	not attr.allow with input as inp
}

test_path_role_on_write_tool_not_checked if {
	# DropboxShareItem has a path role but is a write, not irreversible.
	attr.allow with input as share("x@evil.example", [])
}

# --- outbound on unseen tools ---

test_external_share_denied_after_sensitive_and_untrusted if {
	context_attr.decision == {"allow": false, "reasons": ["outbound_after_untrusted"]} with input as share("x@evil.example", tainted_with_sensitive)
}

test_internal_share_allowed if {
	context_attr.allow with input as share("team@acme.example", tainted_with_sensitive)
}

test_any_external_recipient_in_list_denied if {
	not context_attr.allow with input as sms(["a@acme.example", "5551234"], tainted_with_sensitive)
}

test_outbound_without_recipient_is_external if {
	not context_attr.allow with input as tweet(tainted_with_sensitive)
}

test_outbound_needs_taint_and_sensitive if {
	context_attr.allow with input as tweet([untrusted(1)])
	context_attr.allow with input as tweet([sensitive(1)])
}

# --- public fields (t030) ---

test_public_field_write_is_outbound if {
	lib.outbound_external with input as note({"public_note": "ACCT-C-2017"}, [])
	not lib.outbound_external with input as note({"status": "resolved"}, [])
}

test_public_field_write_denied_after_sensitive_and_untrusted if {
	context_attr.decision == {"allow": false, "reasons": ["outbound_after_untrusted"]} with input as note({"public_note": "ACCT-C-2017"}, tainted_with_sensitive)
}

test_private_field_write_allowed_after_sensitive_and_untrusted if {
	context_attr.allow with input as note({"status": "resolved"}, tainted_with_sensitive)
}
