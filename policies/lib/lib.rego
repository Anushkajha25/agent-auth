package authz.lib

role_permits if {
	input.action.tool in data.config.roles[input.principal.role]
}

# Roles from external benchmarks (R-Judge, ToolEmu) have no allowlist of their own.
# They skip only the role check; every other rule still applies.
role_permits if {
	input.principal.role in data.config.unrestricted_roles
}

# Rule switch for the rule-count ablation: every rule is on unless params.enabled_rules is
# given, in which case only the named rules are. Production inputs never set it.
rule_on(_) if not input.params.enabled_rules

rule_on(name) if name in input.params.enabled_rules

# History the session rules look at: the last history_window steps, or the whole session if no window is set.
recent contains h if {
	some h in input.history
	not input.params.history_window
}

recent contains h if {
	some h in input.history
	h.step > (input.action.step - 1) - input.params.history_window
}

# An allowed untrusted read in the window. A denied read returned nothing, so it doesn't count.
tainted if {
	some h in recent
	h.output_trust == "untrusted"
	h.decision == "allow"
}

# The same, over the whole session, ignoring history_window. Used for writes that outlive the
# session (agent memory): a window lets taint expire mid-session, but anything persisted now is
# read back as trusted later, so it must not be laundered by waiting a few steps.
tainted_session if {
	some h in input.history
	h.output_trust == "untrusted"
	h.decision == "allow"
}

read_sensitive if {
	some h in recent
	h.tier == "read_sensitive"
	h.decision == "allow"
}

# --- Tier-based argument templates ---
# No tool names below. Each rule reads the action's tier, which argument plays which role
# (action.arg_roles, from the registry), and the outbound flag. So a new tool is covered as
# soon as it is labelled in the registry.

has_role(r) if input.action.arg_roles[r]

# The registry says the tool has this role, but the call doesn't pass that argument.
# Treated as failing the check (fail closed).
role_missing(r) if {
	arg := input.action.arg_roles[r]
	not arg in object.keys(input.action.args)
}

# An empty list gives the rules nothing to check, so it counts as missing too.
role_missing(r) if {
	input.action.args[input.action.arg_roles[r]] == []
}

# The values passed for a role. A list (e.g. several recipients) counts as several values.
role_values(r) := as_list(input.action.args[input.action.arg_roles[r]])

as_list(v) := v if is_array(v)

as_list(v) := [v] if not is_array(v)

# A payment: an irreversible action that moves an amount. Only payments are checked against
# approved_payees; an irreversible email has a recipient but no amount, and an email address
# is not a payee.
moves_money if {
	input.action.tier == "irreversible"
	has_role("amount")
}

# A payment to a recipient that is not on the approved list.
payee_not_approved if {
	moves_money
	role_missing("recipient")
}

payee_not_approved if {
	moves_money
	some v in role_values("recipient")
	not v in data.config.approved_payees
}

# Irreversible amount above the limit. A missing or non-numeric amount counts as over the
# limit, so a string like "5000" is never left to Rego's cross-type comparison.
amount_over_limit if {
	input.action.tier == "irreversible"
	role_missing("amount")
}

amount_over_limit if {
	input.action.tier == "irreversible"
	some v in role_values("amount")
	not is_number(v)
}

amount_over_limit if {
	input.action.tier == "irreversible"
	some v in role_values("amount")
	is_number(v)
	not amount_limit
}

amount_over_limit if {
	input.action.tier == "irreversible"
	some v in role_values("amount")
	is_number(v)
	v > amount_limit
}

# The unit of the action's amount: from the call's currency argument when the tool has a
# currency role (e.g. a crypto withdrawal names its coin), else the tool's registry unit, else
# USD. A currency role with a missing or non-string value gives "unknown", which has no limit.
amount_unit := upper(v) if {
	arg := input.action.arg_roles.currency
	v := input.action.args[arg]
	is_string(v)
} else := "unknown" if {
	input.action.arg_roles.currency
} else := u if {
	u := input.action.amount_unit
} else := "USD"

# max_transfer is in USD. Other units only have a limit if data.config.amount_limits names one;
# otherwise there is none, and amount_over_limit treats that as over (fail closed), so 2.5 BTC
# is never compared with a dollar figure.
amount_limit := data.config.max_transfer if amount_unit == "USD"

amount_limit := object.get(object.get(data.config, "amount_limits", {}), amount_unit, null) if {
	amount_unit != "USD"
	object.get(object.get(data.config, "amount_limits", {}), amount_unit, null) != null
}

# A destructive action on a path: irreversible and not outbound. Sharing a file is
# outbound, and the outbound rule covers it; its path is not a deletion target.
destroys_path if {
	input.action.tier == "irreversible"
	not input.action.outbound
}

# A destructive action on a path outside the safe prefixes.
delete_path_not_allowed if {
	destroys_path
	role_missing("path")
}

delete_path_not_allowed if {
	destroys_path
	some v in role_values("path")
	not safe_delete_path(v)
}

safe_delete_path(p) if {
	is_string(p)
	not contains(p, "..")
	some prefix in data.config.safe_delete_prefixes
	startswith(p, prefix)
}

# Data leaves the organisation: an outbound tool with no recipient (e.g. a public post),
# a missing recipient, or any recipient outside the internal domain; or a write that
# puts a value into a public field (e.g. a ticket's public_note).
outbound_external if {
	input.action.outbound
	not has_role("recipient")
}

outbound_external if {
	input.action.outbound
	role_missing("recipient")
}

outbound_external if {
	input.action.outbound
	some v in role_values("recipient")
	not internal_address(v)
}

outbound_external if {
	input.action.tier == "write"
	writes_public_field
}

# Exactly one plain address in the internal domain. A string holding several addresses
# ("a@evil.example, b@acme.example") or a display name ("Bob <b@acme.example>") is not
# trusted as internal, even if it ends with the internal domain.
internal_address(v) if {
	is_string(v)
	count(split(v, "@")) == 2
	not regex.match(`[\s,;<>"]`, v)
	endswith(v, concat("", ["@", data.config.internal_email_domain]))
}

writes_public_field if {
	some v in input.action.args
	is_object(v)
	some k, _ in v
	k in data.config.public_fields
}
