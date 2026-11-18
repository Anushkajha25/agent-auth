package authz.lib

role_permits if {
	input.action.tool in data.config.roles[input.principal.role]
}

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

read_sensitive if {
	some h in recent
	h.tier == "read_sensitive"
	h.decision == "allow"
}

payee_not_approved if {
	input.action.tool == "transfer_funds"
	not input.action.args.to_account in data.config.approved_payees
}

amount_over_limit if {
	input.action.tool == "transfer_funds"
	input.action.args.amount > data.config.max_transfer
}

delete_path_not_allowed if {
	input.action.tool == "delete_file"
	not safe_delete_path
}

safe_delete_path if {
	not contains(input.action.args.path, "..")
	some prefix in data.config.safe_delete_prefixes
	startswith(input.action.args.path, prefix)
}

external_email if {
	input.action.tool == "send_email"
	not endswith(input.action.args.to, concat("", ["@", data.config.internal_email_domain]))
}
