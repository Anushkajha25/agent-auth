# L4: role check, and the tier-based argument rules only apply once the session is tainted.
# Also blocks outbound actions (email, sharing, public fields, ...) to outside parties after
# sensitive data and untrusted input were both read.
package authz.context_attr

import data.authz.lib

default allow := false

allow if count(deny) == 0

deny contains "role_not_permitted" if not lib.role_permits

deny contains "missing_tier" if not input.action.tier

deny contains "payee_not_approved" if {
	lib.rule_on("payee_not_approved")
	lib.tainted
	lib.payee_not_approved
}

deny contains "amount_over_limit" if {
	lib.rule_on("amount_over_limit")
	lib.tainted
	lib.amount_over_limit
}

deny contains "delete_path_not_allowed" if {
	lib.rule_on("delete_path_not_allowed")
	lib.tainted
	lib.delete_path_not_allowed
}

deny contains "outbound_after_untrusted" if {
	lib.rule_on("outbound_after_untrusted")
	lib.tainted
	lib.read_sensitive
	lib.outbound_external
}

# Memory poisoning: untrusted content must not be written into state that later sessions
# read back (agent memory, saved notes). Session taint ends with the session; this stops
# an injection from outliving it.
deny contains "persistent_write_after_untrusted" if {
	lib.rule_on("persistent_write_after_untrusted")
	lib.tainted
	input.action.persistent
}

decision := {"allow": allow, "reasons": sort([r | some r in deny])}
