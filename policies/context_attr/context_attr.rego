# L4: role check, and the argument rules only apply once the session is tainted.
# Also blocks email to outside addresses after sensitive data and untrusted input were both read.
package authz.context_attr

import data.authz.lib

default allow := false

allow if count(deny) == 0

deny contains "role_not_permitted" if not lib.role_permits

deny contains "missing_tier" if not input.action.tier

deny contains "payee_not_approved" if {
	lib.tainted
	lib.payee_not_approved
}

deny contains "amount_over_limit" if {
	lib.tainted
	lib.amount_over_limit
}

deny contains "delete_path_not_allowed" if {
	lib.tainted
	lib.delete_path_not_allowed
}

deny contains "external_email_after_untrusted" if {
	lib.tainted
	lib.read_sensitive
	lib.external_email
}

decision := {"allow": allow, "reasons": sort([r | some r in deny])}
