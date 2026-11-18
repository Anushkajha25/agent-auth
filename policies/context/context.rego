# L3: role check plus session taint.
package authz.context

import data.authz.lib

default allow := false

allow if count(deny) == 0

deny contains "role_not_permitted" if not lib.role_permits

deny contains "missing_tier" if not input.action.tier

deny contains "irreversible_after_untrusted" if {
	input.action.tier == "irreversible"
	lib.tainted
}

decision := {"allow": allow, "reasons": sort([r | some r in deny])}
