# Context-aware policy: static role check plus session-history rules.
package authz.context

import data.authz.lib

default allow := false

allow if count(deny) == 0

deny contains "role_not_permitted" if not lib.role_permits

deny contains "missing_tier" if not input.action.tier

# A denied untrusted read produced no content, so it does not taint the session.
deny contains "irreversible_after_untrusted" if {
	input.action.tier == "irreversible"
	some h in input.history
	h.output_trust == "untrusted"
	h.decision == "allow"
}

decision := {"allow": allow, "reasons": sort([r | some r in deny])}
