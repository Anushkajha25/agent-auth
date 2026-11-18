# L2: role check plus argument rules on irreversible actions. No history.
package authz.attr

import data.authz.lib

default allow := false

allow if count(deny) == 0

deny contains "role_not_permitted" if not lib.role_permits

deny contains "missing_tier" if not input.action.tier

deny contains "payee_not_approved" if lib.payee_not_approved

deny contains "amount_over_limit" if lib.amount_over_limit

deny contains "delete_path_not_allowed" if lib.delete_path_not_allowed

decision := {"allow": allow, "reasons": sort([r | some r in deny])}
