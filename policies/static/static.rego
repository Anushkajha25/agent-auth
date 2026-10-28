# Baseline 2: static role allowlist, no history.
package authz.static

import data.authz.lib

default allow := false

allow if count(deny) == 0

deny contains "role_not_permitted" if not lib.role_permits

decision := {"allow": allow, "reasons": sort([r | some r in deny])}
