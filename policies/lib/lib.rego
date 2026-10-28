package authz.lib

role_permits if {
	input.action.tool in data.config.roles[input.principal.role]
}
