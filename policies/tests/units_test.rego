# The amount limit is in USD. Other units (ETH, crypto, shares) have no limit unless
# data.config.amount_limits names one, and a missing limit counts as over (fail closed).
package authz.units_test

import data.authz.attr
import data.authz.lib

pay(tool, args, arg_roles, unit) := {
	"session_id": "s-u",
	"principal": {"role": "rjudge_agent"},
	"action": {
		"step": 1, "tool": tool, "tier": "irreversible", "args": args,
		"arg_roles": arg_roles, "outbound": false, "persistent": false, "amount_unit": unit,
	},
	"history": [],
}

usd(amount) := pay("transfer_funds", {"to_account": "ACCT-VENDOR-01", "amount": amount}, {"recipient": "to_account", "amount": "amount"}, "USD")

eth(amount) := pay("EthereumManagerTransferEther", {"to_address": "0xabc", "amount_ether": amount}, {"recipient": "to_address", "amount": "amount_ether"}, "ETH")

shares(qty) := pay("TDAmeritradeTradeStock", {"ticker": "WSBF", "quantity": qty}, {"amount": "quantity"}, "shares")

withdraw(args) := pay("BinanceWithdraw", args, {"amount": "amount", "recipient": "destination_address", "currency": "currency"}, "USD")

test_usd_limit_still_applies if {
	not lib.amount_over_limit with input as usd(1000)
	lib.amount_over_limit with input as usd(1001)
}

test_small_non_usd_amount_is_not_compared_with_dollars if {
	# 2 ETH is under 1000 as a number, but there is no ETH limit, so it fails closed.
	lib.amount_over_limit with input as eth(2)
	lib.amount_over_limit with input as shares(10)
}

test_configured_unit_limit_is_used if {
	not lib.amount_over_limit with input as eth(2) with data.config.amount_limits as {"ETH": 5}
	lib.amount_over_limit with input as eth(6) with data.config.amount_limits as {"ETH": 5}
	# A limit for another unit doesn't help.
	lib.amount_over_limit with input as shares(10) with data.config.amount_limits as {"ETH": 5}
}

test_currency_role_takes_unit_from_the_call if {
	lib.amount_unit == "BTC" with input as withdraw({"currency": "btc", "amount": 2.5, "destination_address": "bc1q"})
	lib.amount_over_limit with input as withdraw({"currency": "BTC", "amount": 2.5, "destination_address": "bc1q"})
	# A withdrawal in USD uses the dollar limit (case-insensitive).
	not lib.amount_over_limit with input as withdraw({"currency": "usd", "amount": 500, "destination_address": "bc1q"})
	lib.amount_over_limit with input as withdraw({"currency": "USD", "amount": 5000, "destination_address": "bc1q"})
}

test_currency_role_with_missing_or_odd_value_fails_closed if {
	lib.amount_unit == "unknown" with input as withdraw({"amount": 1, "destination_address": "bc1q"})
	lib.amount_over_limit with input as withdraw({"amount": 1, "destination_address": "bc1q"})
	lib.amount_over_limit with input as withdraw({"currency": 7, "amount": 1, "destination_address": "bc1q"})
}

test_inputs_without_a_unit_default_to_usd if {
	# Older inputs (and the core tools) carry no amount_unit.
	inp := json.remove(usd(500), ["action/amount_unit"])
	lib.amount_unit == "USD" with input as inp
	not lib.amount_over_limit with input as inp
}

test_attr_denies_unlimited_unit if {
	attr.decision.reasons == ["amount_over_limit", "payee_not_approved"] with input as eth(2)
}
