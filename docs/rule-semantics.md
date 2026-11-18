# How the policy engine decides

This answers the three questions from the proposal feedback: is it rule-based, how do we know whether a rule is satisfied, and how do we guarantee the decision is deterministic.

## 1. A decision is a function of one input document

Before every tool call, the interceptor builds an input document and asks the policy engine (OPA) for a decision:

```
decide(input, policy, data) -> {allow: bool, reasons: [string]}
```

| Input field | What it holds | Who sets it |
|---|---|---|
| `principal.role` | The agent's role, e.g. `finance_assistant` | Deployment config |
| `action.tool`, `action.args` | The call the agent wants to make | The agent (LLM) |
| `action.tier` | `read_public`, `read_sensitive`, `write` or `irreversible` | Tool registry |
| `history[]` | Earlier steps: tool, tier, `output_trust`, and whether it was allowed | Interceptor |
| `params.history_window` | Optional: how many recent steps the session rules look at | Deployment config |

`policy` is the Rego files and `data` is `policies/config/data.json` (roles, approved payees, transfer limit, safe delete paths, internal email domain).

**The LLM never labels anything.** Tiers and trust labels come from `registry/tools.yaml`, which people write. The interceptor attaches them, and the history is built by the interceptor, not reported by the agent. The only agent-controlled values are the tool name and its arguments. Arguments are only ever compared against fixed lists and limits in `data.json`.

## 2. Rules and how they combine

Every rule has the same form:

```
deny contains "<reason>" if {
    condition 1
    condition 2
    ...
}
```

A rule fires when **all** of its conditions are true. Each condition is a simple check on the input or on `data`, such as "the tool is `transfer_funds`" or "the payee is not in `approved_payees`".

- **Allow only if no rule fires.** `allow if count(deny) == 0`, with `default allow := false`.
- **Deny overrides.** There are no allow rules that could conflict with a deny, so there are no priorities and rule order doesn't matter.
- **All reasons are reported**, sorted, so a decision says exactly which rules fired.
- **Fail closed.** An unknown tool, an invalid input, an unreachable OPA or an undefined policy result are all denials.

The shared conditions live in `policies/lib/lib.rego`:

| Condition | True when |
|---|---|
| `role_permits` | The tool is in the role's allowlist |
| `tainted` | A step in the window used a tool with `output_trust: untrusted` **and was allowed**. A denied read returned nothing, so it doesn't count. |
| `read_sensitive` | A step in the window was an allowed `read_sensitive` tool |
| `payee_not_approved` | `transfer_funds` to an account not in `approved_payees` |
| `amount_over_limit` | `transfer_funds` amount above `max_transfer` |
| `delete_path_not_allowed` | `delete_file` path is outside `safe_delete_prefixes`, or contains `..` |
| `external_email` | `send_email` to an address outside `@internal_email_domain` |

## 3. Policy levels

Each level is a separate Rego package built from the conditions above, so we can compare them on the same traces (RQ3).

| Level | Package | Deny rules (besides role and missing tier) |
|---|---|---|
| L0 | `noop` | None: everything is allowed |
| L1 | `static` | Role allowlist only |
| L2 | `attr` | Payee, amount and delete-path checks on every call. No history. |
| L3 | `context` | Irreversible action after any untrusted input |
| L4 | `context_attr` | Payee, amount and delete-path checks, **but only once the session is tainted**. External email after both sensitive and untrusted input. |

## 4. Why the decision is deterministic

The agent is not deterministic: the LLM may pick different tools on different runs. The **authorization decision** is, because for a given input document the result is always the same.

1. **The policy is a pure function.** Rego evaluation has no side effects. A test fails the build if any policy uses a built-in that reads the outside world or the clock (`http.send`, `time.*`, `rand.*`, `uuid.*`, `net.*`, `opa.runtime`).
2. **Everything the decision depends on is recorded.** Each log line stores the full input, a SHA-256 of its canonical JSON (sorted keys), and a SHA-256 of every policy file plus `data.json`.
3. **OPA is checked against those files.** Before any run, we check that OPA has loaded exactly the policies and data on disk, and stop if it hasn't. So the logged policy hash is the policy that was actually evaluated.
4. **Order can't leak in.** History is ordered by step number, and reasons are returned sorted.
5. **It's tested, not just argued.** The determinism check replays every logged input against OPA N times and compares the results with the log. On the current suite: 144 steps × 5 policy levels, 5 runs each, 100% identical.

## 5. Known limits

- Trust is labelled **per tool**, not per piece of content. Any `fetch_url` result counts as untrusted, even from a trusted site.
- We don't track whether an *argument value* came from untrusted content. L4 relies on fixed allowlists instead, which someone has to maintain.
- Rules only cover the actions we wrote them for. L4 still misses data copied into a public record field (`t030`), because `update_record` isn't treated as outbound.
