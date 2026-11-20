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
| `action.arg_roles` | Which argument is the `recipient`, `amount` or `path`, e.g. `{"recipient": "to"}` | Tool registry |
| `action.outbound` | Whether the tool sends data outside the organisation | Tool registry |
| `action.persistent` | Whether the tool writes state that later sessions read (agent memory) | Tool registry |
| `history[]` | Earlier steps: tool, tier, `output_trust`, and whether it was allowed | Interceptor |
| `params.history_window` | Optional: how many recent steps the session rules look at | Deployment config |
| `params.enabled_rules` | Optional, experiments only: which of L4's rules are switched on (rule-count ablation) | Experiment runner |

`policy` is the Rego files and `data` is `policies/config/data.json` (roles, unrestricted roles, approved payees, transfer limit, safe delete paths, internal email domain, public fields).

**The LLM never labels anything.** Tiers, trust labels, argument roles and the outbound/persistent flags come from the YAML files in `registry/`, which people write. The interceptor attaches them, and the history is built by the interceptor, not reported by the agent. The only agent-controlled values are the tool name and its arguments. Arguments are only ever compared against fixed lists and limits in `data.json`.

## 2. Rules and how they combine

Every rule has the same form:

```
deny contains "<reason>" if {
    condition 1
    condition 2
    ...
}
```

A rule fires when **all** of its conditions are true. Each condition is a simple check on the input or on `data`, such as "the action is irreversible" or "the recipient is not in `approved_payees`".

- **Allow only if no rule fires.** `allow if count(deny) == 0`, with `default allow := false`.
- **Deny overrides.** There are no allow rules that could conflict with a deny, so there are no priorities and rule order doesn't matter.
- **All reasons are reported**, sorted, so a decision says exactly which rules fired.
- **Fail closed.** An unknown tool, an invalid input, an unreachable OPA or an undefined policy result are all denials.

The shared conditions live in `policies/lib/lib.rego`:

| Condition | True when |
|---|---|
| `role_permits` | The tool is in the role's allowlist, or the role is in `unrestricted_roles` (external benchmarks with no roles of their own) |
| `tainted` | A step in the window used a tool with `output_trust: untrusted` **and was allowed**. A denied read returned nothing, so it doesn't count. |
| `read_sensitive` | A step in the window was an allowed `read_sensitive` tool |
| `payee_not_approved` | An `irreversible` action whose `recipient` argument (any value, if it is a list) is not in `approved_payees`, or is missing |
| `amount_over_limit` | An `irreversible` action whose `amount` argument is above `max_transfer`, is not a number, or is missing |
| `delete_path_not_allowed` | An `irreversible` action whose `path` argument is not a string, contains `..`, is outside `safe_delete_prefixes`, or is missing |
| `outbound_external` | An `outbound` action with no recipient, or a recipient outside `@internal_email_domain`; or a `write` that sets a field listed in `public_fields` |

**These are templates, not tool rules.** None of them names a tool. They read the tier, `arg_roles` and `outbound`
from the registry, so `BankManagerTransferFunds` (R-Judge) is checked exactly like our `transfer_funds` once its
labels say which argument is the recipient and which is the amount. A tool with no `arg_roles` is never checked by
the argument rules; that is a labelling decision, visible in the registry.

## 3. Policy levels

Each level is a separate Rego package built from the conditions above, so we can compare them on the same traces (RQ3).

| Level | Package | Deny rules (besides role and missing tier) |
|---|---|---|
| L0 | `noop` | None: everything is allowed |
| L1 | `static` | Role allowlist only |
| L2 | `attr` | Payee, amount and path checks on every call. No history. |
| L3 | `context` | Irreversible action after any untrusted input |
| L4 | `context_attr` | Payee, amount and path checks, **but only once the session is tainted**. Outbound data to outside parties after both sensitive and untrusted input (`outbound_after_untrusted`). A `persistent` write (agent memory) after untrusted input (`persistent_write_after_untrusted`). |

**Why the memory rule.** Taint lasts for one session. An injection that gets the agent to save "always pay X1" into
memory would come back in a later, clean session as trusted content. Blocking persistent writes once the session is
tainted stops the injection at the point where it would outlive the session. Because of this, `read_memory` is labelled
trusted; the tier ablation measures what changes if it isn't.

**Switching rules for the ablation.** Each of L4's optional rules also requires `lib.rule_on("<reason>")`, which is
true unless `params.enabled_rules` is given and leaves the rule out. Production inputs never set it, so L4 behaves the
same; the rule-count ablation uses it to add or remove rules without a second copy of the policy. The role and
missing-tier checks are always on.

## 4. Why the decision is deterministic

The agent is not deterministic: the LLM may pick different tools on different runs. The **authorization decision** is, because for a given input document the result is always the same.

1. **The policy is a pure function.** Rego evaluation has no side effects. A test fails the build if any policy uses a built-in that reads the outside world or the clock (`http.send`, `time.*`, `rand.*`, `uuid.*`, `net.*`, `opa.runtime`).
2. **Everything the decision depends on is recorded.** Each log line stores the full input, a SHA-256 of its canonical JSON (sorted keys), and a SHA-256 of every policy file plus `data.json`.
3. **OPA is checked against those files.** Before any run, we check that OPA has loaded exactly the policies and data on disk, and stop if it hasn't. So the logged policy hash is the policy that was actually evaluated.
4. **Order can't leak in.** History is ordered by step number, and reasons are returned sorted.
5. **It's tested, not just argued.** The determinism check replays every logged input against OPA N times and compares the results with the log. On the custom suite: 144 steps × 5 policy levels, 5 runs each, 100% identical.
6. **Registry variants are recorded too.** The tier ablation decides with modified labels, but the labels used are part of each logged input, so those logs replay identically as well.

## 5. Known limits

- Trust is labelled **per tool**, not per piece of content. Any `fetch_url` result counts as untrusted, even from a trusted site.
- We don't track whether an *argument value* came from untrusted content. L4 relies on fixed allowlists instead, which someone has to maintain.
- The allowlists belong to one organisation (our fictional Acme). On R-Judge, whose payees and addresses are different, every payment or share after untrusted input is denied, including legitimate ones. We report those false positives rather than adding R-Judge's accounts to the lists.
- Taint-based rules can't catch harm that happens with no untrusted input before it (R-Judge's "unintended" risk type): the agent makes the mistake on its own.
- The templates are only as good as the labels. A tool with no `arg_roles`, or an outbound tool not marked `outbound`, isn't checked by the argument rules. Public fields are a fixed list in `data.json`.
