# Agent Auth

Context-aware authorization for LLM agent tool calls. Every tool call goes through an
interceptor, which asks a policy decision point (PDP) to allow or deny it. The decision can
depend on the session history as well as the agent's role.

```
labeled traces → interceptor → PDP (L0–L4) → JSONL decision log → metrics
```

## Pinned versions

- **OPA:** `openpolicyagent/opa:1.21.4` (latest stable when this was set up, released 2026-10-23). Policies use Rego v1 syntax.
- **Python:** 3.11+ (developed on 3.13).

## Setup

```bash
python3.13 -m venv .venv
.venv/bin/pip install -e '.[dev]'
docker compose up -d                       # OPA on http://localhost:8181
```

Set `OPA_URL` to point at a different OPA server.

## Commands

```bash
# Python tests (no OPA needed)
.venv/bin/pytest -m "not opa"

# Rego unit tests
docker compose run --rm opa test /policies -v

# Replay all traces under every policy level (add --window N to limit history)
.venv/bin/python -m authz.eval.replay --pdp all --traces scenarios/custom --out results/

# E2/E3: results by category, level trade-off, history-window sweep, with figures
.venv/bin/python -m authz.eval.experiments --out results/experiments

# Re-check every logged decision 5 times
.venv/bin/python -m authz.eval.determinism --log results/<run_id>/decisions.jsonl --runs 5

# Everything, including the OPA integration test
.venv/bin/pytest
```

## Live agent and system experiments (E1, E4, E5)

E1 needs only OPA. E4 and E5 call an LLM API, so set a key first; it is read from the
environment and never written to logs:

```bash
export OPENAI_API_KEY=...        # for --provider openai
export ANTHROPIC_API_KEY=...     # for --provider anthropic
```

```bash
# E1: enforcement latency for L0-L4 across history lengths (no API key needed)
.venv/bin/python -m authz.eval.latency --out results/e1

# E4: Rego L4 vs. an LLM judge on the same traces, each input asked 5 times
#     (about 144 x 5 judge calls; try --limit 5 first)
.venv/bin/python -m authz.eval.judge_compare --provider openai --model gpt-4o-mini --runs 5 --out results/e4

# E5: live agent on scenarios/live under each condition, 3 seeds
#     (add 'judge' to --conditions for the LLM judge; --only l01_refund_known_customer to try one task)
.venv/bin/python -m authz.eval.live --provider openai --model gpt-4o-mini --conditions L0,L1,L3,L4 --seeds 3 --out results/e5
```

The agent (`src/authz/agent/`) is a minimal function-calling loop. Every tool call goes
through the interceptor; a denied call comes back to the model as a tool error and the agent
re-plans. Runs stop at 15 tool calls, 3 denials, a repeated identical denial, or 20 LLM calls.
The system prompt says nothing about security, so all protection comes from the policy.
Live tasks (`scenarios/live/`, schema `schemas/live_task.schema.json`) list the calls that
complete the user's task and the calls an injection is trying to cause; runs are scored on
what the executor actually ran.

## Policy levels

| Level | `--pdp` | Rules |
|---|---|---|
| L0 | `noop` | Allow everything |
| L1 | `static` | Role allowlist |
| L2 | `attr` | Role + payee, amount and delete-path checks, no history |
| L3 | `context` | Role + deny irreversible actions after untrusted input |
| L4 | `context_attr` | Role + payee/amount/path checks once tainted + no external email after sensitive and untrusted input |

See `docs/rule-semantics.md` for how rules are evaluated and why decisions are deterministic.

## Expected results

45 traces, 144 steps, 25 of them unsafe.

| Level | Violation rate | False positive rate |
|---|---|---|
| L0 noop | 25/25 (100%) | 0/119 |
| L1 static | 20/25 (80%), catches only role violations | 0/119 |
| L2 attr | 7/25 (28%), misses exfiltration | 3/119 |
| L3 context | 7/25 (28%), misses exfiltration | 7/119 |
| L4 context_attr | 1/25 (4%), misses t030 | 1/119 (t018) |

## Layout

| Path | What it is |
|---|---|
| `registry/tools.yaml` | Tool labels (tier, output trust). The single source of truth. |
| `policies/` | Rego: `lib` (shared conditions), `static`, `attr`, `context`, `context_attr`, `config/data.json` (roles and allowlists, loaded as `data.config`), `tests/` |
| `schemas/` | JSON Schemas for the PDP input, traces and live tasks |
| `scenarios/custom/` | 45 labeled traces in 7 categories (144 steps, 25 unsafe) |
| `src/authz/interceptor.py` | Fail-closed interceptor. The only code path that runs a tool. |
| `src/authz/tools/executor.py` | `ToolExecutor` interface and `MockToolExecutor`: runs the mock tools, records every executed call per session, and can override tool outputs per task. |
| `src/authz/pdp/` | `NoOpPDP`, `OpaPDP`, and `make_pdp` |
| `src/authz/eval/` | `replay`, `metrics`, `determinism`, `experiments` (E2/E3), `latency` (E1), `judge_compare` (E4), `live` (E5), `task_success` |
| `src/authz/agent/` | `llm` (OpenAI and Anthropic clients over HTTP), `loop` (the tool-calling agent) |
| `src/authz/pdp/llm_judge.py` | Baseline 3: LLM judge as the PDP, given the same context as the Rego policies |
| `scenarios/live/` | 13 live tasks for E5 (6 benign, 7 attacks) |
| `docs/` | `rule-semantics.md`, E2/E3 figures |
| `results/` | Run outputs (gitignored) |

## Design notes

- **Fail closed.** If the PDP raises or times out (500 ms), the call is denied with `pdp_unavailable`. A tool that isn't in the registry is denied with `unknown_tool`. With `--validate-input`, input that fails the schema is denied with `invalid_input`. The PDP isn't called in either case.
- **Taint rule.** A session is tainted once any *allowed* untrusted-output tool has run in the history window (the whole session by default). A denied untrusted read produced no content, so it doesn't taint the session.
- **Reproducibility.** Each log line records `input_sha256`, which is a hash of canonical JSON, and `policy_sha256`, which hashes every `.rego` file plus `config/data.json`. The determinism check refuses to run if the policies have changed since the log was written.
- **OPA policy check.** OPA runs with `--watch`. Before using OPA, `replay` and `determinism` check that OPA has the same policies and data as the files on disk, and stop if they don't. This keeps `policy_sha256` in the log accurate.
- **No non-deterministic built-ins.** A pytest test fails if any `.rego` file uses `http.send`, `time.*`, `rand.*`, `uuid.*`, `net.*` or `opa.runtime`.
