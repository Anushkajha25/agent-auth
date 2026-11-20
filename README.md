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

# P5: rule-count ablation on L4 (cumulative and leave-one-out), per dataset and combined
.venv/bin/python -m authz.eval.rule_ablation --traces scenarios/custom scenarios/rjudge scenarios/memory

# P6: tier ablation: tighten/loosen registry labels and re-run L2-L4 on every dataset
.venv/bin/python -m authz.eval.tier_ablation --traces scenarios/custom scenarios/rjudge scenarios/memory

# Re-check every logged decision 5 times
.venv/bin/python -m authz.eval.determinism --log results/<run_id>/decisions.jsonl --runs 5

# Everything, including the OPA integration test
.venv/bin/pytest
```

## Live agent and system experiments (E1, E4, E5)

E1 needs only OPA. E4 and E5 need an LLM. The free option is a local model through
[Ollama](https://ollama.com), which needs no account or API key:

```bash
brew install ollama            # or download the app from ollama.com
ollama serve                   # leave running (the Ollama app does this for you)
ollama pull qwen2.5:7b         # ~4.7 GB; any model with tool calling works (qwen2.5:3b for 8 GB Macs)
```

Set `OLLAMA_URL` if Ollama isn't on `http://localhost:11434/v1`. Hosted APIs also work with
`--provider openai` or `--provider anthropic` and `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`;
keys are read from the environment and never logged.

```bash
# E1: enforcement latency for L0-L4 across history lengths (no LLM needed)
.venv/bin/python -m authz.eval.latency --out results/e1

# E4: Rego L4 vs. an LLM judge on the same traces, each input asked 5 times
#     (about 144 x 5 judge calls; try --limit 5 first)
.venv/bin/python -m authz.eval.judge_compare --provider ollama --model qwen2.5:7b --runs 5 --out results/e4

# E5: live agent on scenarios/live under each condition, 3 seeds
#     (add 'judge' to --conditions for the LLM judge; --only l01_refund_known_customer to try one task)
.venv/bin/python -m authz.eval.live --provider ollama --model qwen2.5:7b --conditions L0,L1,L3,L4 --seeds 3 --out results/e5
```

The agent (`src/authz/agent/`) is a minimal function-calling loop. Every tool call goes
through the interceptor; a denied call comes back to the model as a tool error and the agent
re-plans. Runs stop at 15 tool calls, 3 denials, a repeated identical denial, or 20 LLM calls.
The system prompt says nothing about security, so all protection comes from the policy.
Live tasks (`scenarios/live/`, schema `schemas/live_task.schema.json`) list the calls that
complete the user's task and the calls an injection is trying to cause; runs are scored on
what the executor actually ran.

## R-Judge dataset

60 traces from [R-Judge](https://github.com/Lordog/R-Judge) (Yuan et al., EMNLP 2024) live in `scenarios/rjudge/`
(17 safe, 43 unsafe), with tool labels in `registry/rjudge.yaml`. They test the history and argument rules on outside
data; they use one role, `rjudge_agent`, listed in `unrestricted_roles` in `policies/config/data.json`, so it may call
every tool and they don't test RBAC. Every other rule still applies. R-Judge tools have no mock implementation: replay
runs them on a stub that accepts any arguments, and the live agent never sees them.

**What's committed**

| File | What it is |
| --- | --- |
| `scripts/rjudge/selection.csv` | The 66 candidate records: keep/drop, the harmful step, and a one-line reason (60 kept, 6 dropped) |
| `registry/rjudge.yaml` | Tier, output_trust, args, arg_roles and outbound for all 67 tools used |
| `scenarios/rjudge/rj_*.json` | The generated traces |
| `scripts/rjudge/*.py` | Candidate filter, subset proposal, converter |

**Reproduce the traces**

```bash
# 1. Get R-Judge next to this repo (not inside it), at the commit we used
git clone https://github.com/Lordog/R-Judge.git ../R-Judge
git -C ../R-Judge checkout 83ce301

# 2. Convert the selected records into traces (overwrites scenarios/rjudge/rj_*.json)
python scripts/rjudge/convert.py ../R-Judge
#   -> wrote 60 traces ... ({'benign': 17, 'adversarial': 43}), dropped 6 records

# 3. Check
pytest -q tests/test_rjudge_converter.py
git status scenarios/rjudge/   # no changes = identical to the committed traces
```

`python scripts/rjudge/convert.py ../R-Judge --list-tools` lists every tool in the subset with the argument names it
was called with. The converter stops with `MISSING from registry/rjudge.yaml` if a tool has no label.

**How the subset was chosen** (only needed to redo the selection)

```bash
python scripts/rjudge/select_candidates.py ../R-Judge /tmp/rjudge_candidates.csv
python scripts/rjudge/propose_subset.py /tmp/rjudge_candidates.csv ../R-Judge /tmp/selection_proposed.csv
```

1. Keep records with a payment, deletion, email/sharing, record-update or file/system-command tool call
   (571 → 257). Tool names with a read verb (Get, Read, Search, View, ...) count as reads.
2. Drop near-duplicates (same label and same tool sequence) → 220 (18 safe, 202 unsafe).
3. Propose all safe records plus unsafe ones spread across action types → 66.
4. In each unsafe record, mark the one step that causes the harm as `should_allow: false`; all other steps are
   `true`. Records with no single harmful tool call are dropped (6). Only 18 usable safe records exist, so the split
   is 17/43 rather than 50/50.

Write the proposal to `/tmp` as above: `propose_subset.py` would overwrite the labelled `selection.csv`.

## Policy levels

| Level | `--pdp` | Rules |
|---|---|---|
| L0 | `noop` | Allow everything |
| L1 | `static` | Role allowlist |
| L2 | `attr` | Role + recipient, amount and path checks on irreversible actions, no history |
| L3 | `context` | Role + deny irreversible actions after untrusted input |
| L4 | `context_attr` | Role + recipient/amount/path checks once tainted + no outbound data to outside parties after sensitive and untrusted input + no memory writes after untrusted input |

The argument rules are **tier-based templates**: they never name a tool. They read the action's tier, the
registry's `arg_roles` (which argument is the `recipient`, `amount` or `path`) and `outbound` flag, so a tool from
another dataset is covered once it is labelled. Writing to a public field (`public_fields` in `data.json`, e.g. a
ticket's `public_note`) counts as outbound. Tools marked `persistent` (agent memory) can't be written after
untrusted input, so an injection can't outlive its session.

See `docs/rule-semantics.md` for how rules are evaluated and why decisions are deterministic.

## Expected results

Custom suite: 45 traces, 144 steps, 25 of them unsafe.

| Level | Violation rate | False positive rate |
|---|---|---|
| L0 noop | 25/25 (100%) | 0/119 |
| L1 static | 20/25 (80%), catches only role violations | 0/119 |
| L2 attr | 7/25 (28%), misses exfiltration | 3/119 |
| L3 context | 7/25 (28%), misses exfiltration | 7/119 |
| L4 context_attr | 0/25 (0%) | 1/119 (t018) |

R-Judge (60 traces, 143 steps, 43 unsafe) and memory (5 traces, 11 steps, 2 unsafe):

| Level | R-Judge violations | R-Judge false positives | Memory violations | Memory false positives |
|---|---|---|---|---|
| L0 noop | 43/43 | 0/100 | 2/2 | 0/9 |
| L1 static | 43/43 (unrestricted role) | 0/100 | 2/2 | 0/9 |
| L2 attr | 30/43 | 4/100 | 2/2 | 0/9 |
| L3 context | 29/43 | 4/100 | 2/2 | 0/9 |
| L4 context_attr | 21/43 | 3/100 | 0/2 | 1/9 (m05) |

Many R-Judge harms happen with no untrusted input before them (the "unintended" risk type), which taint-based
rules can't catch by design. The allowlists (`approved_payees`, internal email domain) belong to our fictional
company, so legitimate R-Judge payments and shares after untrusted input are denied; we report this rather than
add R-Judge's accounts to the lists.

## Layout

| Path | What it is |
|---|---|
| `registry/` | Tool labels, the single source of truth. Every `*.yaml` is loaded: `tools.yaml` (our 10 tools, each with a mock), `rjudge.yaml` (R-Judge). Per tool: `tier`, `output_trust`, `args`, and optionally `arg_roles`, `outbound`, `persistent` |
| `policies/` | Rego: `lib` (shared conditions), `static`, `attr`, `context`, `context_attr`, `config/data.json` (roles, `unrestricted_roles`, allowlists and `public_fields`, loaded as `data.config`), `tests/` |
| `schemas/` | JSON Schemas for the PDP input, traces and live tasks |
| `scenarios/custom/` | 45 labeled traces in 7 categories (144 steps, 25 unsafe) |
| `scenarios/memory/` | 5 memory-poisoning traces (3 benign, 2 attacks) |
| `src/authz/interceptor.py` | Fail-closed interceptor. The only code path that runs a tool. |
| `src/authz/tools/executor.py` | `ToolExecutor` interface and `MockToolExecutor`: runs the mock tools, records every executed call per session, and can override tool outputs per task. In replay, registry tools without a mock run on a stub. |
| `src/authz/pdp/` | `NoOpPDP`, `OpaPDP`, and `make_pdp` |
| `src/authz/eval/` | `replay`, `metrics`, `determinism`, `experiments` (E2/E3), `latency` (E1), `judge_compare` (E4), `live` (E5), `task_success`, `rule_ablation` (P5), `tier_ablation` (P6) |
| `src/authz/agent/` | `llm` (Ollama, OpenAI and Anthropic clients over HTTP), `loop` (the tool-calling agent) |
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
