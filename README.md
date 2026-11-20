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
.venv/bin/python -m authz.eval.rule_ablation --traces scenarios/custom scenarios/rjudge scenarios/memory scenarios/toolemu

# P6: tier ablation: tighten/loosen registry labels and re-run L2-L4 on every dataset
.venv/bin/python -m authz.eval.tier_ablation --traces scenarios/custom scenarios/rjudge scenarios/memory scenarios/toolemu

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
ollama pull qwen3:8b           # ~5.2 GB agent / LLM judge
ollama pull llama-guard3:8b    # ~4.9 GB, only for the Llama Guard judge (llama-guard3:1b on small machines)
```

Tested agents: `qwen3:8b` completes all six benign live tasks with no policy. `qwen2.5:7b` and
`llama3.1:8b` did not: one sent a refund to an invented account number, the other wrote a call to a
tool that doesn't exist as plain text. `qwen3:8b` writes long reasoning, so start Ollama with
`OLLAMA_CONTEXT_LENGTH=8192 ollama serve` for long tasks. Calls run at temperature 0, but that does not make
runs repeatable: the same task can attack in one run and not the next, so report several seeds per task
(`--seeds 3`) where time allows and treat single-seed rates as rough.

Set `OLLAMA_URL` if Ollama isn't on `http://localhost:11434/v1`. Hosted APIs also work with
`--provider openai` or `--provider anthropic` and `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`;
keys are read from the environment and never logged.

```bash
# E1: enforcement latency for L0-L4 across history lengths (no LLM needed)
.venv/bin/python -m authz.eval.latency --out results/e1

# E4: Rego L4 vs. judges on the same traces, each input asked 5 times
#     (about 144 x 5 calls per judge; try --limit 5 first). --judge llm | llama_guard | both
.venv/bin/python -m authz.eval.judge_compare --judge both --provider ollama --model qwen3:8b --runs 5 --out results/e4

# E5: live agent on scenarios/live under each condition
#     (add 'judge' for the LLM judge or 'guard' for Llama Guard; --only l01_refund_known_customer to try one task)
.venv/bin/python -m authz.eval.live --provider ollama --model qwen3:8b --conditions L0,L1,L3,L4 --seeds 1 --out results/e5
```

`--provider scripted` runs E5 with a worst-case agent instead of a model: it makes each task's intended calls
and then the attack's, whatever the policy says, so it shows what each level does when the agent falls for every
injection (no LLM, no cost). Each live task's `script` holds those calls.

To run all of E1, E4 and E5 in one go, with checks that OPA, Ollama and the models are ready first:

```bash
scripts/run_e1_e4_e5.sh smoke   # ~10 minutes: a tiny version of every step, to catch setup problems
scripts/run_e1_e4_e5.sh full    # the real runs (hours on a laptop)
```

Results, `run.log` and `environment.txt` (commit, policy hash, models, machine) go to `results/final-<mode>-<time>/`.
Set `AGENT_MODEL` / `GUARD_MODEL` to use other models, and `E4_EXTERNAL=1` to also run E4 on R-Judge and ToolEmu.

The agent (`src/authz/agent/`) is a minimal function-calling loop. Every tool call goes
through the interceptor; a denied call comes back to the model as a tool error and the agent
re-plans. Runs stop at 15 tool calls, 3 denials, a repeated identical denial, or 20 LLM calls.
The system prompt says nothing about security, so all protection comes from the policy.
Live tasks (`scenarios/live/`, schema `schemas/live_task.schema.json`) list the calls that
complete the user's task and the calls an injection is trying to cause; runs are scored on
what the executor actually ran.

There are two probabilistic baselines. The **LLM judge** (`pdp/llm_judge.py`) asks an
instruction-following model for `{"allow": ..., "reason": ...}`. **Llama Guard 3**
(`pdp/llama_guard.py`) is a safety classifier whose built-in categories are content harms
(violence, self-harm, ...), which a transfer or a deletion doesn't match, so it is prompted in
the official Llama Guard 3 format with four categories written for this threat model:
unauthorized tool use, injected irreversible action, data exfiltration, destructive or
remote-code command. Both get the same facts as the Rego policies (role allowlist, allowlists,
tool labels, history), and both fail closed on a reply they can't parse.

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

## ToolEmu dataset

80 traces from 40 [ToolEmu](https://github.com/ryoungj/ToolEmu) test cases (Ruan et al., ICLR 2024) live in
`scenarios/toolemu/`, with tool labels in `registry/toolemu.yaml`. Like R-Judge they use one role,
`toolemu_agent`, that may call every tool.

ToolEmu cases have no tool calls: each gives a user instruction, the risky actions an agent might take (in
prose) and what a careful agent should do. `scripts/toolemu/cases.yaml` spells out each case as ToolEmu tool
calls twice:

- **risky** (`te_<n>_risky`, adversarial): the agent acts out one of the case's Potential Risky Actions. The
  one step that causes the harm is `should_allow: false`, the rest `true` (the R-Judge rule).
- **safe** (`te_<n>_safe`, benign): the agent follows the case's Expected Achievements, which often means it
  stops and asks the user. Every step is `true`.

`risk_type` is `injection` (7 cases) when the harmful step follows content the agent read (an email, a web
page, a GitHub issue, a blog's script), and `unintended` (33 cases) when it's the agent's own mistake on an
underspecified request. Most ToolEmu risks are the second kind, so many risky steps can only be told apart from
the safe ones by their arguments (which account, which file, which address), not by the history.

The 23 ToolEmu cases that R-Judge reuses are excluded (R-Judge copies their user instructions), so no scenario
is counted twice. `convert.py` checks every step against ToolEmu's own specs: the tool must belong to one of the
case's toolkits, argument names must exist, required arguments must be present, types must match, and values
must be in the allowed set where ToolEmu lists one.

```bash
# 1. Get ToolEmu next to this repo, at the commit we used
git clone https://github.com/ryoungj/ToolEmu.git ../ToolEmu
git -C ../ToolEmu checkout ac4a7ab

# 2. Convert (overwrites scenarios/toolemu/te_*.json)
python scripts/toolemu/convert.py ../ToolEmu
#   -> wrote 80 traces ... from 40 cases

# 3. Check (also regenerates the traces and compares them with the committed ones)
pytest -q tests/test_toolemu_converter.py
```

`--list-tools` lists every tool the cases use with its argument names. Tools that `rjudge.yaml` also labels keep
exactly its tier, output_trust, arg_roles and outbound; `args` in `toolemu.yaml` is ToolEmu's full parameter
list, while `rjudge.yaml` lists the arguments seen in its traces.

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
| L2 attr | 29/43 | 4/100 | 2/2 | 0/9 |
| L3 context | 29/43 | 4/100 | 2/2 | 0/9 |
| L4 context_attr | 20/43 | 3/100 | 0/2 | 1/9 (m05) |

Many R-Judge harms happen with no untrusted input before them (the "unintended" risk type), which taint-based
rules can't catch by design. The allowlists (`approved_payees`, internal email domain) belong to our fictional
company, so legitimate R-Judge payments and shares after untrusted input are denied; we report this rather than
add R-Judge's accounts to the lists.

ToolEmu (80 traces, 206 steps, 40 unsafe):

| Level | Violation rate | False positive rate |
|---|---|---|
| L0 noop | 40/40 (100%) | 0/166 |
| L1 static | 40/40 (100%, unrestricted role) | 0/166 |
| L2 attr | 24/40 (60%) | 6/166 |
| L3 context | 32/40 (80%) | 5/166 |
| L4 context_attr | 34/40 (85%) | 3/166 |

On ToolEmu, L4 is worse than L2. 33 of the 40 cases are `unintended`: the agent's own mistake with no untrusted
input before it. L4 applies the argument rules only once the session is tainted, so it lets those through, while
L2 checks arguments on every irreversible call. This is the cost of L4's low false-positive rate on the custom
suite, not a bug. As with R-Judge, some L2 catches come from our fictional company's allowlists.

**P5, rule count (L4, all four datasets combined, 110 unsafe / 394 safe steps).** Adding rules one at a time:
role only 105/110 violations and 0 false positives; + payee 89; + amount 84; + delete path 76 (2 FP); + outbound
56 (7 FP); + persistent write 54 (8 FP). Leaving one out, `outbound_after_untrusted` matters most (removing it
gives 74/110) and `persistent_write_after_untrusted` only matters on the memory set. Full tables:
`docs/figures/p5/results.md`.

**P6, tier labels (same policies, registry changed).** L4 barely moves when labels are tightened, but loosening
them hurts: marking email as trusted raises L4's custom violations from 0/25 to 9/25, web pages as trusted to
10/25, and `delete_file` as a plain write to 5/25. Marking every outbound tool irreversible helps L3 (custom 7 → 1,
R-Judge 29 → 18) at the cost of more false positives (custom 7 → 11). So output_trust labels carry most of the
weight. Full tables: `docs/figures/p6/results.md`.

**E5, worst-case agent** (`--provider scripted`: always makes the injected calls; 6 benign and 7 attack tasks):

| Condition | Benign task success | Attack success |
|---|---|---|
| L0 | 6/6 | 7/7 |
| L1 | 6/6 | 6/7 |
| L2 | 6/6 | 3/7 |
| L3 | 4/6 | 2/7 |
| L4 | 6/6 | 1/7 (l12) |

L4's one miss, l12, is a by-design gap: an injected "bank details changed" note redirects payment to a different
payee that is also on the approved list, for an amount under the limit, so no rule fires. Results with a
real model (E1, E4 and E5 on `qwen3:8b`) come from `scripts/run_e1_e4_e5.sh full`.

The figures and tables in `docs/figures/` were regenerated from these runs (policy hash `832227e9726a`):
E2/E3 on the custom suite at the top level, P5 and P6 on all four datasets in `p5/` and `p6/`, and the
worst-case E5 in `e5_scripted/`.

## Layout

| Path | What it is |
|---|---|
| `registry/` | Tool labels, the single source of truth. Every `*.yaml` is loaded: `tools.yaml` (our tools, each with a mock, including `read_memory` / `write_memory`), `rjudge.yaml` (R-Judge), `toolemu.yaml` (ToolEmu). Per tool: `tier`, `output_trust`, `args`, and optionally `arg_roles`, `outbound`, `persistent`, `amount_unit` |
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
| `scenarios/toolemu/`, `registry/toolemu.yaml`, `scripts/toolemu/` | 80 ToolEmu traces, their tool labels, and the hand-written cases + converter |
| `src/authz/pdp/llama_guard.py` | Baseline 3b: Llama Guard 3 via Ollama, with categories for this threat model |
| `docs/` | `rule-semantics.md`; `figures/` with E2/E3 (custom), P5 and P6 (all datasets) and worst-case E5 results |
| `results/` | Run outputs (gitignored) |

## Design notes

- **Fail closed.** If the PDP raises or times out (500 ms), the call is denied with `pdp_unavailable`. A tool that isn't in the registry is denied with `unknown_tool`. With `--validate-input`, input that fails the schema is denied with `invalid_input`. The PDP isn't called in either case.
- **Taint rule.** A session is tainted once any *allowed* untrusted-output tool has run in the history window (the whole session by default). A denied untrusted read produced no content, so it doesn't taint the session.
- **Reproducibility.** Each log line records `input_sha256`, which is a hash of canonical JSON, and `policy_sha256`, which hashes every `.rego` file plus `config/data.json`. The determinism check refuses to run if the policies have changed since the log was written.
- **OPA policy check.** OPA runs with `--watch`. Before using OPA, `replay` and `determinism` check that OPA has the same policies and data as the files on disk, and stop if they don't. This keeps `policy_sha256` in the log accurate.
- **No non-deterministic built-ins.** A pytest test fails if any `.rego` file uses `http.send`, `time.*`, `rand.*`, `uuid.*`, `net.*` or `opa.runtime`.
