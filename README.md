# Agent Auth

Context-aware authorization for LLM agent tool calls. Every tool call goes through an
interceptor, which asks a policy decision point (PDP) to allow or deny it. The decision can
depend on the session history as well as the agent's role.

```
labeled traces → interceptor → PDP (noop | OPA static | OPA context) → JSONL decision log → metrics
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

# Replay the 5 traces under all three PDPs
.venv/bin/python -m authz.eval.replay --pdp all --traces scenarios/custom --out results/

# Re-check every logged decision 5 times
.venv/bin/python -m authz.eval.determinism --log results/<run_id>/decisions.jsonl --runs 5

# Everything, including the OPA integration test
.venv/bin/pytest
```

## Expected results

| PDP | Violation rate | False positive rate |
|---|---|---|
| noop | 3/3 (100%) | 0/10 |
| static | 2/3 (67%), misses t002 and t005 | 0/10 |
| context | 0/3 (0%) | 0/10 |

## Layout

| Path | What it is |
|---|---|
| `registry/tools.yaml` | Tool labels (tier, output trust). The single source of truth. |
| `policies/` | Rego: `lib`, `static` (role allowlist), `context` (role + history taint), `config/data.json` (role map, loaded as `data.config`), `tests/` |
| `schemas/` | JSON Schemas for the PDP input and for traces |
| `scenarios/custom/` | The 5 labeled traces (13 steps, 3 unsafe) |
| `src/authz/interceptor.py` | Fail-closed interceptor. The only caller of the mock tools. |
| `src/authz/pdp/` | `NoOpPDP`, `OpaPDP`, and `make_pdp` |
| `src/authz/eval/` | `replay`, `metrics`, `determinism` |
| `results/` | Run outputs (gitignored) |

## Design notes

- **Fail closed.** If the PDP raises or times out (500 ms), the call is denied with `pdp_unavailable`. A tool that isn't in the registry is denied with `unknown_tool`. With `--validate-input`, input that fails the schema is denied with `invalid_input`. The PDP isn't called in either case.
- **Taint rule.** `context` denies an `irreversible` action once any *allowed* untrusted-output tool has run in the session. A denied untrusted read produced no content, so it doesn't taint the session.
- **Reproducibility.** Each log line records `input_sha256`, which is a hash of canonical JSON, and `policy_sha256`, which hashes every `.rego` file plus `config/data.json`. The determinism check refuses to run if the policies have changed since the log was written.
- **OPA policy check.** OPA runs with `--watch`. Before using OPA, `replay` and `determinism` check that OPA has the same policies and data as the files on disk, and stop if they don't. This keeps `policy_sha256` in the log accurate.
- **No non-deterministic built-ins.** A pytest test fails if any `.rego` file uses `http.send`, `time.*`, `rand.*`, `uuid.*`, `net.*` or `opa.runtime`.
