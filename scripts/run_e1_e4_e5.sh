#!/usr/bin/env bash
# Runs the system experiments end to end: E1 (latency), E4 (Rego L4 vs. the LLM judge and
# Llama Guard), E5 (live agent: the worst-case scripted agent, then a real model).
#
#   scripts/run_e1_e4_e5.sh smoke    # ~10 min: tiny version of every step, to catch setup problems
#   scripts/run_e1_e4_e5.sh full     # the real runs (hours on a laptop; leave it plugged in)
#
# Needs: OPA running with the current policies (docker compose up -d), Ollama running with the
# agent and guard models pulled. Override with AGENT_MODEL, GUARD_MODEL, OLLAMA_URL, OPA_URL.
# E4_EXTERNAL=1 also runs E4 on R-Judge and ToolEmu (many more judge calls).
# Everything goes to results/final-<mode>-<time>/, with run.log and environment.txt.
set -euo pipefail

MODE="${1:-}"
if [ "$MODE" != "smoke" ] && [ "$MODE" != "full" ]; then
  echo "usage: $0 smoke|full" >&2
  exit 2
fi

cd "$(dirname "$0")/.."
AGENT_MODEL="${AGENT_MODEL:-qwen3:8b}"
GUARD_MODEL="${GUARD_MODEL:-llama-guard3:8b}"
OPA_URL="${OPA_URL:-http://localhost:8181}"
OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434/v1}"
export OPA_URL OLLAMA_URL
OLLAMA_BASE="${OLLAMA_URL%/}"
OLLAMA_BASE="${OLLAMA_BASE%/v1}"

if [ -x .venv/bin/python ]; then PY=.venv/bin/python; else PY=python3; fi
OUT="results/final-${MODE}-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
LOG="$OUT/run.log"

say() { printf '\n=== %s  [%s]\n' "$1" "$(date +%H:%M:%S)" | tee -a "$LOG"; }
fail() { echo "ERROR: $1" | tee -a "$LOG" >&2; exit 1; }
run() { echo "+ $*" >>"$LOG"; "$@" 2>&1 | tee -a "$LOG"; }

# ---------- preflight ----------
say "Preflight"
"$PY" -c "import authz" 2>/dev/null || fail "the project isn't installed: run  pip install -e '.[dev]'  in your venv"
curl -fsS -m 3 "$OPA_URL/health" >/dev/null || fail "OPA isn't reachable at $OPA_URL (run: docker compose up -d)"
"$PY" - <<'PYEOF' || fail "OPA is serving different policies than policies/ (restart it: docker compose restart)"
import os
from authz.pdp.opa_sync import verify_opa_policies
verify_opa_policies(os.environ["OPA_URL"])
PYEOF
TAGS="$(curl -fsS -m 5 "$OLLAMA_BASE/api/tags")" || fail "Ollama isn't reachable at $OLLAMA_BASE (open the Ollama app or run: ollama serve)"
for m in "$AGENT_MODEL" "$GUARD_MODEL"; do
  case "$TAGS" in
    *"\"$m\""*) ;;
    *) fail "Ollama doesn't have $m yet (run: ollama pull $m)" ;;
  esac
done
echo "OPA, policies, Ollama and both models are ready." | tee -a "$LOG"

{
  echo "mode: $MODE"
  echo "date: $(date)"
  echo "git commit: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "git status: $(git status --porcelain 2>/dev/null | wc -l | tr -d ' ') uncommitted change(s)"
  echo "policy_sha256: $("$PY" -c 'from authz import POLICIES_DIR; from authz.hashing import policy_sha256; print(policy_sha256(POLICIES_DIR))')"
  echo "python: $("$PY" --version 2>&1)"
  echo "os: $(uname -srm)"
  echo "machine: $( (sysctl -n machdep.cpu.brand_string 2>/dev/null || grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2) | sed 's/^ *//')"
  echo "agent model: $AGENT_MODEL"
  echo "guard model: $GUARD_MODEL"
  echo "ollama models: $TAGS"
} >"$OUT/environment.txt"

if [ "$MODE" = "smoke" ]; then
  E1_ARGS="--n 50 --warmup 10 --history 0,10"
  E4_ARGS="--runs 2 --limit 2"
  E5_ARGS="--only l01_refund_known_customer,l07_email_injection_transfer --conditions L0,L4,guard"
else
  E1_ARGS=""
  E4_ARGS="--runs 5"
  E5_ARGS="--conditions L0,L1,L3,L4,guard"
fi

# ---------- E1 ----------
say "E1: latency (no LLM)"
run "$PY" -m authz.eval.latency --out "$OUT/e1" $E1_ARGS

# ---------- E4 ----------
say "E4: L4 vs LLM judge ($AGENT_MODEL) and Llama Guard ($GUARD_MODEL), custom suite"
run "$PY" -m authz.eval.judge_compare --judge both --provider ollama --model "$AGENT_MODEL" \
  --guard-model "$GUARD_MODEL" --traces scenarios/custom --out "$OUT/e4-custom" $E4_ARGS
if [ "${E4_EXTERNAL:-0}" = "1" ]; then
  for d in rjudge toolemu; do
    say "E4 on $d"
    run "$PY" -m authz.eval.judge_compare --judge both --provider ollama --model "$AGENT_MODEL" \
      --guard-model "$GUARD_MODEL" --traces "scenarios/$d" --out "$OUT/e4-$d" $E4_ARGS
  done
fi

# ---------- E5 ----------
say "E5a: worst-case agent (always follows the injection), every level"
run "$PY" -m authz.eval.live --provider scripted --conditions L0,L1,L2,L3,L4 --out "$OUT/e5-worst-case" --no-plots

say "E5b: real agent ($AGENT_MODEL)"
run "$PY" -m authz.eval.live --provider ollama --model "$AGENT_MODEL" --guard-model "$GUARD_MODEL" \
  --seeds 1 --out "$OUT/e5-live" $E5_ARGS

say "Done"
{
  echo "Results are in $OUT:"
  find "$OUT" -name results.md | sort | sed 's/^/  /'
  echo "Send the whole $OUT folder (zip it) for the write-up."
} | tee -a "$LOG"
