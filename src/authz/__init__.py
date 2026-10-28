"""Agent AuthZ: context-aware authorization for LLM agent tool calls."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = REPO_ROOT / "registry" / "tools.yaml"
POLICIES_DIR = REPO_ROOT / "policies"
SCHEMAS_DIR = REPO_ROOT / "schemas"
