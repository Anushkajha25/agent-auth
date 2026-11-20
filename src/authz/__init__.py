"""Agent AuthZ: context-aware authorization for LLM agent tool calls."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = REPO_ROOT / "registry"  # every *.yaml in here is loaded
REGISTRY_PATH = REGISTRY_DIR / "tools.yaml"  # the core tools (the ones with mock implementations)
POLICIES_DIR = REPO_ROOT / "policies"
SCHEMAS_DIR = REPO_ROOT / "schemas"
