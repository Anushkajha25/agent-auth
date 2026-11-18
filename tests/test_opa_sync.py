import shutil
import subprocess
import socket
import time

import pytest
import requests

from authz import POLICIES_DIR
from authz.pdp.opa_sync import PolicyMismatch, diff_opa_policies, verify_opa_policies

pytestmark = pytest.mark.opa

OPA_BIN = shutil.which("opa")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def private_opa(tmp_path):
    if not OPA_BIN:
        pytest.skip("opa binary not on PATH")
    pol = tmp_path / "policies"
    shutil.copytree(POLICIES_DIR, pol)
    port = free_port()
    proc = subprocess.Popen([OPA_BIN, "run", "--server", "--addr", f"127.0.0.1:{port}", str(pol)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            requests.get(f"{url}/health", timeout=0.2).raise_for_status()
            break
        except requests.RequestException:
            time.sleep(0.1)
    yield url, pol
    proc.terminate()
    proc.wait()


def test_matches_when_unchanged(private_opa):
    url, pol = private_opa
    assert diff_opa_policies(url, pol) == []
    verify_opa_policies(url, pol)


def test_detects_edited_rego(private_opa):
    url, pol = private_opa
    f = pol / "context" / "context.rego"
    f.write_text(f.read_text() + "\n# edited\n")
    assert diff_opa_policies(url, pol) == ["context/context.rego: OPA has a different version"]
    with pytest.raises(PolicyMismatch):
        verify_opa_policies(url, pol)


def test_detects_changed_data(private_opa):
    url, pol = private_opa
    (pol / "config" / "data.json").write_text('{"roles": {}}')
    assert diff_opa_policies(url, pol) == ["config/data.json: OPA has different data"]


def test_detects_new_file_not_loaded(private_opa):
    url, pol = private_opa
    (pol / "extra.rego").write_text("package extra\n")
    assert "extra.rego: not loaded in OPA" in diff_opa_policies(url, pol)
