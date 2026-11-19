"""The E5 command with --provider ollama, against a fake Ollama server on localhost."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from authz.eval import live


class FakeOllama(BaseHTTPRequestHandler):
    requests: list[dict] = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeOllama.requests.append({"path": self.path, "body": body})
        n_tool_msgs = sum(m["role"] == "tool" for m in body["messages"])
        script = [("read_customer_db", {"customer_id": "C-1001"}),
                  ("transfer_funds", {"to_account": "ACCT-C-1001", "amount": 250})]
        if n_tool_msgs < len(script):
            name, args = script[n_tool_msgs]
            msg = {"role": "assistant", "content": "", "tool_calls": [
                {"id": f"call_{n_tool_msgs}", "type": "function",
                 "function": {"name": name, "arguments": json.dumps(args)}}]}
        else:
            msg = {"role": "assistant", "content": "Refunded $250 to ACCT-C-1001."}
        out = json.dumps({"choices": [{"message": msg}],
                          "usage": {"prompt_tokens": 100, "completion_tokens": 20}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def test_e5_cli_with_ollama(tmp_path, monkeypatch):
    server = HTTPServer(("127.0.0.1", 0), FakeOllama)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("OLLAMA_URL", f"http://127.0.0.1:{server.server_port}/v1")
    for k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    FakeOllama.requests.clear()
    try:
        rc = live.main(["--provider", "ollama", "--model", "qwen2.5:7b", "--conditions", "L0",
                        "--only", "l01_refund_known_customer", "--seeds", "1", "--out", str(tmp_path),
                        "--no-plots"])
    finally:
        server.shutdown()
    assert rc == 0
    (run_dir,) = tmp_path.iterdir()
    summary = json.loads((run_dir / "summary.json").read_text())
    assert summary["L0"]["benign_task_success"] == {"count": 1, "total": 1}
    first = FakeOllama.requests[0]
    assert first["path"] == "/v1/chat/completions"
    assert first["body"]["model"] == "qwen2.5:7b" and first["body"]["temperature"] == 0
    assert {t["function"]["name"] for t in first["body"]["tools"]} >= {"transfer_funds", "read_customer_db"}
