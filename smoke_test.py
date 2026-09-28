"""Real-server smoke test: boots uvicorn in a thread and exercises HTTP."""
import json
import threading
import time
import urllib.request

import uvicorn

from app.app import create_app

BASE = "http://127.0.0.1:8765"


def req(method, path, body=None, token=None, raw_auth=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    if data:
        r.add_header("content-type", "application/json")
    if raw_auth is not None:
        r.add_header("authorization", raw_auth)
    elif token:
        r.add_header("authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


config = uvicorn.Config(create_app(), host="127.0.0.1", port=8765, log_level="warning")
server = uvicorn.Server(config)
t = threading.Thread(target=server.run, daemon=True)
t.start()
for _ in range(50):
    try:
        urllib.request.urlopen(BASE + "/health")
        break
    except Exception:
        time.sleep(0.1)

assert req("GET", "/health")[0] == 200
tokens = req("GET", "/api/v1/local/tokens")[1]["tokens"]
alice, bob = tokens["alice"], tokens["bob"]

code, body = req("POST", "/api/v1/leases", {"secret_name": "db/password", "ttl_seconds": 60})
assert code == 401 and body["error"]["reason"] == "missing_credential", body

code, body = req("POST", "/api/v1/leases", {"secret_name": "db/password", "ttl_seconds": 60},
                 raw_auth="Bearer garbage")
assert code == 401 and body["error"]["reason"] == "forged_credential", body

code, body = req("POST", "/api/v1/leases", {"secret_name": "db/password", "ttl_seconds": 60}, token=bob)
assert code == 403 and body["error"]["reason"] == "unauthorized_scope", body

code, lease = req("POST", "/api/v1/leases", {"secret_name": "db/password", "ttl_seconds": 60},
                  token=alice)
assert code == 201 and lease["version"] == 1
lid = lease["lease_id"]

code, got = req("GET", f"/api/v1/leases/{lid}/secret", token=alice)
assert code == 200 and got["value"] == "db-password-v1", got

print("REAL-SERVER SMOKE TEST PASSED")
server.should_exit = True
time.sleep(0.2)
import os
os._exit(0)  # avoid reaping the uvicorn daemon thread during interpreter teardown
