pub const REMOTE_BOOTSTRAP: &str = r#"#!/usr/bin/env python3
import base64
import json
import os
import pathlib
import subprocess
import sys

def fail(code, message):
    payload = {
        "ok": False,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "error": {"code": code, "message": message},
    }
    print(json.dumps(payload, ensure_ascii=False))
    sys.exit(0)

def ok(payload):
    payload.setdefault("ok", True)
    payload.setdefault("exit_code", 0)
    payload.setdefault("stdout", "")
    payload.setdefault("stderr", "")
    print(json.dumps(payload, ensure_ascii=False))
    sys.exit(0)

if len(sys.argv) < 3:
    fail("invalid_argument", "expected mode and payload")

mode = sys.argv[1]
payload = json.loads(base64.b64decode(sys.argv[2]).decode("utf-8"))

if mode == "exec":
    env = os.environ.copy()
    env.update(payload.get("env", {}))
    cwd = payload.get("cwd")
    timeout = payload.get("timeout_seconds")
    try:
        result = subprocess.run(
            payload["command"],
            shell=True,
            cwd=cwd,
            env=env,
            timeout=timeout,
            capture_output=True,
            text=True,
        )
    except subprocess.TimeoutExpired as exc:
        ok({
            "ok": False,
            "exit_code": 124,
            "stdout": exc.stdout or "",
            "stderr": (exc.stderr or "") + "\ncommand timed out",
            "error": {"code": "command_timeout", "message": "remote command timed out"},
        })
    ok({
        "ok": result.returncode == 0,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "error": None if result.returncode == 0 else {"code": "command_failed", "message": f"remote command exited with {result.returncode}"},
    })

elif mode == "read":
    path = pathlib.Path(payload["path"])
    data = path.read_bytes()
    ok({
        "data": {
            "content_b64": base64.b64encode(data).decode("ascii"),
            "size_bytes": len(data),
        }
    })

elif mode == "write":
    path = pathlib.Path(payload["path"])
    content = sys.stdin.buffer.read()
    mode_name = payload["mode"]
    if mode_name == "create":
        flags = "xb"
    elif mode_name == "append":
        flags = "ab"
    else:
        flags = "wb"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, flags) as fh:
        fh.write(content)
    ok({"data": {"bytes_written": len(content)}})

else:
    fail("invalid_argument", f"unknown mode: {mode}")
"#;

