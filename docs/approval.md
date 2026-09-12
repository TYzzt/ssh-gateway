# Human approval

Agent policy rules return `allow`, `confirm`, or `deny`. `risk` is metadata only; `effect` controls execution.

```yaml
approval:
  enabled: true
  ttl_seconds: 300
  storage: { type: sqlite, path: /data/approvals.db }
profiles:
  - name: production
    agent_policy:
      rules:
        - id: service-status
          match: { operation: exec, commands: ["systemctl status *"] }
          effect: allow
          risk: low
        - id: service-restart
          match: { operation: exec, commands: ["systemctl restart *"] }
          effect: confirm
          risk: medium
        - id: no-reboot
          match: { operation: exec, commands: ["reboot", "shutdown *"] }
          effect: deny
          risk: critical
        - id: nginx-write
          match: { operation: write, paths: ["/etc/nginx/**"] }
          effect: confirm
          risk: high
```

Rules run in order after capabilities and existing safety checks. With no rules, legacy exact `allowed_commands` and path behavior remains unchanged. An unmatched request in a non-empty ruleset is denied. Shell wrappers are not unwrapped; broad wrapper rules should not be used.

## Workflow

MCP returns `{"status":"confirmation_required","approval":{"id":"apr_...","profile":"production","operation":"exec","summary":"systemctl restart nginx","risk":"medium","expires_at":1780000000}}`. The agent must stop. A human then uses:

```console
ssh-gateway approval list
ssh-gateway approval show apr_...
ssh-gateway approval approve apr_...
```

Approval atomically claims the pending row, verifies its SHA-256 request hash, reruns policy and path safety checks, and executes the frozen request once. `approval reject` rejects it; `approval cleanup` removes terminal rows. `ssh-gateway --agent approval ...` is denied, and MCP exposes no approve/reject tools.

Write approvals bind encoded content. Upload approvals also bind the current local file bytes, so a changed source is rejected. Remote file operations rerun remote real-path enforcement at execution to protect against symlink changes. List/show/MCP expose redacted metadata, never stored payload.

SQLite WAL and conditional state changes provide concurrency safety and restart persistence. For Docker use `/data/approvals.db`. The packaged systemd unit makes `/var/lib/ssh-gateway` writable; use `/var/lib/ssh-gateway/approvals.db` owned by `ssh-gateway`. If approval storage is disabled or unavailable, confirmation fails closed.
