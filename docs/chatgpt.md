# ChatGPT MCP

MCP returns `confirmation_required` as structured content. Tell the user to approve its ID with `ssh-gateway approval approve <id>`. MCP intentionally has no approve/reject tool; do not rewrite and retry the operation. See [Human approval](approval.md).

MCP tool calls do not accept `task_id` from the agent. For bounded task grants and Plans, configure the gateway to inject a stable task ID from an environment variable. `propose_plan` may persist an ordered proposal without executing it; plan and grant approval remain Human CLI-only.

`ssh-gateway` exposes a bearer-authenticated Streamable HTTP MCP endpoint at `/mcp`. It does not use the obsolete ChatGPT Plugin Manifest.

## NAS deployment

Configure profiles and policy in `config/profiles.yaml`, then start the compose service:

```bash
export SSH_GATEWAY_MCP_TOKEN="$(openssl rand -hex 32)"
docker compose up -d --build
curl http://127.0.0.1:8765/health
```

Profile management is disabled by default. To expose `create_profile` and `delete_profile`, use YAML configuration, enable the feature below, and make the bind-mounted directory writable by container UID `10001` so the gateway can atomically replace `profiles.yaml`:

```bash
sudo chown -R 10001:10001 config
```

Restart the MCP service after changing the enablement setting so clients receive the updated tool list. Profile creation and deletion are applied after the MCP client obtains user confirmation; they do not require a second Human CLI approval. YAML comments are not retained after a write.

The process explicitly binds all interfaces inside its network-isolated container, while the published host port remains loopback-only. Publish HTTPS through Cloudflare Tunnel, Tailscale, Caddy, or Nginx; `ssh-gateway` intentionally does not terminate public TLS. Do not bake the token or SSH credentials into the image.

For native Linux, install [the systemd unit](../packaging/systemd/ssh-gateway.service), create `/etc/ssh-gateway/environment` containing `SSH_GATEWAY_MCP_TOKEN=...`, then enable `ssh-gateway.service`. `ssh-gateway serve` runs daemon IPC and MCP against one shared `GatewayService` and session pool.

## Configuration

```yaml
mcp:
  listen: 127.0.0.1:8765
  auth:
    type: bearer
    token_env: SSH_GATEWAY_MCP_TOKEN
  task_id_env: SSH_GATEWAY_TASK_ID
  local_file_root: /data
  allowed_origins:
    - https://gateway.example.com
  profile_management:
    enabled: false
```

`task_id_env` is optional, but `propose_plan` requires it and task-scoped grants only match when it is set. `local_file_root` is required for `upload_file` and `download_file`; both local paths must remain below it. `allowed_origins` is checked only when the client sends an `Origin` header. Bearer authentication is mandatory.

## ChatGPT setup

Expose `/mcp` through an authenticated HTTPS route. In ChatGPT workspace settings, enable developer mode, create a custom MCP app, provide the HTTPS MCP URL and Bearer authentication, then scan tools. Current ChatGPT custom MCP availability and write-action confirmation depend on workspace plan and admin policy.

Available tools: `list_hosts`, `get_profile_policy`, `exec`, `read_file`, `write_file`, `upload_file`, `download_file`, `list_sessions`, `close_session`, and `propose_plan`. When profile management is enabled, `create_profile` and `delete_profile` are also exposed. MCP always applies Agent Policy. `read_file` paginates by byte offset and caps one response at 256 KiB.

`get_profile_policy` accepts an optional profile name and returns complete Agent Policy without SSH credentials. `create_profile` is create-only and rejects duplicate names. `delete_profile` refuses the last profile, referenced profiles, and profiles with active sessions. Profile mutations cannot be converted into grants or plans.

## Security model

Agents see `PublicProfileInfo`, never serialized credential-bearing profiles. Audit records go to stderr/service logs and include request ID, caller, operation, profile, duration, result, and optionally a redacted command. Keep MCP on loopback behind a private tunnel or reverse proxy; rotate the bearer token if service logs or environment access may have been compromised.

Profile credentials are written only to the gateway-owned YAML configuration. MCP responses, errors, and audit logs expose only explicitly credential-redacted details.

Agent commands require an exact `agent_policy.allowed_commands` match; an empty list denies Agent/MCP exec. Restricted file operations validate the opened remote file descriptor against remotely resolved allowed roots, so symlink changes after validation cannot redirect I/O. Use a restricted remote Unix account, filesystem permissions, sudo policy, and containers as additional boundaries.

## References

- [MCP Streamable HTTP transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports)
- [MCP tool specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [OpenAI: developer mode and MCP apps in ChatGPT](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt)
