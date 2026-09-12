# ChatGPT MCP

`ssh-gateway` exposes a bearer-authenticated Streamable HTTP MCP endpoint at `/mcp`. It does not use the obsolete ChatGPT Plugin Manifest.

## NAS deployment

Configure profiles and policy in `config/profiles.yaml`, then start the compose service:

```bash
export SSH_GATEWAY_MCP_TOKEN="$(openssl rand -hex 32)"
docker compose up -d --build
curl http://127.0.0.1:8765/health
```

The process explicitly binds all interfaces inside its network-isolated container, while the published host port remains loopback-only. Publish HTTPS through Cloudflare Tunnel, Tailscale, Caddy, or Nginx; `ssh-gateway` intentionally does not terminate public TLS. Do not bake the token or SSH credentials into the image.

For native Linux, install [the systemd unit](../packaging/systemd/ssh-gateway.service), create `/etc/ssh-gateway/environment` containing `SSH_GATEWAY_MCP_TOKEN=...`, then enable `ssh-gateway.service`. `ssh-gateway serve` runs daemon IPC and MCP against one shared `GatewayService` and session pool.

## Configuration

```yaml
mcp:
  listen: 127.0.0.1:8765
  auth:
    type: bearer
    token_env: SSH_GATEWAY_MCP_TOKEN
  local_file_root: /data
  allowed_origins:
    - https://gateway.example.com
```

`local_file_root` is required for `upload_file` and `download_file`; both local paths must remain below it. `allowed_origins` is checked only when the client sends an `Origin` header. Bearer authentication is mandatory.

## ChatGPT setup

Expose `/mcp` through an authenticated HTTPS route. In ChatGPT workspace settings, enable developer mode, create a custom MCP app, provide the HTTPS MCP URL and Bearer authentication, then scan tools. Current ChatGPT custom MCP availability and write-action confirmation depend on workspace plan and admin policy.

Available tools: `list_hosts`, `exec`, `read_file`, `write_file`, `upload_file`, `download_file`, `list_sessions`, and `close_session`. MCP always applies Agent Policy. `read_file` paginates by byte offset and caps one response at 256 KiB.

## Security model

Agents see `PublicProfileInfo`, never serialized credential-bearing profiles. Audit records go to stderr/service logs and include request ID, caller, operation, profile, duration, result, and optionally a redacted command. Keep MCP on loopback behind a private tunnel or reverse proxy; rotate the bearer token if service logs or environment access may have been compromised.

Agent commands require an exact `agent_policy.allowed_commands` match; an empty list denies Agent/MCP exec. Restricted file operations validate the opened remote file descriptor against remotely resolved allowed roots, so symlink changes after validation cannot redirect I/O. Use a restricted remote Unix account, filesystem permissions, sudo policy, and containers as additional boundaries.

## References

- [MCP Streamable HTTP transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports)
- [MCP tool specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [OpenAI: developer mode and MCP apps in ChatGPT](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt)
