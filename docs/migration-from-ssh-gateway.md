# Migrating from ssh-gateway

`ssh-gateway` through v0.1.5 continues as **SSHMCP** from v0.2.0. The original GitHub repository, history, tags, releases, issues, and pull requests were transferred to [sshmcp/sshmcp](https://github.com/sshmcp/sshmcp). The SSH transport, session, policy, approval, grant, and plan features continue in SSHMCP.

| Before | From v0.2.0 |
| --- | --- |
| `ssh-gateway` command and Cargo package | `sshmcp` |
| `TYzzt/ssh-gateway` | `sshmcp/sshmcp` |
| `ARRT_CONFIG_PATH` or `SSH_GATEWAY_CONFIG_PATH` | `SSHMCP_CONFIG_PATH` |
| `SSH_GATEWAY_MCP_TOKEN` | `SSHMCP_MCP_TOKEN` |
| `SSH_GATEWAY_TASK_ID` | `SSHMCP_TASK_ID` |
| `skills/ssh-gateway` | `skills/sshmcp` |
| `ssh-gateway.service` | `sshmcp.service` |

New environment names take precedence when both are set. Old names remain accepted for compatibility and are deprecated. No token value is printed by the loader. An explicit `mcp.auth.token_env` or `mcp.task_id_env` using the old name still works and honors the new name when present.

New config files live under `~/.config/sshmcp` on Linux (`$XDG_CONFIG_HOME/sshmcp` when set), or `%APPDATA%\sshmcp\config` on Windows. Data uses `~/.local/share/sshmcp` on Linux and the corresponding Windows application data location. The loader searches the new config directory before the legacy `ssh-gateway` and `arrt` application directories (on Linux, under `$XDG_CONFIG_HOME`). Within each directory it checks `profiles.yaml`, `profiles.yml`, then `profiles.toml`. The data directory uses the legacy location if it already exists and the new location does not. No files are moved or deleted automatically. A custom `SSHMCP_CONFIG_PATH` takes priority over all directories.

Install the new binary and Skill, update service units and environment files, then run `sshmcp profile validate`. Preserve your old config and approval database until you have checked the new installation. SSHMCP is the open-source Core and self-hosted implementation; SSHMCP Cloud is a separate future hosted product.
