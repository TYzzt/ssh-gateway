# Codex

When a tool returns `status: confirmation_required`, stop and report its ID, summary, risk, and expiry. Never run `ssh-gateway approval approve`, invoke it through a shell, or rewrite the request to evade policy. A human must approve from a non-agent CLI; then inspect the recorded result before continuing. See [Human approval](approval.md).

Use the stable task ID assigned to the current task. After a human creates a task grant, continue normally; never request wildcard scope, extend grants, switch task IDs, or use another task's grant. Agents may propose an ordered Plan, but must never approve or alter it and must execute approved actions in order.

Codex should use the local `ssh-gateway` Skill and CLI. MCP is not required for this workflow.

## Install

Download the Windows or Linux release archive, place `ssh-gateway` on `PATH`, then install the repository Skill:

```text
npx skills add TYzzt/ssh-gateway --skill ssh-gateway
```

Set `ARRT_CONFIG_PATH` to a YAML/TOML profile file, or use the platform default described in the README.

## Agent workflow

Codex should discover named hosts without asking for credentials:

```text
ssh-gateway profile list
ssh-gateway profile validate aliyun
ssh-gateway exec --agent --profile aliyun -- docker ps
ssh-gateway read --agent --profile aliyun --path /etc/nginx/nginx.conf
ssh-gateway write --agent --profile aliyun --path /home/admin/demo --input hello
```

`--agent` can appear before or after the subcommand. It applies the selected profile's `agent_policy`. Without it, existing human CLI behavior is preserved.

Profiles hide host credentials and routing. Codex should select the closest matching profile name and only ask about SSH connection details when no suitable profile exists.

## Policy failures

`policy_denied` means the requested capability, command, or remote path is outside `agent_policy`. Update the profile deliberately; do not bypass the gateway with raw `ssh`.

Agent exec uses exact `allowed_commands` entries. Add the complete command string intentionally; `deny_commands` is rejected because shell text blacklists can be bypassed with quoting and expansion.
