# ssh-gateway CLI Usage

## Binary bootstrap

If `ssh-gateway` is missing, install it before doing any remote action:

```text
powershell -ExecutionPolicy Bypass -File <skill-dir>/scripts/install.ps1
bash <skill-dir>/scripts/install.sh
```

The install scripts download the latest GitHub Release by default and print a JSON object containing the resolved binary path.

## Preflight

Use these checks before any remote action:

```text
ssh-gateway profile validate
ssh-gateway profile validate <profile>
ssh-gateway daemon status
```

## Common operations

```text
ssh-gateway exec --profile <profile> -- hostname
ssh-gateway exec --profile <profile> --cwd /tmp --timeout 30 -- env
ssh-gateway read --profile <profile> --path /etc/hostname
ssh-gateway write --profile <profile> --path /tmp/demo.txt --input hello
ssh-gateway upload --profile <profile> --src ./local.txt --dst /tmp/local.txt
ssh-gateway download --profile <profile> --src /tmp/local.txt --dst ./local-copy.txt
ssh-gateway tunnel open --profile <profile> --local 8080 --remote 127.0.0.1:11434
ssh-gateway session list
ssh-gateway session inspect --id <session-id>
```

## Failure handling

- `ssh-gateway` command not found: run the bundled install script for the current platform, then retry with the installed binary path.
- `daemon_unavailable`: the daemon is not listening; retry through a normal command or start the daemon explicitly.
- `config_error`: the profile or auth configuration is invalid; fix the config instead of bypassing the gateway.
- `ssh_error`: SSH transport or remote auth failed; inspect the target profile and bastion chain.
- `agent_error`: the remote helper failed; review remote stderr and try again through the same profile.

## Safety reminders

- Do not request raw passwords if the profile is intended to carry auth.
- Do not copy private keys into chat history.
- Prefer named profiles and profile reuse over ad-hoc host commands.
