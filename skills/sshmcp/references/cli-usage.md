# sshmcp CLI Usage

## Binary bootstrap

If `sshmcp` is missing, install it before doing any remote action:

```text
powershell -ExecutionPolicy Bypass -File <skill-dir>/scripts/install.ps1
bash <skill-dir>/scripts/install.sh
```

The install scripts download the latest GitHub Release by default and print a JSON object containing the resolved binary path.
Before reinstalling, also check the installer's default target path:

- Windows: `%LOCALAPPDATA%\sshmcp\bin\sshmcp.exe`
- Linux: `$HOME/.local/bin/sshmcp`

On Windows, `install.ps1` also persists the install directory into the user `PATH` for future shells by default. Use the printed `binary_path` immediately, and open a new shell later if `user_path_updated` is `true`.

## Preflight

Use these checks before any remote action:

```text
sshmcp profile validate
sshmcp profile validate <profile>
sshmcp profile list
sshmcp daemon status
sshmcp --version
```

## Common operations

```text
sshmcp exec --agent --profile <profile> -- hostname
sshmcp exec --agent --profile <profile> --cwd /tmp --timeout 30 -- env
sshmcp read --agent --profile <profile> --path /etc/hostname
sshmcp write --agent --profile <profile> --path /tmp/demo.txt --input hello
sshmcp upload --agent --profile <profile> --src ./local.txt --dst /tmp/local.txt
sshmcp download --agent --profile <profile> --src /tmp/local.txt --dst ./local-copy.txt
sshmcp tunnel open --agent --profile <profile> --local 8080 --remote 127.0.0.1:11434
sshmcp session list --agent
sshmcp session inspect --agent --id <session-id>
```

Relative local paths for `upload --src` and `download --dst` are resolved from the CLI caller's current working directory, not the daemon's working directory. Relative `.` and `..` components are normalized. The daemon rejects relative local paths received directly over RPC with `relative_local_path`.

Uploads create remote parent directories and overwrite existing remote files. Downloads create local parent directories and atomically overwrite existing local files after receiving and syncing the complete content. Transfer JSON reports `local_src`/`remote_dst` or `remote_src`/`local_dst`; downloads also report whether an existing file was `overwritten`.

Under MSYS2, set `MSYS2_ARG_CONV_EXCL="*"` on transfer commands. Otherwise MSYS2 may rewrite remote POSIX paths before the CLI can distinguish them from local paths:

```text
MSYS2_ARG_CONV_EXCL="*" sshmcp upload --profile <profile> --src ./local.txt --dst /tmp/local.txt
```

## Windows PowerShell notes

When the local shell is Windows PowerShell, `sshmcp exec --profile ... --` does not prevent PowerShell from parsing the rest of the line first. Complex Unix command lines can fail locally before `sshmcp` receives them.

Prefer these patterns:

```text
sshmcp --% exec --profile <profile> -- sudo -n find /opt /srv /home /root -maxdepth 4 -type f \( -name '*.yml' -o -name '*.yaml' -o -name '*.env' \)
sshmcp exec --profile <profile> -- sudo -n bash -lc 'find /opt /srv /home /root -maxdepth 4 -type f \( -name "*.yml" -o -name "*.yaml" -o -name "*.env" \)'
```

Avoid generating Bash-style escaping directly in raw PowerShell command lines such as:

```text
sshmcp exec --profile <profile> -- sudo -n find /opt /srv /home /root -maxdepth 4 -type f \( -name '*.yml' -o -name '*.yaml' -o -name '*.env' \)
```

unless the command is protected by `--%` or wrapped for a remote shell like `bash -lc`.

## Failure handling

- `sshmcp` command not found: first retry with the default install path for the platform; if it is absent, run the bundled install script for the current platform, then retry with the printed `binary_path`.
- `daemon_unavailable`: the daemon is not listening; retry through a normal command or start the daemon explicitly.
- `config_error`: the profile or auth configuration is invalid; fix the config instead of bypassing the gateway.
- `ssh_error`: SSH transport or remote auth failed; inspect the target profile and bastion chain.
- `agent_error`: the remote helper failed; review remote stderr and try again through the same profile.
- `policy_denied`: the Agent Policy rejected a capability, command, or remote path; do not bypass it with raw SSH.
- For passphrase-protected private keys, store the `passphrase` in the profile auth block and retry through the same profile instead of switching to raw `ssh`.

## Safety reminders

- Do not request raw passwords if the profile is intended to carry auth.
- Do not request raw key passphrases if the profile is intended to carry auth.
- Do not copy private keys into chat history.
- Prefer named profiles and profile reuse over ad-hoc host commands.
