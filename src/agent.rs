pub fn expected_version(version: &str) -> String {
    let base = if version.trim().is_empty() {
        env!("CARGO_PKG_VERSION").to_string()
    } else {
        version.to_string()
    };
    format!("{base}+policy-fd-v1")
}

pub fn render_agent_script(version: &str) -> String {
    format!(
        r#"#!/bin/sh
set -eu
SSHMCPD_VERSION='{version}'

quote_sh() {{
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}}

decode_b64() {{
  if command -v base64 >/dev/null 2>&1; then
    printf '%s' "$1" | base64 -d
  elif command -v openssl >/dev/null 2>&1; then
    printf '%s' "$1" | openssl base64 -d -A
  else
    echo "base64 decoder missing" >&2
    return 127
  fi
}}

encode_file_b64() {{
  if command -v base64 >/dev/null 2>&1; then
    base64 < "$1" | tr -d '\n'
  elif command -v openssl >/dev/null 2>&1; then
    openssl base64 -A < "$1"
  else
    echo "base64 encoder missing" >&2
    return 127
  fi
}}

emit_result() {{
  code="$1"
  stdout_file="$2"
  stderr_file="$3"
  printf '%s\n' "$code"
  encode_file_b64 "$stdout_file"
  printf '\n'
  encode_file_b64 "$stderr_file"
  printf '\n'
}}

run_exec() {{
  cwd_b64="$1"
  timeout_secs="$2"
  command_b64="$3"
  shift 3
  out_file="$(mktemp)"
  err_file="$(mktemp)"
  cwd=''
  if [ "$cwd_b64" != "-" ]; then
    cwd="$(decode_b64 "$cwd_b64")"
  fi
  command_text="$(decode_b64 "$command_b64")"
  exec_command="sh -lc $(quote_sh "$command_text")"
  while [ "$#" -gt 0 ]; do
    assignment="$(decode_b64 "$1")"
    exec_command="env $(quote_sh "$assignment") $exec_command"
    shift
  done
  if [ "$timeout_secs" != "0" ] && command -v timeout >/dev/null 2>&1; then
    exec_command="timeout $(quote_sh "$timeout_secs") $exec_command"
  fi
  if [ -n "$cwd" ]; then
    exec_command="cd $(quote_sh "$cwd") && $exec_command"
  fi
  if sh -lc "$exec_command" >"$out_file" 2>"$err_file"; then
    code=0
  else
    code=$?
  fi
  emit_result "$code" "$out_file" "$err_file"
  rm -f "$out_file" "$err_file"
}}

run_read() {{
  path="$(decode_b64 "$1")"
  out_file="$(mktemp)"
  err_file="$(mktemp)"
  if cat -- "$path" >"$out_file" 2>"$err_file"; then
    code=0
  else
    code=$?
  fi
  emit_result "$code" "$out_file" "$err_file"
  rm -f "$out_file" "$err_file"
}}

path_allowed_fd() {{
  fd="$1"
  shift
  actual="$(readlink -f "/proc/$$/fd/$fd" 2>/dev/null || true)"
  [ -n "$actual" ] || return 1
  while [ "$#" -gt 0 ]; do
    root="$(decode_b64 "$1")"
    resolved_root="$(readlink -f -- "$root" 2>/dev/null || true)"
    if [ -n "$resolved_root" ]; then
      case "$actual" in
        "$resolved_root") return 0 ;;
        "$resolved_root"/*) return 0 ;;
      esac
      [ "$resolved_root" = "/" ] && return 0
    fi
    shift
  done
  return 1
}}

run_read_policy() {{
  path="$(decode_b64 "$1")"
  shift
  out_file="$(mktemp)"
  err_file="$(mktemp)"
  code=0
  if exec 3< "$path"; then
    if path_allowed_fd 3 "$@"; then
      cat <&3 >"$out_file" 2>"$err_file" || code=$?
    else
      printf 'agent policy denied resolved read path: %s\n' "$path" >"$err_file"
      code=77
    fi
    exec 3<&-
  else
    printf 'cannot open remote path: %s\n' "$path" >"$err_file"
    code=1
  fi
  emit_result "$code" "$out_file" "$err_file"
  rm -f "$out_file" "$err_file"
}}

run_write() {{
  mode="$1"
  path="$(decode_b64 "$2")"
  out_file="$(mktemp)"
  err_file="$(mktemp)"
  input_file="$(mktemp)"
  cat >"$input_file"
  parent="$(dirname "$path")"
  if [ -n "$parent" ] && [ "$parent" != "." ]; then
    mkdir -p "$parent" 2>>"$err_file" || true
  fi
  case "$mode" in
    create)
      if [ -e "$path" ]; then
        printf 'target already exists: %s\n' "$path" >"$err_file"
        code=17
      elif cat "$input_file" >"$path" 2>>"$err_file"; then
        code=0
      else
        code=$?
      fi
      ;;
    truncate)
      if cat "$input_file" >"$path" 2>>"$err_file"; then
        code=0
      else
        code=$?
      fi
      ;;
    append)
      if cat "$input_file" >>"$path" 2>>"$err_file"; then
        code=0
      else
        code=$?
      fi
      ;;
    *)
      printf 'unsupported write mode: %s\n' "$mode" >"$err_file"
      code=64
      ;;
  esac
  if [ "$code" = "0" ]; then
    wc -c <"$input_file" | tr -d ' ' >"$out_file"
  fi
  emit_result "$code" "$out_file" "$err_file"
  rm -f "$out_file" "$err_file" "$input_file"
}}

run_write_policy() {{
  mode="$1"
  path="$(decode_b64 "$2")"
  shift 2
  out_file="$(mktemp)"
  err_file="$(mktemp)"
  input_file="$(mktemp)"
  cat >"$input_file"
  parent="$(dirname "$path")"
  base="$(basename "$path")"
  code=0

  if [ ! -d "$parent" ] || ! exec 4< "$parent"; then
    printf 'policy write requires an existing parent directory: %s\n' "$parent" >"$err_file"
    code=77
  elif ! path_allowed_fd 4 "$@"; then
    printf 'agent policy denied resolved write parent: %s\n' "$parent" >"$err_file"
    code=77
  else
    target="/proc/$$/fd/4/$base"
    case "$mode" in
      create)
        set -C
        if ! exec 3> "$target"; then
          printf 'target already exists: %s\n' "$path" >"$err_file"
          code=17
        fi
        ;;
      truncate|append)
        if ! exec 3>> "$target"; then
          printf 'cannot open remote path: %s\n' "$path" >"$err_file"
          code=1
        fi
        ;;
      *)
        printf 'unsupported write mode: %s\n' "$mode" >"$err_file"
        code=64
        ;;
    esac
    if [ "$code" = "0" ] && ! path_allowed_fd 3 "$@"; then
      printf 'agent policy denied resolved write path: %s\n' "$path" >"$err_file"
      code=77
    fi
    if [ "$code" = "0" ]; then
      if [ "$mode" = "truncate" ]; then
        : > "/proc/$$/fd/3"
      fi
      cat "$input_file" >&3 2>>"$err_file" || code=$?
    fi
    exec 3>&- 2>/dev/null || true
    exec 4<&- 2>/dev/null || true
  fi
  if [ "$code" = "0" ]; then
    wc -c <"$input_file" | tr -d ' ' >"$out_file"
  fi
  emit_result "$code" "$out_file" "$err_file"
  rm -f "$out_file" "$err_file" "$input_file"
}}

case "${{1:-}}" in
  version|--version)
    printf '%s\n' "$SSHMCPD_VERSION"
    ;;
  exec)
    shift
    run_exec "$@"
    ;;
  read)
    shift
    run_read "$@"
    ;;
  read-policy)
    shift
    run_read_policy "$@"
    ;;
  write)
    shift
    run_write "$@"
    ;;
  write-policy)
    shift
    run_write_policy "$@"
    ;;
  *)
    echo "unknown command: $1" >&2
    exit 64
    ;;
esac
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_revision_forces_remote_agent_refresh() {
        assert_eq!(expected_version("1.2.3"), "1.2.3+policy-fd-v1");
    }

    #[cfg(unix)]
    #[test]
    fn policy_file_operations_reject_symlink_escape_without_modifying_target() {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::symlink;
        use std::process::{Command, Stdio};

        let temp = std::env::temp_dir().join(format!("sshmcp-policy-{}", uuid::Uuid::new_v4()));
        let allowed = temp.join("allowed");
        let outside = temp.join("outside");
        fs::create_dir_all(&allowed).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let outside_file = outside.join("secret.txt");
        fs::write(&outside_file, b"original").unwrap();
        let link = allowed.join("escape.txt");
        symlink(&outside_file, &link).unwrap();
        let agent = temp.join("agent.sh");
        fs::write(&agent, render_agent_script("test")).unwrap();

        let mut read_command = Command::new("sh");
        read_command
            .arg(&agent)
            .arg("read-policy")
            .arg(BASE64.encode(link.as_os_str().as_encoded_bytes()))
            .arg(BASE64.encode(allowed.as_os_str().as_encoded_bytes()));
        let read = read_command.output().unwrap();
        assert_eq!(
            String::from_utf8_lossy(&read.stdout).lines().next(),
            Some("77")
        );

        let mut write_command = Command::new("sh");
        write_command
            .arg(&agent)
            .arg("write-policy")
            .arg("truncate")
            .arg(BASE64.encode(link.as_os_str().as_encoded_bytes()))
            .arg(BASE64.encode(allowed.as_os_str().as_encoded_bytes()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut write = write_command.spawn().unwrap();
        write.stdin.take().unwrap().write_all(b"modified").unwrap();
        let write = write.wait_with_output().unwrap();
        assert_eq!(
            String::from_utf8_lossy(&write.stdout).lines().next(),
            Some("77")
        );
        assert_eq!(fs::read(&outside_file).unwrap(), b"original");
        fs::remove_dir_all(temp).unwrap();
    }
}
