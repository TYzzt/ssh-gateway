pub fn expected_version(version: &str) -> String {
    if version.trim().is_empty() {
        env!("CARGO_PKG_VERSION").to_string()
    } else {
        version.to_string()
    }
}

pub fn render_agent_script(version: &str) -> String {
    format!(
        r#"#!/bin/sh
set -eu
SSH_GATEWAYD_VERSION='{version}'

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

case "${{1:-}}" in
  version|--version)
    printf '%s\n' "$SSH_GATEWAYD_VERSION"
    ;;
  exec)
    shift
    run_exec "$@"
    ;;
  read)
    shift
    run_read "$@"
    ;;
  write)
    shift
    run_write "$@"
    ;;
  *)
    echo "unknown command: $1" >&2
    exit 64
    ;;
esac
"#
    )
}
