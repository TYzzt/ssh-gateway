#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-latest}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
REPO="TYzzt/ssh-gateway"
BINARY_NAME="ssh-gateway"

if [[ "${OSTYPE:-}" == darwin* ]]; then
  echo "ssh-gateway does not currently publish macOS release assets." >&2
  exit 1
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_cmd curl
require_cmd tar

api_headers=(
  -H "Accept: application/vnd.github+json"
  -H "User-Agent: ssh-gateway-skill-installer"
)

if [[ "$VERSION" == "latest" ]]; then
  release_json="$(curl -fsSL "${api_headers[@]}" "https://api.github.com/repos/${REPO}/releases/latest")"
  version_tag="$(printf '%s' "$release_json" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
else
  version_tag="$VERSION"
  [[ "$version_tag" == v* ]] || version_tag="v${version_tag}"
  release_json="$(curl -fsSL "${api_headers[@]}" "https://api.github.com/repos/${REPO}/releases/tags/${version_tag}")"
fi

if [[ -z "${version_tag:-}" ]]; then
  echo "failed to resolve release version" >&2
  exit 1
fi

asset_name="ssh-gateway-${version_tag}-x86_64-unknown-linux-gnu.tar.gz"
asset_url="$(printf '%s' "$release_json" | tr '\n' ' ' | sed -n "s/.*\"browser_download_url\":[[:space:]]*\"\\([^\"]*${asset_name//./\\.}\\)\".*/\\1/p")"

if [[ -z "${asset_url:-}" ]]; then
  echo "release asset not found: ${asset_name}" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
temp_root="$(mktemp -d)"
archive_path="${temp_root}/${asset_name}"
extract_dir="${temp_root}/extract"
mkdir -p "$extract_dir"

cleanup() {
  rm -rf "$temp_root"
}
trap cleanup EXIT

curl -fsSL "${api_headers[@]}" -o "$archive_path" "$asset_url"
tar -xzf "$archive_path" -C "$extract_dir"

binary_path="$(find "$extract_dir" -type f -name "$BINARY_NAME" | head -n1)"
if [[ -z "${binary_path:-}" ]]; then
  echo "binary not found in archive" >&2
  exit 1
fi

target_path="${INSTALL_DIR}/${BINARY_NAME}"
cp "$binary_path" "$target_path"
chmod +x "$target_path"

on_path="false"
case ":$PATH:" in
  *":${INSTALL_DIR}:"*) on_path="true" ;;
esac

printf '{\n'
printf '  "version": "%s",\n' "$version_tag"
printf '  "binary_path": "%s",\n' "$target_path"
printf '  "install_dir": "%s",\n' "$INSTALL_DIR"
printf '  "on_path": %s' "$on_path"
if [[ "$on_path" == "true" ]]; then
  printf '\n'
else
  printf ',\n  "add_to_path_hint": "Add %s to PATH if you want to invoke ssh-gateway without an absolute path."\n' "$INSTALL_DIR"
fi
printf '}\n'
