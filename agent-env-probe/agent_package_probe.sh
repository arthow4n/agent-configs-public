#!/usr/bin/env bash
# agent_package_probe.sh
# Explicit opt-in package/runtime capability tests for agentic environments.
# No system/global installs, no sudo, no shell-profile/PATH edits, no credential inspection.

set -u
set -o pipefail

VERSION="1.0.0"
DO_PY=0
DO_NPM=0
DO_DENO_NPM=0
DO_DENO_INSTALL=0

PY_PACKAGE="packaging==26.3"
PY_WHEEL_GLOB="packaging-26.3-*.whl"
PY_WHEEL_SHA256="d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c"

NPM_PACKAGE="ms@2.1.3"
NPM_TARBALL="ms-2.1.3.tgz"
NPM_INTEGRITY="sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA=="

DENO_VERSION="2.9.6"
DENO_SHA_LINUX_X86_64="394f07f4da2bebe6ce6f1e7ce0fa16429b29b08c35e3fac3fe25972676dff4b2"
DENO_SHA_LINUX_AARCH64="9a46afc6c392c7cd2ff71a31558935545b46408d0e87f7a86908c712721c046e"
DENO_SHA_DARWIN_X86_64="7d4524b82bcc557fe020a1a5b56956ed42b992ae5b28026e8ad5d17329533f5f"
DENO_SHA_DARWIN_AARCH64="213a2f304f04d3c9cb5220669afad138f60a5aab1fe80962abdeb8f35807a472"

usage() {
  cat <<'USAGE'
Usage: agent_package_probe.sh [options]

This companion probe performs writes/network/package execution ONLY when explicitly invoked.
All writes are confined to a freshly created temporary directory and are deleted afterward.

Options:
  --python-package-test  Download packaging==26.3 as a wheel only, verify SHA-256,
                         install into a temp directory with no dependencies, execute a
                         deterministic import test, then delete it.
  --npm-package-test     Download ms@2.1.3 with npm in an isolated HOME/config/cache,
                         disable lifecycle scripts, verify SHA-512 integrity, install
                         only into a temp prefix, execute with Node, then delete it.
  --deno-npm-test        If Deno is already present, resolve and execute ms@2.1.3 via
                         Deno's npm: compatibility layer using a temp DENO_DIR.
  --deno-install-test    Download official pinned Deno v2.9.6 ZIP to a temp directory,
                         verify hardcoded SHA-256, extract/run it locally, then test
                         npm:ms@2.1.3. No global install or PATH modification.
  --package-tests        Run Python + npm + existing-Deno tests. Does not download Deno.
  --all-install-tests    Run every test, including the portable Deno download test.
  -h, --help             Show help.

Deliberate safety properties:
  * no sudo or system package manager
  * no global Python/npm/Deno install
  * no shell profile or PATH edits
  * no environment-variable dump or credential discovery
  * npm user/global config and inherited environment are not used for registry access
  * npm lifecycle scripts are disabled
  * Python source builds and dependency trees are disabled
  * downloaded Python/npm/Deno artifacts are pinned and integrity-checked
  * package/network commands are bounded when `timeout` is available
  * command stderr/stdout from package managers is suppressed to avoid leaking URLs/config
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --python-package-test) DO_PY=1; shift ;;
    --npm-package-test) DO_NPM=1; shift ;;
    --deno-npm-test) DO_DENO_NPM=1; shift ;;
    --deno-install-test) DO_DENO_INSTALL=1; shift ;;
    --package-tests) DO_PY=1; DO_NPM=1; DO_DENO_NPM=1; shift ;;
    --all-install-tests) DO_PY=1; DO_NPM=1; DO_DENO_NPM=1; DO_DENO_INSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$DO_PY" -eq 0 ] && [ "$DO_NPM" -eq 0 ] && [ "$DO_DENO_NPM" -eq 0 ] && [ "$DO_DENO_INSTALL" -eq 0 ]; then
  usage
  exit 2
fi

have() { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n===== %s =====\n' "$1"; }
kv() { printf '%-30s %s\n' "$1:" "$2"; }

probe_tmpdir() {
  local base="${TMPDIR:-/tmp}" d=""
  [ -d "$base" ] && [ -w "$base" ] || return 1
  d=$(mktemp -d "$base/agent-package-probe.XXXXXX" 2>/dev/null || true)
  [ -n "$d" ] && [ -d "$d" ] || return 1
  printf '%s' "$d"
}

safe_cleanup() {
  local d="${1:-}"
  case "$d" in
    */agent-package-probe.*) rm -rf -- "$d" 2>/dev/null || true ;;
    *) return 1 ;;
  esac
}

bounded() {
  local secs=$1
  shift
  if have timeout; then timeout "${secs}s" "$@"; else "$@"; fi
}

sha256_file() {
  local f=$1
  if have sha256sum; then sha256sum "$f" 2>/dev/null | awk '{print $1}'; return; fi
  if have shasum; then shasum -a 256 "$f" 2>/dev/null | awk '{print $1}'; return; fi
  if have openssl; then openssl dgst -sha256 "$f" 2>/dev/null | awk '{print $NF}'; return; fi
  return 1
}

download_https() {
  local url=$1 out=$2
  case "$url" in https://*) ;; *) return 2 ;; esac
  if have curl; then
    curl -fL --proto '=https' --connect-timeout 8 --max-time 120 -o "$out" "$url" >/dev/null 2>&1
    return $?
  fi
  if have wget; then
    wget -q --https-only --timeout=120 -O "$out" "$url" >/dev/null 2>&1
    return $?
  fi
  return 127
}

python_test() {
  section "PYTHON / PYPI TEMP INSTALL"
  local py="" d="" wheel="" actual="" rc=0
  if have python3; then py=$(command -v python3); elif have python; then py=$(command -v python); fi
  [ -n "$py" ] || { kv "python.runtime" "SKIP: absent"; return; }
  "$py" -m pip --version >/dev/null 2>&1 || { kv "python.pip" "SKIP: unavailable"; return; }
  d=$(probe_tmpdir || true)
  [ -n "$d" ] || { kv "python.temp_dir" "BLOCKED"; return; }
  mkdir -p "$d/home" "$d/download" "$d/site" || { kv "python.temp_setup" "BLOCKED"; safe_cleanup "$d"; return; }

  kv "python.test_package" "$PY_PACKAGE"
  bounded 30 env HOME="$d/home" "$py" -m pip --isolated download --disable-pip-version-check --no-input \
    --timeout 8 --retries 0 --only-binary=:all: --no-deps --dest "$d/download" "$PY_PACKAGE" >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || { kv "python.download" "FAIL/BLOCKED (exit $rc)"; safe_cleanup "$d"; return; }
  kv "python.download" "PASS"

  wheel=$(find "$d/download" -maxdepth 1 -type f -name "$PY_WHEEL_GLOB" -print -quit 2>/dev/null || true)
  [ -n "$wheel" ] || { kv "python.wheel" "FAIL: missing"; safe_cleanup "$d"; return; }
  actual=$(sha256_file "$wheel" 2>/dev/null || true)
  [ -n "$actual" ] || { kv "python.sha256" "BLOCKED: hash utility absent"; safe_cleanup "$d"; return; }
  [ "$actual" = "$PY_WHEEL_SHA256" ] || { kv "python.sha256" "FAIL: mismatch"; safe_cleanup "$d"; return; }
  kv "python.sha256" "PASS"

  env HOME="$d/home" "$py" -m pip --isolated install --disable-pip-version-check --no-input \
    --no-index --only-binary=:all: --no-deps --target "$d/site" "$wheel" >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || { kv "python.temp_install" "FAIL/BLOCKED (exit $rc)"; safe_cleanup "$d"; return; }
  kv "python.temp_install" "PASS"

  env HOME="$d/home" "$py" -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from packaging.version import Version; raise SystemExit(0 if Version("2.10.0") > Version("2.9.0") else 1)' "$d/site" >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] && kv "python.execution" "PASS" || kv "python.execution" "FAIL (exit $rc)"
  safe_cleanup "$d"
  kv "python.cleanup" "attempted"
}

npm_test() {
  section "NODE / NPM TEMP INSTALL"
  local npm_bin="" node_bin="" d="" tgz="" integrity="" minpath="" rc=0
  have node && have npm || { kv "node/npm" "SKIP: absent"; return; }
  node_bin=$(command -v node); npm_bin=$(command -v npm)
  d=$(probe_tmpdir || true)
  [ -n "$d" ] || { kv "npm.temp_dir" "BLOCKED"; return; }
  mkdir -p "$d/home" "$d/cache" "$d/download" "$d/app" || { kv "npm.temp_setup" "BLOCKED"; safe_cleanup "$d"; return; }
  : > "$d/npmrc"
  minpath="$(dirname "$node_bin"):$(dirname "$npm_bin"):/usr/bin:/bin"

  kv "npm.test_package" "$NPM_PACKAGE"
  (cd "$d/download" && bounded 30 env -i PATH="$minpath" HOME="$d/home" LANG=C \
    npm_config_userconfig="$d/npmrc" npm_config_cache="$d/cache" npm_config_registry="https://registry.npmjs.org/" \
    npm_config_fetch_retries=0 npm_config_fetch_timeout=10000 npm_config_fetch_retry_mintimeout=1000 npm_config_fetch_retry_maxtimeout=10000 \
    "$npm_bin" pack --ignore-scripts --silent "$NPM_PACKAGE" >/dev/null 2>&1)
  rc=$?
  [ "$rc" -eq 0 ] || { kv "npm.download" "FAIL/BLOCKED (exit $rc)"; safe_cleanup "$d"; return; }
  tgz="$d/download/$NPM_TARBALL"
  [ -f "$tgz" ] || { kv "npm.tarball" "FAIL: missing"; safe_cleanup "$d"; return; }
  kv "npm.download" "PASS"

  integrity=$(env -i PATH="$minpath" HOME="$d/home" LANG=C "$node_bin" -e \
    'const fs=require("fs"),c=require("crypto"); process.stdout.write("sha512-"+c.createHash("sha512").update(fs.readFileSync(process.argv[1])).digest("base64"))' "$tgz" 2>/dev/null || true)
  [ "$integrity" = "$NPM_INTEGRITY" ] || { kv "npm.integrity" "FAIL/BLOCKED"; safe_cleanup "$d"; return; }
  kv "npm.integrity" "PASS"

  env -i PATH="$minpath" HOME="$d/home" LANG=C npm_config_userconfig="$d/npmrc" npm_config_cache="$d/cache" \
    "$npm_bin" install --offline --ignore-scripts --no-audit --no-fund --package-lock=false --prefix "$d/app" "$tgz" >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || { kv "npm.temp_install" "FAIL/BLOCKED (exit $rc)"; safe_cleanup "$d"; return; }
  kv "npm.temp_install" "PASS (scripts disabled)"

  env -i PATH="$minpath" HOME="$d/home" LANG=C "$node_bin" -e \
    'const ms=require(process.argv[1]); process.exit(ms("2s")===2000 ? 0 : 1)' "$d/app/node_modules/ms" >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] && kv "node.execution" "PASS" || kv "node.execution" "FAIL (exit $rc)"
  safe_cleanup "$d"
  kv "npm.cleanup" "attempted"
}

deno_npm_with() {
  local deno_bin=$1 d="" rc=0
  d=$(probe_tmpdir || true)
  [ -n "$d" ] || { kv "deno.temp_dir" "BLOCKED"; return; }
  mkdir -p "$d/home" "$d/cache" || { kv "deno.temp_setup" "BLOCKED"; safe_cleanup "$d"; return; }

  bounded 30 env -i HOME="$d/home" DENO_DIR="$d/cache" DENO_NO_PROMPT=1 NO_COLOR=1 LANG=C \
    "$deno_bin" info "npm:$NPM_PACKAGE" >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || { kv "deno.npm_resolution" "FAIL/BLOCKED (exit $rc)"; safe_cleanup "$d"; return; }
  kv "deno.npm_resolution" "PASS"

  bounded 30 env -i HOME="$d/home" DENO_DIR="$d/cache" DENO_NO_PROMPT=1 NO_COLOR=1 LANG=C \
    "$deno_bin" eval 'import ms from "npm:ms@2.1.3"; if (ms("2s") !== 2000) Deno.exit(1);' >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] && kv "deno.npm_execution" "PASS" || kv "deno.npm_execution" "FAIL (exit $rc)"
  safe_cleanup "$d"
  kv "deno.cache_cleanup" "attempted"
}

existing_deno_test() {
  section "EXISTING DENO / NPM COMPATIBILITY"
  have deno || { kv "deno.runtime" "SKIP: absent"; return; }
  kv "deno.runtime" "present"
  deno_npm_with "$(command -v deno)"
}

portable_deno_test() {
  section "PORTABLE DENO DOWNLOAD / EXECUTION"
  local os arch asset sha url d zip actual deno_bin rc=0
  os=$(uname -s 2>/dev/null || echo unknown)
  arch=$(uname -m 2>/dev/null || echo unknown)
  case "$os:$arch" in
    Linux:x86_64|Linux:amd64) asset="deno-x86_64-unknown-linux-gnu.zip"; sha="$DENO_SHA_LINUX_X86_64" ;;
    Linux:aarch64|Linux:arm64) asset="deno-aarch64-unknown-linux-gnu.zip"; sha="$DENO_SHA_LINUX_AARCH64" ;;
    Darwin:x86_64|Darwin:amd64) asset="deno-x86_64-apple-darwin.zip"; sha="$DENO_SHA_DARWIN_X86_64" ;;
    Darwin:aarch64|Darwin:arm64) asset="deno-aarch64-apple-darwin.zip"; sha="$DENO_SHA_DARWIN_AARCH64" ;;
    *) kv "deno.portable" "SKIP: unsupported $os/$arch"; return ;;
  esac

  d=$(probe_tmpdir || true)
  [ -n "$d" ] || { kv "deno.temp_dir" "BLOCKED"; return; }
  zip="$d/$asset"
  url="https://github.com/denoland/deno/releases/download/v${DENO_VERSION}/${asset}"
  kv "deno.version" "$DENO_VERSION"
  kv "deno.asset" "$asset"

  download_https "$url" "$zip"
  rc=$?
  [ "$rc" -eq 0 ] || { kv "deno.download" "FAIL/BLOCKED (exit $rc)"; safe_cleanup "$d"; return; }
  kv "deno.download" "PASS"

  actual=$(sha256_file "$zip" 2>/dev/null || true)
  [ -n "$actual" ] || { kv "deno.sha256" "BLOCKED: hash utility absent"; safe_cleanup "$d"; return; }
  [ "$actual" = "$sha" ] || { kv "deno.sha256" "FAIL: mismatch"; safe_cleanup "$d"; return; }
  kv "deno.sha256" "PASS"

  mkdir -p "$d/bin" "$d/home" "$d/cache"
  if have unzip; then
    unzip -q "$zip" -d "$d/bin" >/dev/null 2>&1; rc=$?
  elif have python3; then
    python3 -m zipfile -e "$zip" "$d/bin" >/dev/null 2>&1; rc=$?
  elif have python; then
    python -m zipfile -e "$zip" "$d/bin" >/dev/null 2>&1; rc=$?
  else
    kv "deno.extract" "BLOCKED: unzip/Python absent"; safe_cleanup "$d"; return
  fi
  [ "$rc" -eq 0 ] || { kv "deno.extract" "FAIL (exit $rc)"; safe_cleanup "$d"; return; }
  deno_bin="$d/bin/deno"
  [ -f "$deno_bin" ] || { kv "deno.extract" "FAIL: binary missing"; safe_cleanup "$d"; return; }
  chmod u+x "$deno_bin" 2>/dev/null || true
  kv "deno.extract" "PASS"

  env -i HOME="$d/home" DENO_DIR="$d/cache" DENO_NO_PROMPT=1 NO_COLOR=1 LANG=C "$deno_bin" --version >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || { kv "deno.execution" "FAIL/BLOCKED (exit $rc)"; safe_cleanup "$d"; return; }
  kv "deno.execution" "PASS"
  deno_npm_with "$deno_bin"
  safe_cleanup "$d"
  kv "deno.portable_cleanup" "attempted"
}

section "PACKAGE PROBE"
kv "probe version" "$VERSION"
kv "python opted in" "$([ "$DO_PY" -eq 1 ] && echo yes || echo no)"
kv "npm opted in" "$([ "$DO_NPM" -eq 1 ] && echo yes || echo no)"
kv "existing Deno opted in" "$([ "$DO_DENO_NPM" -eq 1 ] && echo yes || echo no)"
kv "portable Deno opted in" "$([ "$DO_DENO_INSTALL" -eq 1 ] && echo yes || echo no)"

[ "$DO_PY" -eq 1 ] && python_test
[ "$DO_NPM" -eq 1 ] && npm_test
[ "$DO_DENO_NPM" -eq 1 ] && existing_deno_test
[ "$DO_DENO_INSTALL" -eq 1 ] && portable_deno_test

section "END"
kv "result" "package probe completed"
