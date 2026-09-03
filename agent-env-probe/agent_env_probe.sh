#!/usr/bin/env bash
# agent_env_probe.sh
# Read-only-by-default environment capability probe for agentic sandboxes/VMs.
# It intentionally avoids secrets, file contents, environment variables,
# browser profiles, process command lines, SSH config, cloud metadata endpoints,
# and arbitrary outbound requests.

set -u
set -o pipefail

VERSION="1.0.1"
DO_NETWORK=0
DO_SUDO=0
DO_WRITE=0
PERSIST_DIR=""

usage() {
  cat <<'USAGE'
Usage: agent_env_probe.sh [options]

Default mode is read-only and makes no outbound network requests.

Options:
  --network              Opt in to bounded DNS/HTTPS reachability checks to example.com.
  --sudo-test            Opt in to `sudo -n true` (no command is run as root).
  --write-test           Opt in to a temporary write/fsync/delete test under $TMPDIR or /tmp.
  --persistence-dir DIR  Opt in to a two-run persistence marker in DIR.
                         First run creates a random marker; a later run reports whether it survived.
  -h, --help             Show this help.

Safety exclusions by design:
  * no environment-variable dump
  * no credential/token/key discovery
  * no browser-cookie/profile inspection
  * no SSH/Git/cloud credential inspection
  * no process command-line dump
  * no cloud-instance metadata endpoint access (169.254.169.254, etc.)
  * no port scanning
  * no public-IP lookup
  * no load/stress benchmark or large allocation
  * no package installation
  * no sudo/root action other than optional `sudo -n true`
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --network) DO_NETWORK=1; shift ;;
    --sudo-test) DO_SUDO=1; shift ;;
    --write-test) DO_WRITE=1; shift ;;
    --persistence-dir)
      [ "$#" -ge 2 ] || { echo "error: --persistence-dir requires DIR" >&2; exit 2; }
      PERSIST_DIR=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n===== %s =====\n' "$1"; }
kv() { printf '%-32s %s\n' "$1:" "$2"; }
first_line() { "$@" 2>&1 | sed -n '1p' | tr '\t' ' '; }
trim() { sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }
read_file_line() { [ -r "$1" ] && sed -n '1p' "$1" 2>/dev/null || true; }
yesno() { [ "$1" -eq 0 ] && printf 'yes' || printf 'no'; }

# Conservative redaction for strings that accidentally resemble credentials.
redact_line() {
  sed -E \
    -e 's/(Bearer|bearer)[[:space:]]+[A-Za-z0-9._~+\/=:-]+/\1 <REDACTED>/g' \
    -e 's/(token|password|passwd|secret|api[_-]?key)[[:space:]]*[:=][[:space:]]*[^[:space:]]+/\1=<REDACTED>/Ig' \
    -e 's/(AKIA|ASIA)[A-Z0-9]{16}/<AWS_KEY_REDACTED>/g' \
    -e 's/(gh[pousr]_[A-Za-z0-9_]{20,})/<GITHUB_TOKEN_REDACTED>/g'
}

safe_version() {
  # Print only presence + first version line. Never prints PATH.
  local cmd=$1 out=""
  if ! have "$cmd"; then
    printf '%-20s %s\n' "$cmd" "absent"
    return
  fi

  case "$cmd" in
    python|python3|pip|pip3|uv|node|npm|pnpm|yarn|bun|deno|rustc|cargo|gcc|g++|clang|cmake|make|ninja|meson|git|gh|docker|podman|buildah|kubectl|helm|terraform|ansible|curl|wget|jq|rg|sqlite3|ffmpeg|pandoc|tesseract|java|javac|dotnet|ruby|php)
      out=$(first_line "$cmd" --version || true)
      ;;
    go)
      out=$(first_line go version || true)
      ;;
    perl)
      out=$(perl -v 2>&1 | awk 'NF {print; exit}' || true)
      ;;
    R)
      out=$(first_line R --version || true)
      ;;
    libreoffice|soffice)
      out=$(first_line "$cmd" --version || true)
      ;;
    convert)
      out=$(convert -version 2>/dev/null | sed -n '1p' || true)
      ;;
    magick)
      out=$(magick -version 2>/dev/null | sed -n '1p' || true)
      ;;
    gs)
      out=$(first_line gs --version || true)
      ;;
    pdftotext)
      out=$(pdftotext -v 2>&1 | sed -n '1p' || true)
      ;;
    ssh)
      out=$(ssh -V 2>&1 | sed -n '1p' || true)
      ;;
    psql)
      out=$(first_line psql --version || true)
      ;;
    mysql)
      out=$(mysql --version 2>&1 | sed -n '1p' || true)
      ;;
    redis-cli)
      out=$(redis-cli --version 2>&1 | sed -n '1p' || true)
      ;;
    chromium|chromium-browser|google-chrome|google-chrome-stable|firefox)
      out=$(first_line "$cmd" --version || true)
      ;;
    *)
      out="present"
      ;;
  esac

  out=$(printf '%s' "$out" | redact_line | cut -c1-220)
  [ -n "$out" ] || out="present (version unavailable)"
  printf '%-20s %s\n' "$cmd" "$out"
}

bytes_human() {
  # Input integer bytes; output compact IEC value. Uses awk only.
  awk -v b="${1:-0}" 'BEGIN {
    split("B KiB MiB GiB TiB",u," "); i=1;
    while (b>=1024 && i<5) { b/=1024; i++ }
    if (i==1) printf "%.0f %s",b,u[i]; else printf "%.2f %s",b,u[i]
  }'
}

cpu_quota_v2() {
  local f="/sys/fs/cgroup/cpu.max" q p
  [ -r "$f" ] || return 0
  read -r q p < "$f" 2>/dev/null || return 0
  kv "cgroup cpu.max" "$q $p"
  if [ "$q" != "max" ] 2>/dev/null; then
    awk -v q="$q" -v p="$p" 'BEGIN { if (p>0) printf "%-32s %.3f\n", "cgroup CPU quota cores:", q/p }'
  fi
}

memory_limit_v2() {
  local f="/sys/fs/cgroup/memory.max" v
  [ -r "$f" ] || return 0
  v=$(read_file_line "$f")
  kv "cgroup memory.max" "$v"
  if printf '%s' "$v" | grep -Eq '^[0-9]+$'; then
    kv "cgroup memory limit" "$(bytes_human "$v")"
  fi
  if [ -r /sys/fs/cgroup/memory.current ]; then
    v=$(read_file_line /sys/fs/cgroup/memory.current)
    kv "cgroup memory.current" "$v"
    if printf '%s' "$v" | grep -Eq '^[0-9]+$'; then
      kv "cgroup memory current" "$(bytes_human "$v")"
    fi
  fi
}

pids_limit_v2() {
  local f="/sys/fs/cgroup/pids.max" v
  [ -r "$f" ] || return 0
  v=$(read_file_line "$f")
  kv "cgroup pids.max" "$v"
  [ -r /sys/fs/cgroup/pids.current ] && kv "cgroup pids.current" "$(read_file_line /sys/fs/cgroup/pids.current)"
}

section "PROBE"
kv "probe version" "$VERSION"
if have date; then kv "timestamp UTC" "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true)"; fi
kv "default safety mode" "read-only / no outbound network"
kv "network test opted in" "$([ "$DO_NETWORK" -eq 1 ] && echo yes || echo no)"
kv "sudo test opted in" "$([ "$DO_SUDO" -eq 1 ] && echo yes || echo no)"
kv "write test opted in" "$([ "$DO_WRITE" -eq 1 ] && echo yes || echo no)"
kv "persistence test opted in" "$([ -n "$PERSIST_DIR" ] && echo yes || echo no)"

section "OS / KERNEL"
if [ -r /etc/os-release ]; then
  # Allowlist only non-sensitive OS fields.
  . /etc/os-release
  kv "OS" "${PRETTY_NAME:-${NAME:-unknown}}"
  kv "OS ID" "${ID:-unknown}"
  kv "OS version ID" "${VERSION_ID:-unknown}"
else
  kv "OS" "unknown"
fi
kv "kernel" "$(uname -sr 2>/dev/null || echo unknown)"
kv "architecture" "$(uname -m 2>/dev/null || echo unknown)"
kv "machine word size" "$(getconf LONG_BIT 2>/dev/null || echo unknown)-bit"

section "VIRTUALIZATION / CONTAINER"
virt="unknown"
if have systemd-detect-virt; then virt=$(systemd-detect-virt 2>/dev/null || true); [ -n "$virt" ] || virt="none-detected"; fi
kv "systemd virtualization" "$virt"
if have virt-what; then kv "virt-what" "$(virt-what 2>/dev/null | tr '\n' ',' | sed 's/,$//' || true)"; else kv "virt-what" "unavailable"; fi
kv "/.dockerenv present" "$([ -e /.dockerenv ] && echo yes || echo no)"
kv "/run/.containerenv present" "$([ -e /run/.containerenv ] && echo yes || echo no)"
if [ -r /proc/1/cgroup ]; then
  c=$(grep -Eo 'docker|containerd|kubepods|podman|lxc|agent' /proc/1/cgroup 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//' || true)
  kv "cgroup container hints" "${c:-none-visible}"
else
  kv "cgroup container hints" "proc cgroup unavailable"
fi

section "CPU"
if have nproc; then kv "logical CPUs (nproc)" "$(nproc 2>/dev/null || echo unknown)"; fi
if have getconf; then kv "logical CPUs (getconf)" "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)"; fi
if have lscpu; then
  model=$(lscpu 2>/dev/null | awk -F: '/^Model name:/ {sub(/^[ \t]+/,"",$2); print $2; exit}')
  sockets=$(lscpu 2>/dev/null | awk -F: '/^Socket\(s\):/ {gsub(/ /,"",$2); print $2; exit}')
  cores=$(lscpu 2>/dev/null | awk -F: '/^Core\(s\) per socket:/ {gsub(/ /,"",$2); print $2; exit}')
  threads=$(lscpu 2>/dev/null | awk -F: '/^Thread\(s\) per core:/ {gsub(/ /,"",$2); print $2; exit}')
  hv=$(lscpu 2>/dev/null | awk -F: '/^Hypervisor vendor:/ {sub(/^[ \t]+/,"",$2); print $2; exit}')
  kv "CPU model" "${model:-hidden/unavailable}"
  kv "sockets visible" "${sockets:-hidden/unavailable}"
  kv "cores/socket visible" "${cores:-hidden/unavailable}"
  kv "threads/core visible" "${threads:-hidden/unavailable}"
  kv "hypervisor vendor" "${hv:-hidden/unavailable}"
else
  kv "lscpu" "unavailable"
fi
cpu_quota_v2
# cgroup v1 fallback
if [ -r /sys/fs/cgroup/cpu/cpu.cfs_quota_us ] && [ -r /sys/fs/cgroup/cpu/cpu.cfs_period_us ]; then
  q=$(read_file_line /sys/fs/cgroup/cpu/cpu.cfs_quota_us); p=$(read_file_line /sys/fs/cgroup/cpu/cpu.cfs_period_us)
  kv "cgroup v1 CPU quota" "$q / $p us"
fi

section "MEMORY / SWAP"
if [ -r /proc/meminfo ]; then
  mt=$(awk '/^MemTotal:/ {print $2*1024; exit}' /proc/meminfo)
  ma=$(awk '/^MemAvailable:/ {print $2*1024; exit}' /proc/meminfo)
  st=$(awk '/^SwapTotal:/ {print $2*1024; exit}' /proc/meminfo)
  kv "MemTotal" "$(bytes_human "${mt:-0}")"
  kv "MemAvailable" "$(bytes_human "${ma:-0}")"
  kv "SwapTotal" "$(bytes_human "${st:-0}")"
else
  kv "/proc/meminfo" "unavailable"
fi
memory_limit_v2
if [ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
  v=$(read_file_line /sys/fs/cgroup/memory/memory.limit_in_bytes)
  kv "cgroup v1 memory limit" "$v ($(bytes_human "$v" 2>/dev/null || echo unknown))"
fi

section "FILESYSTEM"
for p in / /workspace /mnt/data /tmp; do
  if [ -e "$p" ]; then
    kv "path present: $p" "yes"
    if df -P -k "$p" >/dev/null 2>&1; then
      # Stable, compact capacity line. No source-device field, avoiding host identifiers.
      df -P -k "$p" 2>/dev/null | awk -v p="$p" 'NR==2 {printf "%-32s total=%s KiB used=%s KiB avail=%s KiB use=%s\n", ("capacity " p ":"), $2,$3,$4,$5}'
    fi
    if df -P -i "$p" >/dev/null 2>&1; then
      df -P -i "$p" 2>/dev/null | awk -v p="$p" 'NR==2 {printf "%-32s inodes=%s used=%s free=%s use=%s\n", ("inodes " p ":"), $2,$3,$4,$5}'
    fi
    if have getconf; then kv "NAME_MAX $p" "$(getconf NAME_MAX "$p" 2>/dev/null || echo unavailable)"; fi
    [ -w "$p" ] && kv "writable $p" "yes" || kv "writable $p" "no"
  else
    kv "path present: $p" "no"
  fi
done

section "PROCESS / RESOURCE LIMITS"
# ulimit values are shell-level resource limits and reveal no command lines or secrets.
( ulimit -a 2>/dev/null || true ) | sed 's/^/  /'
pids_limit_v2

section "NAMESPACE VISIBILITY"
if [ -d /proc/self/ns ]; then
  for n in mnt pid net user ipc uts cgroup time; do
    if [ -e "/proc/self/ns/$n" ]; then
      v=$(readlink "/proc/self/ns/$n" 2>/dev/null || echo visible)
      kv "namespace $n" "$v"
    else
      kv "namespace $n" "hidden/unavailable"
    fi
  done
else
  kv "/proc/self/ns" "hidden/unavailable"
fi
kv "/proc/cpuinfo readable" "$([ -r /proc/cpuinfo ] && echo yes || echo no)"
kv "/sys readable" "$([ -r /sys/kernel ] && echo yes || echo no)"
kv "PCI inventory readable" "$([ -r /sys/bus/pci/devices ] && echo yes || echo no)"

section "GPU / ACCELERATOR VISIBILITY"
kv "/dev/dri present" "$([ -d /dev/dri ] && echo yes || echo no)"
ng=$(find /dev -maxdepth 1 -name 'nvidia*' -print 2>/dev/null | wc -l | tr -d ' ')
kv "NVIDIA device nodes" "${ng:-0}"
if have nvidia-smi; then
  kv "nvidia-smi" "present"
  # Read-only query; no utilization loop.
  nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader 2>/dev/null | sed 's/^/  GPU: /' | head -n 8
else
  kv "nvidia-smi" "absent"
fi
if have lspci; then
  gpu=$(lspci 2>/dev/null | grep -Ei 'vga|3d controller|display controller' | head -n 8 || true)
  if [ -n "$gpu" ]; then printf '%s\n' "$gpu" | sed 's/^/  PCI GPU: /'; else kv "lspci GPU" "none visible"; fi
else
  kv "lspci" "unavailable"
fi

section "DEVELOPMENT TOOLCHAIN"
for x in \
  python python3 pip pip3 uv \
  node npm pnpm yarn bun deno \
  go rustc cargo \
  gcc g++ clang cmake make ninja meson \
  java javac dotnet ruby php R perl \
  git gh; do
  safe_version "$x"
done

section "INFRA / CONTAINER TOOLS"
for x in docker podman buildah kubectl helm terraform ansible; do safe_version "$x"; done

section "DATA / NETWORK CLIENTS"
for x in curl wget jq rg sqlite3 psql mysql redis-cli ssh; do safe_version "$x"; done

section "BROWSER / DOCUMENT / MEDIA TOOLS"
for x in chromium chromium-browser google-chrome google-chrome-stable firefox libreoffice soffice pandoc ffmpeg convert magick tesseract pdftotext gs; do safe_version "$x"; done

section "PRIVILEGE SURFACE"
kv "effective UID is root" "$([ "$(id -u 2>/dev/null || echo 1)" = "0" ] && echo yes || echo no)"
kv "sudo binary" "$([ -x "$(command -v sudo 2>/dev/null || printf /nonexistent)" ] && echo present || echo absent)"
if [ "$DO_SUDO" -eq 1 ]; then
  if have sudo; then
    # `sudo -n true` asks whether passwordless sudo is available; `true` has no side effect.
    if sudo -n true >/dev/null 2>&1; then
      kv "passwordless sudo" "yes"
    else
      rc=$?
      kv "passwordless sudo" "no/blocked (exit $rc)"
    fi
  else
    kv "passwordless sudo" "not testable: sudo absent"
  fi
else
  kv "passwordless sudo" "not tested (use --sudo-test)"
fi

section "LOCAL NETWORK STACK (NO OUTBOUND TRAFFIC)"
kv "loopback interface" "$([ -e /sys/class/net/lo ] && echo present || echo unavailable)"
if have ss; then
  # Count listeners only; do not print addresses/processes.
  tcp_count=$(ss -ltnH 2>/dev/null | wc -l | tr -d ' ')
  udp_count=$(ss -lunH 2>/dev/null | wc -l | tr -d ' ')
  kv "TCP listeners count" "${tcp_count:-unknown}"
  kv "UDP listeners count" "${udp_count:-unknown}"
else
  kv "socket listener inventory" "ss unavailable"
fi

section "OUTBOUND NETWORK TEST"
if [ "$DO_NETWORK" -eq 1 ]; then
  if have getent; then
    if getent ahosts example.com >/dev/null 2>&1; then kv "DNS example.com" "reachable"; else kv "DNS example.com" "blocked/failed"; fi
  else
    kv "DNS test" "getent unavailable"
  fi
  if have curl; then
    code=$(curl -fsS -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 6 https://example.com/ 2>/dev/null || true)
    kv "HTTPS example.com" "${code:-failed}"
  elif have wget; then
    if wget -q --spider --timeout=6 https://example.com/ >/dev/null 2>&1; then kv "HTTPS example.com" "reachable"; else kv "HTTPS example.com" "blocked/failed"; fi
  else
    kv "HTTPS test" "curl/wget unavailable"
  fi
else
  kv "status" "skipped; use --network to opt in"
fi

section "TEMP WRITE TEST"
if [ "$DO_WRITE" -eq 1 ]; then
  base=${TMPDIR:-/tmp}
  if [ -d "$base" ] && [ -w "$base" ]; then
    d=$(mktemp -d "$base/agent-env-probe.XXXXXX" 2>/dev/null || true)
    if [ -n "$d" ] && [ -d "$d" ]; then
      f="$d/probe.bin"
      # 1 MiB only; file is immediately fsynced when possible and removed.
      if dd if=/dev/zero of="$f" bs=1048576 count=1 conv=fsync status=none 2>/dev/null; then
        kv "1 MiB temp write/fsync" "success"
      else
        kv "1 MiB temp write/fsync" "failed"
      fi
      rm -f "$f" 2>/dev/null || true
      rmdir "$d" 2>/dev/null || true
    else
      kv "temporary directory creation" "failed"
    fi
  else
    kv "temporary directory" "not writable"
  fi
else
  kv "status" "skipped; use --write-test to opt in"
fi

section "TWO-RUN FILE PERSISTENCE TEST"
if [ -n "$PERSIST_DIR" ]; then
  marker="$PERSIST_DIR/.agent_env_probe_persistence_marker"
  if [ -f "$marker" ]; then
    # Marker contains only fixed text + timestamp + random nonce generated by us.
    created=$(sed -n '1p' "$marker" 2>/dev/null | cut -c1-80)
    kv "marker survived from prior run" "yes"
    kv "marker metadata" "$created"
    kv "cleanup" "remove $marker when finished"
  else
    if [ -d "$PERSIST_DIR" ] && [ -w "$PERSIST_DIR" ]; then
      nonce=""
      if [ -r /dev/urandom ]; then nonce=$(od -An -N8 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n'); fi
      [ -n "$nonce" ] || nonce="no-random-source"
      ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo unknown-time)
      ( umask 077; printf 'created=%s nonce=%s\n' "$ts" "$nonce" > "$marker" )
      if [ -f "$marker" ]; then
        kv "marker created" "yes"
        kv "rerun instruction" "rerun later with the same --persistence-dir"
        kv "cleanup" "remove $marker when finished"
      else
        kv "marker created" "failed"
      fi
    else
      kv "persistence directory" "missing or not writable"
    fi
  fi
else
  kv "status" "skipped; use --persistence-dir DIR to opt in"
fi

section "INTENTIONALLY NOT PROBED"
printf '%s\n' \
  "  secrets / environment variables / tokens / credentials" \
  "  browser cookies, profiles, saved passwords, or auth databases" \
  "  SSH keys/config, Git credential stores, cloud CLI credentials" \
  "  arbitrary file contents or directory listings" \
  "  process command lines" \
  "  cloud metadata services or public egress IP" \
  "  remote port scans" \
  "  sustained CPU/RAM/disk/network benchmarks" \
  "  package installation or privilege escalation" \
  "  cross-session process survival (requires a deliberate two-phase test)" \
  "  browser automation capabilities (must be tested through the agent/browser layer)"

section "END"
kv "result" "probe completed"
