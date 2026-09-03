#!/usr/bin/env bash
# agent_env_probe.sh
# Standardized environment + capability probe for agentic sandboxes/VMs.
# One command, zero modes. Performs bounded inventory and active capability tests.
# Avoids secrets, private file contents, browser profiles/cookies, process command
# lines, SSH/Git/cloud credentials, cloud metadata, public-IP discovery, port
# scanning, and sustained stress benchmarks.

set -u
set -o pipefail

VERSION="2.3.1"

if [ "$#" -ne 0 ]; then
  echo "Usage: ./agent_env_probe.sh" >&2
  echo "This probe has no modes or options; run it with no arguments." >&2
  exit 2
fi

PY_PACKAGE="packaging==26.3"
PY_WHEEL_GLOB="packaging-26.3-*.whl"
PY_WHEEL_SHA256="d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c"

MS_PACKAGE="ms@2.1.3"
MS_TARBALL="ms-2.1.3.tgz"
MS_INTEGRITY="sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA=="

ZOD_PACKAGE="zod@4.5.4"
ZOD_TARBALL="zod-4.5.4.tgz"
ZOD_INTEGRITY="sha512-sC95tT5iHHH9gtpj6A81kh+NEaRAUFN+qlUPDUbRfOMvNf5QCBqsb3WgvnpVtK5Y+4UfA6KqufotuTvMGiTlsA=="

DENO_VERSION="2.9.6"
DENO_SHA_LINUX_X86_64="394f07f4da2bebe6ce6f1e7ce0fa16429b29b08c35e3fac3fe25972676dff4b2"
DENO_SHA_LINUX_AARCH64="9a46afc6c392c7cd2ff71a31558935545b46408d0e87f7a86908c712721c046e"
DENO_SHA_DARWIN_X86_64="7d4524b82bcc557fe020a1a5b56956ed42b992ae5b28026e8ad5d17329533f5f"
DENO_SHA_DARWIN_AARCH64="213a2f304f04d3c9cb5220669afad138f60a5aab1fe80962abdeb8f35807a472"

PROBE_TMP=""
APT_HELLO_INSTALLED=0
APT_PRIV_MODE=""

have() { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n===== %s =====\n' "$1"; }
kv() { printf '%-32s %s\n' "$1:" "$2"; }
first_line() { bounded 8 "$@" 2>&1 | sed -n '1p' | tr '\t' ' '; }
read_file_line() { [ -r "$1" ] && sed -n '1p' "$1" 2>/dev/null || true; }

redact_line() {
  sed -E \
    -e 's/(Bearer|bearer)[[:space:]]+[A-Za-z0-9._~+\/=:-]+/\1 <REDACTED>/g' \
    -e 's/(token|password|passwd|secret|api[_-]?key)[[:space:]]*[:=][[:space:]]*[^[:space:]]+/\1=<REDACTED>/Ig' \
    -e 's/(AKIA|ASIA)[A-Z0-9]{16}/<AWS_KEY_REDACTED>/g' \
    -e 's/(gh[pousr]_[A-Za-z0-9_]{20,})/<GITHUB_TOKEN_REDACTED>/g'
}

safe_version() {
  local cmd=$1 out="" rc=0
  if ! have "$cmd"; then
    printf '%-20s %s\n' "$cmd" "absent"
    return
  fi

  case "$cmd" in
    python|python3|pip|pip3|uv|node|npm|pnpm|yarn|bun|deno|rustc|cargo|gcc|g++|clang|cmake|make|ninja|meson|git|gh|docker|podman|buildah|kubectl|helm|terraform|ansible|curl|wget|jq|rg|sqlite3|ffmpeg|pandoc|tesseract|java|javac|dotnet|ruby|php|swift|swiftc|gfortran|corepack|npx|tsc|ts-node|pipx|ipython|jupyter|pytest|cython|numba|hf|playwright|ant|pkg-config|autoconf|automake|zip|tar|gzip|bzip2|xz|zstd|file|strings|readelf|objdump|nm|lsns|unshare|nsenter|chroot|findmnt|socat|rsync|weasyprint|cairosvg|inkscape|latex|pdflatex|xelatex|lualatex|ffprobe|sox|gpg)
      out=$(first_line "$cmd" --version)
      ;;
    go)
      out=$(first_line go version)
      ;;
    perl)
      out=$(bounded 8 perl -v 2>&1 | awk 'NF {print; exit}')
      ;;
    R)
      out=$(first_line R --version)
      ;;
    kotlin|kotlinc)
      out=$(first_line "$cmd" -version)
      ;;
    libreoffice|soffice)
      out=$(first_line "$cmd" --version)
      ;;
    convert)
      out=$(bounded 8 convert -version 2>/dev/null | sed -n '1p')
      ;;
    magick)
      out=$(bounded 8 magick -version 2>/dev/null | sed -n '1p')
      ;;
    gs)
      out=$(first_line gs --version)
      ;;
    pdftotext|pdfinfo|pdftoppm|pdfimages|pdfunite)
      out=$(first_line "$cmd" -v)
      ;;
    ssh)
      out=$(bounded 8 ssh -V 2>&1 | sed -n '1p')
      ;;
    psql)
      out=$(first_line psql --version)
      ;;
    mysql)
      out=$(bounded 8 mysql --version 2>&1 | sed -n '1p')
      ;;
    redis-cli)
      out=$(bounded 8 redis-cli --version 2>&1 | sed -n '1p')
      ;;
    chromium|chromium-browser|google-chrome|google-chrome-stable|firefox)
      out=$(first_line "$cmd" --version)
      ;;
    unzip)
      out=$(bounded 8 unzip -v 2>/dev/null | sed -n '1p')
      ;;
    capsh)
      out=$(bounded 8 capsh --help 2>&1 | sed -n '1p')
      ;;
    ip)
      out=$(bounded 8 ip -Version 2>&1 | sed -n '1p')
      ;;
    ping)
      out=$(bounded 8 ping -V 2>&1 | sed -n '1p')
      ;;
    dot)
      out=$(bounded 8 dot -V 2>&1 | sed -n '1p')
      ;;
    openssl)
      out=$(bounded 8 openssl version 2>&1 | sed -n '1p')
      ;;
    torchrun|xvfb-run|getcap|nc)
      out="present"
      ;;
    *)
      out="present"
      ;;
  esac

  rc=$?
  if [ "$rc" -eq 124 ]; then
    out="TIMEOUT"
  elif [ "$rc" -eq 125 ]; then
    out="SKIP: timeout utility unavailable"
  fi

  out=$(printf '%s' "$out" | redact_line | cut -c1-220)
  [ -n "$out" ] || out="present (version unavailable)"
  printf '%-20s %s\n' "$cmd" "$out"
}

bytes_human() {
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

effective_cpu_threads() {
  local n=1 q p quota
  if have nproc; then n=$(nproc 2>/dev/null || echo 1); fi
  printf '%s' "$n" | grep -Eq '^[0-9]+$' || n=1
  [ "$n" -ge 1 ] 2>/dev/null || n=1
  if [ -r /sys/fs/cgroup/cpu.max ]; then
    read -r q p < /sys/fs/cgroup/cpu.max 2>/dev/null || true
    if printf '%s' "${q:-}" | grep -Eq '^[0-9]+$' && printf '%s' "${p:-}" | grep -Eq '^[0-9]+$' && [ "$p" -gt 0 ]; then
      quota=$(( (q + p - 1) / p ))
      [ "$quota" -ge 1 ] || quota=1
      [ "$quota" -lt "$n" ] && n="$quota"
    fi
  fi
  printf '%s' "$n"
}

cpu_isa_inventory() {
  local arch flags="" feature found=""
  arch=$(uname -m 2>/dev/null || echo unknown)
  if have lscpu; then
    flags=$(lscpu 2>/dev/null | awk -F: '/^(Flags|Features):/ {sub(/^[ \t]+/,"",$2); print $2; exit}' || true)
  fi
  if [ -z "$flags" ] && [ -r /proc/cpuinfo ]; then
    flags=$(awk -F: '/^(flags|Features)[[:space:]]*:/ {sub(/^[ \t]+/,"",$2); print $2; exit}' /proc/cpuinfo 2>/dev/null || true)
  fi

  case "$arch" in
    x86_64|amd64|i?86)
      for feature in sse4_2 avx avx2 avx512f avx512bw avx512vl fma aes sha_ni amx_tile amx_int8 amx_bf16; do
        if printf ' %s ' "$flags" | grep -Fq " $feature "; then
          found="${found}${found:+,}$feature"
        fi
      done
      ;;
    aarch64|arm64|arm*)
      for feature in asimd fp16 sve sve2 aes sha1 sha2 crc32; do
        if printf ' %s ' "$flags" | grep -Fq " $feature "; then
          found="${found}${found:+,}$feature"
        fi
      done
      ;;
  esac
  kv "CPU ISA highlights" "${found:-none/hidden}"
}

bounded() {
  local secs=$1
  shift
  if have timeout; then
    timeout "${secs}s" "$@"
  elif have gtimeout; then
    gtimeout "${secs}s" "$@"
  else
    return 125
  fi
}

ensure_probe_tmp() {
  [ -n "$PROBE_TMP" ] && [ -d "$PROBE_TMP" ] && return 0
  [ -d /tmp ] && [ -w /tmp ] || return 1
  PROBE_TMP=$(mktemp -d /tmp/agent-env-probe.XXXXXX 2>/dev/null || true)
  [ -n "$PROBE_TMP" ] && [ -d "$PROBE_TMP" ]
}

cleanup_probe_tmp() {
  case "${PROBE_TMP:-}" in
    /tmp/agent-env-probe.*) rm -rf -- "$PROBE_TMP" 2>/dev/null || true ;;
  esac
}

cleanup_on_exit() {
  if [ "$APT_HELLO_INSTALLED" -eq 1 ] && [ -n "$APT_PRIV_MODE" ]; then
    run_priv_bounded 60 "$APT_PRIV_MODE" env DEBIAN_FRONTEND=noninteractive LC_ALL=C \
      apt-get -y -o Acquire::Retries=0 -o Dpkg::Use-Pty=0 purge hello >/dev/null 2>&1 || true
  fi
  cleanup_probe_tmp
}
trap cleanup_on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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
    bounded 120 wget -q --https-only --timeout=15 --tries=1 -O "$out" "$url" >/dev/null 2>&1
    return $?
  fi
  return 127
}

npm_file_integrity() {
  local node_bin=$1 file=$2 minpath=$3
  env -i PATH="$minpath" HOME=/tmp LANG=C "$node_bin" -e \
    'const fs=require("fs"),c=require("crypto"); process.stdout.write("sha512-"+c.createHash("sha512").update(fs.readFileSync(process.argv[1])).digest("base64"))' \
    "$file" 2>/dev/null || true
}

root_mode() {
  if [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
    printf 'root'
  elif have sudo && sudo -n true >/dev/null 2>&1; then
    printf 'sudo'
  else
    printf 'blocked'
  fi
}

run_priv_bounded() {
  local secs=$1 mode=$2
  shift 2
  case "$mode" in
    root) bounded "$secs" "$@" ;;
    sudo) bounded "$secs" sudo -n "$@" ;;
    *) return 126 ;;
  esac
}

local_socket_test() {
  section "LOCAL SOCKET TEST"
  local py="" rc
  if have python3; then py=$(command -v python3); elif have python; then py=$(command -v python); fi
  [ -n "$py" ] || { kv "127.0.0.1 TCP bind/connect" "SKIP: Python absent"; return; }

  bounded 8 "$py" -I -c '
import socket, sys
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
accepted = None
try:
    server.settimeout(2)
    client.settimeout(2)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    client.connect(("127.0.0.1", port))
    accepted, addr = server.accept()
    accepted.settimeout(2)
    client.sendall(b"probe")
    data = accepted.recv(5)
    sys.exit(0 if data == b"probe" else 1)
finally:
    if accepted is not None:
        accepted.close()
    client.close()
    server.close()
' >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] && kv "127.0.0.1 TCP bind/connect" "PASS (ephemeral port)" || kv "127.0.0.1 TCP bind/connect" "FAIL/BLOCKED (exit $rc)"
}

gcc_compile_test() {
  section "GCC COMPILE TEST"
  local d src bin out rc
  have gcc || { kv "gcc compile" "SKIP: gcc absent"; return; }
  ensure_probe_tmp || { kv "gcc temp_dir" "BLOCKED"; return; }
  d="$PROBE_TMP/gcc"
  mkdir -p "$d" || { kv "gcc temp_setup" "BLOCKED"; return; }
  src="$d/probe.c"
  bin="$d/probe-bin"
  cat > "$src" <<'EOF_C'
#include <stdio.h>
int main(void) {
  puts("agent-gcc-probe");
  return 0;
}
EOF_C

  bounded 15 gcc -std=c11 -O0 -o "$bin" "$src" >/dev/null 2>&1
  rc=$?
  if [ "$rc" -ne 0 ]; then
    kv "gcc compile" "FAIL/BLOCKED (exit $rc)"
    rm -f "$src" "$bin" 2>/dev/null || true
    return
  fi
  kv "gcc compile" "PASS"

  out=$(bounded 5 "$bin" 2>/dev/null | sed -n '1p' || true)
  [ "$out" = "agent-gcc-probe" ] && kv "gcc binary execution" "PASS" || kv "gcc binary execution" "FAIL"
  rm -f "$src" "$bin" 2>/dev/null || true
  if [ ! -e "$src" ] && [ ! -e "$bin" ]; then
    kv "gcc test cleanup" "PASS"
  else
    kv "gcc test cleanup" "FAIL"
  fi
}

python_ml_inventory() {
  section "ML / NUMERICAL STACK"
  local py="" mod dist label out rc minpath
  if have python3; then py=$(command -v python3); elif have python; then py=$(command -v python); fi
  [ -n "$py" ] || { kv "ml.python" "SKIP: Python absent"; return; }
  minpath="$(dirname "$py"):/usr/local/bin:/usr/bin:/bin"

  while IFS='|' read -r mod dist label; do
    [ -n "$mod" ] || continue
    out=$(bounded 10 env PATH="$minpath" LANG=C HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false TF_CPP_MIN_LOG_LEVEL=3 \
      "$py" -I -c '
import importlib, importlib.metadata as md, sys
mod, dist = sys.argv[1], sys.argv[2]
m = importlib.import_module(mod)
v = getattr(m, "__version__", None)
if v is None:
    try:
        v = md.version(dist)
    except Exception:
        v = "present"
print(str(v))
' "$mod" "$dist" 2>/dev/null)
    rc=$?
    if [ "$rc" -eq 0 ] && [ -n "$out" ]; then
      kv "ml.$label" "$(printf '%s' "$out" | sed -n '1p' | cut -c1-180)"
    elif [ "$rc" -eq 124 ]; then
      kv "ml.$label" "BLOCKED/TIMEOUT"
    else
      kv "ml.$label" "absent/unavailable"
    fi
  done <<'EOF_ML_MODULES'
numpy|numpy|numpy
scipy|scipy|scipy
sklearn|scikit-learn|sklearn
torch|torch|torch
tensorflow|tensorflow|tensorflow
jax|jax|jax
transformers|transformers|transformers
tokenizers|tokenizers|tokenizers
onnx|onnx|onnx
onnxruntime|onnxruntime|onnxruntime
accelerate|accelerate|accelerate
sentence_transformers|sentence-transformers|sentence_transformers
EOF_ML_MODULES

  out=$(bounded 8 "$py" -I -c '
import contextlib, io, re
import numpy as np
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    np.show_config()
text = buf.getvalue().lower()
names = []
for name in ("mkl", "openblas", "blis", "accelerate", "flexiblas", "netlib"):
    if name in text and name not in names:
        names.append(name)
print(",".join(names) or "unknown")
' 2>/dev/null)
  rc=$?
  [ "$rc" -eq 0 ] && kv "numpy BLAS backend" "${out:-unknown}" || kv "numpy BLAS backend" "unavailable"

  out=$(bounded 10 "$py" -I -c 'import jax; print(jax.default_backend())' 2>/dev/null)
  rc=$?
  [ "$rc" -eq 0 ] && [ -n "$out" ] && kv "jax default backend" "$(printf '%s' "$out" | sed -n '1p')" || true

  out=$(bounded 10 env TF_CPP_MIN_LOG_LEVEL=3 "$py" -I -c 'import tensorflow as tf; print(len(tf.config.list_physical_devices("GPU")))' 2>/dev/null)
  rc=$?
  [ "$rc" -eq 0 ] && [ -n "$out" ] && kv "tensorflow GPU devices" "$(printf '%s' "$out" | sed -n '1p')" || true

  out=$(bounded 8 "$py" -I -c 'import onnxruntime as ort; print(",".join(ort.get_available_providers()))' 2>/dev/null)
  rc=$?
  [ "$rc" -eq 0 ] && [ -n "$out" ] && kv "onnxruntime providers" "$(printf '%s' "$out" | sed -n '1p' | cut -c1-180)" || true
}

cpu_ml_benchmark() {
  section "CPU NUMERICAL / ML TEST"
  local py="" threads out rc minpath
  if have python3; then py=$(command -v python3); elif have python; then py=$(command -v python); fi
  [ -n "$py" ] || { kv "cpu.numpy_matmul" "SKIP: Python absent"; kv "torch.cpu_execution" "SKIP: Python absent"; return; }
  minpath="$(dirname "$py"):/usr/local/bin:/usr/bin:/bin"
  threads=$(effective_cpu_threads)
  kv "cpu.numeric_threads" "$threads"

  out=$(bounded 20 env PATH="$minpath" LANG=C \
    OMP_NUM_THREADS="$threads" OPENBLAS_NUM_THREADS="$threads" MKL_NUM_THREADS="$threads" \
    BLIS_NUM_THREADS="$threads" VECLIB_MAXIMUM_THREADS="$threads" NUMEXPR_NUM_THREADS="$threads" \
    "$py" -I -c '
import statistics, time
import numpy as np
n = 1024
a = np.ones((n, n), dtype=np.float32)
b = np.ones((n, n), dtype=np.float32)
_ = a @ b
times = []
for _ in range(3):
    t0 = time.perf_counter()
    c = a @ b
    times.append(time.perf_counter() - t0)
if float(c[0, 0]) != float(n):
    raise SystemExit(2)
med = statistics.median(times)
gflops = (2.0 * n * n * n) / med / 1e9
print(f"{med*1000:.3f}|{gflops:.2f}")
' 2>/dev/null)
  rc=$?
  if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q '|'; then
    kv "cpu.numpy_matmul_1024_f32_ms" "$(printf '%s' "$out" | cut -d'|' -f1)"
    kv "cpu.numpy_matmul_1024_GFLOPs" "$(printf '%s' "$out" | cut -d'|' -f2)"
  elif [ "$rc" -eq 124 ]; then
    kv "cpu.numpy_matmul" "BLOCKED/TIMEOUT"
  else
    kv "cpu.numpy_matmul" "SKIP/FAIL: NumPy unavailable or execution failed (exit $rc)"
  fi

  bounded 12 env PATH="$minpath" LANG=C OMP_NUM_THREADS="$threads" MKL_NUM_THREADS="$threads" \
    "$py" -I -c '
import torch
torch.set_grad_enabled(False)
try:
    torch.set_num_threads(int(__import__("os").environ.get("OMP_NUM_THREADS", "1")))
except Exception:
    pass
a = torch.ones((256, 256), dtype=torch.float32)
c = a @ a
raise SystemExit(0 if float(c[0, 0]) == 256.0 else 2)
' >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] && kv "torch.cpu_execution" "PASS" || kv "torch.cpu_execution" "SKIP/FAIL (exit $rc)"
}

gpu_ml_capability_test() {
  section "GPU / ML CAPABILITY AND EXECUTION"
  local py="" out rc
  if have python3; then py=$(command -v python3); elif have python; then py=$(command -v python); fi
  [ -n "$py" ] || { kv "torch GPU probe" "SKIP: Python absent"; return; }

  out=$(bounded 30 env LANG=C PYTORCH_ENABLE_MPS_FALLBACK=0 "$py" -I -c '
import statistics, time
try:
    import torch
except Exception:
    raise SystemExit(10)

def emit(k, v):
    print(f"{k}|{v}")

emit("torch_version", getattr(torch, "__version__", "unknown"))
emit("torch_cuda_build", getattr(torch.version, "cuda", None) or "none")
emit("torch_hip_build", getattr(torch.version, "hip", None) or "none")

backend = None
device = None
sync = lambda: None

cuda_ok = bool(getattr(torch, "cuda", None) and torch.cuda.is_available())
mps_ok = bool(hasattr(torch.backends, "mps") and torch.backends.mps.is_available())
xpu_ok = bool(hasattr(torch, "xpu") and torch.xpu.is_available())

emit("torch_cuda_available", str(cuda_ok).lower())
emit("torch_mps_available", str(mps_ok).lower())
emit("torch_xpu_available", str(xpu_ok).lower())

if cuda_ok:
    backend = "rocm" if getattr(torch.version, "hip", None) else "cuda"
    device = torch.device("cuda:0")
    sync = torch.cuda.synchronize
    count = torch.cuda.device_count()
    emit("backend", backend)
    emit("device_count", count)
    for i in range(min(count, 4)):
        p = torch.cuda.get_device_properties(i)
        name = str(p.name).replace("|", "/").replace("\n", " ")
        mem_gib = float(p.total_memory) / (1024**3)
        detail = f"{name}; vram={mem_gib:.2f} GiB"
        if backend == "cuda":
            try:
                cc = torch.cuda.get_device_capability(i)
                detail += f"; compute={cc[0]}.{cc[1]}"
            except Exception:
                pass
        else:
            arch = getattr(p, "gcnArchName", None)
            if arch:
                detail += f"; arch={arch}"
        emit(f"device_{i}", detail)
    try:
        emit("bf16_reported", str(bool(torch.cuda.is_bf16_supported())).lower())
    except Exception:
        emit("bf16_reported", "unknown")
elif mps_ok:
    backend = "mps"
    device = torch.device("mps")
    sync = torch.mps.synchronize
    emit("backend", backend)
    emit("device_count", 1)
elif xpu_ok:
    backend = "xpu"
    device = torch.device("xpu:0")
    sync = torch.xpu.synchronize
    emit("backend", backend)
    try:
        emit("device_count", torch.xpu.device_count())
        emit("device_0", str(torch.xpu.get_device_name(0)).replace("|", "/").replace("\n", " "))
    except Exception:
        pass
else:
    emit("backend", "none")
    emit("execution", "SKIP: no usable GPU backend")
    raise SystemExit(0)

torch.set_grad_enabled(False)
try:
    a = torch.ones((512, 512), device=device, dtype=torch.float32)
    b = torch.ones((512, 512), device=device, dtype=torch.float32)
    c = a @ b
    sync()
    ok = abs(float(c[0, 0].item()) - 512.0) < 0.01
    emit("execution", "PASS" if ok else "FAIL: wrong result")
    if not ok:
        raise SystemExit(2)
except Exception as e:
    emit("execution", "FAIL/BLOCKED")
    raise SystemExit(3)

for dtype_name, dtype in (("fp16", torch.float16), ("bf16", torch.bfloat16)):
    try:
        a = torch.ones((32, 32), device=device, dtype=dtype)
        c = a @ a
        sync()
        ok = abs(float(c[0, 0].item()) - 32.0) < 0.5
        emit(f"{dtype_name}_matmul", "PASS" if ok else "FAIL")
    except Exception:
        emit(f"{dtype_name}_matmul", "UNAVAILABLE")

try:
    n = 2048
    a = torch.ones((n, n), device=device, dtype=torch.float32)
    b = torch.ones((n, n), device=device, dtype=torch.float32)
    _ = a @ b
    sync()
    times = []
    for _ in range(3):
        t0 = time.perf_counter()
        c = a @ b
        sync()
        times.append(time.perf_counter() - t0)
    if abs(float(c[0, 0].item()) - float(n)) >= 0.01:
        raise RuntimeError("wrong result")
    med = statistics.median(times)
    gflops = (2.0 * n * n * n) / med / 1e9
    emit("matmul_2048_f32_ms", f"{med*1000:.3f}")
    emit("matmul_2048_GFLOPs", f"{gflops:.2f}")
except Exception:
    emit("benchmark", "FAIL/BLOCKED")
' 2>/dev/null)
  rc=$?

  if [ "$rc" -eq 10 ]; then
    kv "torch GPU probe" "SKIP: torch absent/unavailable"
    return
  fi
  if [ "$rc" -eq 124 ]; then
    kv "torch GPU probe" "BLOCKED/TIMEOUT"
    return
  fi
  if [ -n "$out" ]; then
    while IFS='|' read -r key value; do
      [ -n "$key" ] || continue
      kv "gpu.$key" "$(printf '%s' "$value" | cut -c1-190)"
    done <<EOF_GPU_OUT
$out
EOF_GPU_OUT
    if [ "$rc" -ne 0 ]; then
      kv "torch GPU probe" "FAIL/BLOCKED (exit $rc; partial results above)"
    fi
  else
    kv "torch GPU probe" "FAIL/BLOCKED (exit $rc)"
  fi
}


ROOTLESS_UID=""
ROOTLESS_GID=""
ROOTLESS_NAME=""
ROOTLESS_MODE=""
ROOTLESS_PY=""

prepare_rootless_identity() {
  local uid gid name py=""
  uid=$(id -u 2>/dev/null || echo unknown)
  gid=$(id -g 2>/dev/null || echo unknown)
  if [ "$uid" != "0" ] && printf '%s' "$uid" | grep -Eq '^[0-9]+$'; then
    ROOTLESS_UID="$uid"
    ROOTLESS_GID="$gid"
    ROOTLESS_NAME=$(id -un 2>/dev/null || true)
    ROOTLESS_MODE="current"
    return 0
  fi

  if id nobody >/dev/null 2>&1; then
    ROOTLESS_UID=$(id -u nobody 2>/dev/null || echo 65534)
    ROOTLESS_GID=$(id -g nobody 2>/dev/null || echo 65534)
    ROOTLESS_NAME="nobody"
  else
    ROOTLESS_UID="65534"
    ROOTLESS_GID="65534"
    if have getent; then ROOTLESS_NAME=$(getent passwd 65534 2>/dev/null | awk -F: 'NR==1 {print $1}' || true); fi
  fi

  if have setpriv; then
    ROOTLESS_MODE="setpriv"
    return 0
  fi
  if have python3; then py=$(command -v python3); elif have python; then py=$(command -v python); fi
  if [ -n "$py" ]; then
    ROOTLESS_PY="$py"
    ROOTLESS_MODE="python-drop"
    return 0
  fi
  ROOTLESS_MODE="unavailable"
  return 1
}

run_rootless_bounded() {
  local secs=$1
  shift
  case "$ROOTLESS_MODE" in
    current)
      bounded "$secs" "$@"
      ;;
    setpriv)
      bounded "$secs" setpriv         --reuid="$ROOTLESS_UID" --regid="$ROOTLESS_GID" --clear-groups         --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- "$@"
      ;;
    python-drop)
      bounded "$secs" "$ROOTLESS_PY" -I -c '
import ctypes, os, sys
uid, gid = int(sys.argv[1]), int(sys.argv[2])
cmd = sys.argv[3:]
os.setgroups([])
os.setgid(gid)
os.setuid(uid)
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
    raise SystemExit(126)
os.execvp(cmd[0], cmd)
' "$ROOTLESS_UID" "$ROOTLESS_GID" "$@"
      ;;
    *)
      return 126
      ;;
  esac
}

rootless_level1_test() {
  section "ROOTLESS LEVEL 1 / KERNEL NAMESPACES"
  local rc v
  if ! prepare_rootless_identity; then
    kv "rootless test identity" "BLOCKED: cannot obtain unprivileged execution identity"
    return
  fi
  if [ "$ROOTLESS_MODE" = "current" ]; then
    kv "rootless test identity" "uid=$ROOTLESS_UID gid=$ROOTLESS_GID (current non-root user)"
  else
    kv "rootless test identity" "uid=$ROOTLESS_UID gid=$ROOTLESS_GID (privileges deliberately dropped)"
  fi

  if [ -r /proc/sys/kernel/unprivileged_userns_clone ]; then
    v=$(read_file_line /proc/sys/kernel/unprivileged_userns_clone)
    kv "unprivileged_userns_clone" "${v:-unknown}"
  else
    kv "unprivileged_userns_clone" "not exposed"
  fi
  if [ -r /proc/sys/user/max_user_namespaces ]; then
    v=$(read_file_line /proc/sys/user/max_user_namespaces)
    kv "max_user_namespaces" "${v:-unknown}"
  else
    kv "max_user_namespaces" "not exposed"
  fi

  have unshare || {
    kv "rootless.user_namespace" "SKIP: unshare absent"
    kv "rootless.uid0_mapping" "SKIP: unshare absent"
    kv "rootless.mount_namespace" "SKIP: unshare absent"
    kv "rootless.pid_namespace" "SKIP: unshare absent"
    kv "rootless.proc_mount" "SKIP: unshare absent"
    return
  }

  (cd /tmp && run_rootless_bounded 8 unshare --user sh -c 'true') >/dev/null 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    kv "rootless.user_namespace" "PASS"
  else
    kv "rootless.user_namespace" "FAIL/BLOCKED (exit $rc)"
    kv "rootless.uid0_mapping" "SKIP: user namespace unavailable"
    kv "rootless.mount_namespace" "SKIP: user namespace unavailable"
    kv "rootless.pid_namespace" "SKIP: user namespace unavailable"
    kv "rootless.proc_mount" "SKIP: user namespace unavailable"
    return
  fi

  (cd /tmp && run_rootless_bounded 8 unshare --user --map-root-user sh -c 'test "$(id -u)" = 0') >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] && kv "rootless.uid0_mapping" "PASS" || kv "rootless.uid0_mapping" "FAIL/BLOCKED (exit $rc)"

  (cd /tmp && run_rootless_bounded 8 unshare --user --map-root-user --mount sh -c 'test "$(id -u)" = 0 && test -r /proc/self/mountinfo') >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] && kv "rootless.mount_namespace" "PASS" || kv "rootless.mount_namespace" "FAIL/BLOCKED (exit $rc)"

  (cd /tmp && run_rootless_bounded 8 unshare --user --map-root-user --pid --fork sh -c 'test "$$" -eq 1') >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] && kv "rootless.pid_namespace" "PASS (child is PID 1)" || kv "rootless.pid_namespace" "FAIL/BLOCKED (exit $rc)"

  (cd /tmp && run_rootless_bounded 8 unshare --user --map-root-user --mount --pid --fork --mount-proc sh -c 'test "$$" -eq 1 && test -r /proc/1/status') >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] && kv "rootless.proc_mount" "PASS" || kv "rootless.proc_mount" "FAIL/BLOCKED (exit $rc)"
}

rootless_level2_inventory() {
  section "ROOTLESS LEVEL 2 / SUPPORT COMPONENTS"
  local file cg_rel cg_dir rc
  prepare_rootless_identity >/dev/null 2>&1 || true

  for x in newuidmap newgidmap fuse-overlayfs slirp4netns pasta runc crun bwrap proot rootlesskit dockerd-rootless.sh; do
    safe_version "$x"
  done
  kv "/dev/fuse present" "$([ -e /dev/fuse ] && echo yes || echo no)"

  for kind in subuid subgid; do
    file="/etc/$kind"
    if [ ! -r "$file" ]; then
      kv "$kind entry for test user" "unavailable"
    elif [ -z "$ROOTLESS_NAME" ]; then
      kv "$kind entry for test user" "unknown: no account name"
    elif awk -F: -v u="$ROOTLESS_NAME" '$1==u {found=1} END {exit !found}' "$file" 2>/dev/null; then
      kv "$kind entry for test user" "yes"
    else
      kv "$kind entry for test user" "no"
    fi
  done

  if [ -r /sys/fs/cgroup/cgroup.controllers ]; then
    kv "cgroup v2" "yes"
    cg_rel=$(awk -F: '$1=="0" {print $3; exit}' /proc/self/cgroup 2>/dev/null || true)
    cg_dir="/sys/fs/cgroup${cg_rel:-/}"
    if [ "$ROOTLESS_MODE" = "unavailable" ]; then
      kv "cgroup delegation writable" "unknown: no unprivileged identity"
    else
      run_rootless_bounded 5 sh -c 'test -w "$1/cgroup.procs"' sh "$cg_dir" >/dev/null 2>&1
      rc=$?
      [ "$rc" -eq 0 ] && kv "cgroup delegation writable" "yes" || kv "cgroup delegation writable" "no/blocked"
    fi
  else
    kv "cgroup v2" "no/not exposed"
    kv "cgroup delegation writable" "not applicable/unknown"
  fi
}

prepare_rootless_runtime_tmp() {
  local d=$1
  mkdir -p "$d/home" "$d/run" "$d/tmp" || return 1
  if [ "$ROOTLESS_MODE" != "current" ] && [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
    chown -R "$ROOTLESS_UID:$ROOTLESS_GID" "$d" 2>/dev/null || return 1
  fi
  chmod 700 "$d/home" "$d/run" "$d/tmp" 2>/dev/null || true
}

rootless_level3_runtime() {
  section "ROOTLESS LEVEL 3 / INSTALLED RUNTIMES"
  local d path_default out rc sock podman_bin docker_bin
  prepare_rootless_identity >/dev/null 2>&1 || {
    kv "rootless.podman_info" "SKIP: no unprivileged test identity"
    kv "rootless.docker_info" "SKIP: no unprivileged test identity"
    return
  }
  ensure_probe_tmp || {
    kv "rootless.podman_info" "BLOCKED: temp directory unavailable"
    kv "rootless.docker_info" "BLOCKED: temp directory unavailable"
    return
  }
  d="$PROBE_TMP/rootless-runtime"
  prepare_rootless_runtime_tmp "$d" || {
    kv "rootless.podman_info" "BLOCKED: temp setup failed"
    kv "rootless.docker_info" "BLOCKED: temp setup failed"
    return
  }
  path_default="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

  if have podman; then
    podman_bin=$(command -v podman)
    out=$(run_rootless_bounded 20 env -i PATH="$path_default" HOME="$d/home" XDG_RUNTIME_DIR="$d/run" TMPDIR="$d/tmp" LANG=C       "$podman_bin" info --format '{{.Host.Security.Rootless}}' 2>/dev/null | sed -n '1p' || true)
    if [ "$out" = "true" ]; then
      kv "rootless.podman_info" "PASS (rootless=true; no container created)"
    elif [ -n "$out" ]; then
      kv "rootless.podman_info" "FAIL/UNEXPECTED ($out)"
    else
      kv "rootless.podman_info" "FAIL/BLOCKED (no usable rootless info)"
    fi
  else
    kv "rootless.podman_info" "SKIP: podman absent"
  fi

  if have docker; then
    docker_bin=$(command -v docker)
    sock="/run/user/$ROOTLESS_UID/docker.sock"
    if [ ! -S "$sock" ]; then
      kv "rootless.docker_info" "SKIP: no conventional rootless daemon socket"
    else
      out=$(run_rootless_bounded 15 env -i PATH="$path_default" HOME="$d/home" LANG=C DOCKER_HOST="unix://$sock"         "$docker_bin" info --format '{{json .SecurityOptions}}' 2>/dev/null | sed -n '1p' || true)
      if printf '%s' "$out" | grep -qi 'rootless'; then
        kv "rootless.docker_info" "PASS (rootless security option reported)"
      elif [ -n "$out" ]; then
        kv "rootless.docker_info" "FAIL: daemon reachable but rootless not reported"
      else
        kv "rootless.docker_info" "FAIL/BLOCKED: rootless daemon query failed"
      fi
    fi
  else
    kv "rootless.docker_info" "SKIP: docker absent"
  fi
}


python_package_test() {
  section "PYTHON / PYPI PACKAGE TEST"
  local py="" d wheel actual rc minpath
  if have python3; then py=$(command -v python3); elif have python; then py=$(command -v python); fi
  [ -n "$py" ] || { kv "python.runtime" "SKIP: absent"; return; }
  "$py" -m pip --version >/dev/null 2>&1 || { kv "python.pip" "SKIP: unavailable"; return; }
  ensure_probe_tmp || { kv "python.temp_dir" "BLOCKED"; return; }
  d="$PROBE_TMP/python"
  mkdir -p "$d/home" "$d/download" "$d/site" || { kv "python.temp_setup" "BLOCKED"; return; }
  minpath="$(dirname "$py"):/usr/local/bin:/usr/bin:/bin"

  kv "python.test_package" "$PY_PACKAGE"
  bounded 35 env -i PATH="$minpath" HOME="$d/home" LANG=C PIP_CONFIG_FILE=/dev/null \
    "$py" -m pip --isolated download --disable-pip-version-check --no-input \
    --index-url https://pypi.org/simple --timeout 8 --retries 0 \
    --only-binary=:all: --no-deps --dest "$d/download" "$PY_PACKAGE" >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || { kv "python.download" "FAIL/BLOCKED (exit $rc)"; return; }
  kv "python.download" "PASS"

  wheel=$(find "$d/download" -maxdepth 1 -type f -name "$PY_WHEEL_GLOB" -print -quit 2>/dev/null || true)
  [ -n "$wheel" ] || { kv "python.wheel" "FAIL: missing"; return; }
  actual=$(sha256_file "$wheel" 2>/dev/null || true)
  [ -n "$actual" ] || { kv "python.sha256" "BLOCKED: hash utility absent"; return; }
  [ "$actual" = "$PY_WHEEL_SHA256" ] || { kv "python.sha256" "FAIL: mismatch"; return; }
  kv "python.sha256" "PASS"

  env -i PATH="$minpath" HOME="$d/home" LANG=C PIP_CONFIG_FILE=/dev/null \
    "$py" -m pip --isolated install --disable-pip-version-check --no-input \
    --no-index --only-binary=:all: --no-deps --target "$d/site" "$wheel" >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || { kv "python.temp_install" "FAIL/BLOCKED (exit $rc)"; return; }
  kv "python.temp_install" "PASS"

  env -i PATH="$minpath" HOME="$d/home" LANG=C "$py" -I -c \
    'import sys; sys.path.insert(0, sys.argv[1]); from packaging.version import Version; raise SystemExit(0 if Version("2.10.0") > Version("2.9.0") else 1)' \
    "$d/site" >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] && kv "python.execution" "PASS" || kv "python.execution" "FAIL (exit $rc)"
}

node_package_test() {
  section "NODE / NPM PACKAGE TESTS"
  local node_bin npm_bin d minpath ms_tgz zod_tgz got rc
  have node && have npm || { kv "node/npm" "SKIP: absent"; return; }
  ensure_probe_tmp || { kv "npm.temp_dir" "BLOCKED"; return; }
  node_bin=$(command -v node); npm_bin=$(command -v npm)
  d="$PROBE_TMP/npm"
  mkdir -p "$d/home" "$d/cache" "$d/download" "$d/app" || { kv "npm.temp_setup" "BLOCKED"; return; }
  : > "$d/npmrc"
  minpath="$(dirname "$node_bin"):$(dirname "$npm_bin"):/usr/local/bin:/usr/bin:/bin"

  kv "npm.test_packages" "$MS_PACKAGE, $ZOD_PACKAGE"
  for spec in "$MS_PACKAGE" "$ZOD_PACKAGE"; do
    (cd "$d/download" && bounded 35 env -i PATH="$minpath" HOME="$d/home" LANG=C \
      npm_config_userconfig="$d/npmrc" npm_config_globalconfig="$d/npmrc" npm_config_cache="$d/cache" \
      npm_config_registry="https://registry.npmjs.org/" npm_config_ignore_scripts=true \
      npm_config_audit=false npm_config_fund=false npm_config_fetch_retries=0 \
      npm_config_fetch_timeout=10000 npm_config_fetch_retry_mintimeout=1000 npm_config_fetch_retry_maxtimeout=10000 \
      "$npm_bin" pack --ignore-scripts --silent "$spec" >/dev/null 2>&1)
    rc=$?
    [ "$rc" -eq 0 ] || { kv "npm.download $spec" "FAIL/BLOCKED (exit $rc)"; return; }
    kv "npm.download $spec" "PASS"
  done

  ms_tgz="$d/download/$MS_TARBALL"
  zod_tgz="$d/download/$ZOD_TARBALL"
  [ -f "$ms_tgz" ] && [ -f "$zod_tgz" ] || { kv "npm.tarballs" "FAIL: missing"; return; }

  got=$(npm_file_integrity "$node_bin" "$ms_tgz" "$minpath")
  [ "$got" = "$MS_INTEGRITY" ] || { kv "npm.integrity $MS_PACKAGE" "FAIL"; return; }
  kv "npm.integrity $MS_PACKAGE" "PASS"
  got=$(npm_file_integrity "$node_bin" "$zod_tgz" "$minpath")
  [ "$got" = "$ZOD_INTEGRITY" ] || { kv "npm.integrity $ZOD_PACKAGE" "FAIL"; return; }
  kv "npm.integrity $ZOD_PACKAGE" "PASS"

  bounded 25 env -i PATH="$minpath" HOME="$d/home" LANG=C \
    npm_config_userconfig="$d/npmrc" npm_config_globalconfig="$d/npmrc" npm_config_cache="$d/cache" \
    npm_config_ignore_scripts=true npm_config_audit=false npm_config_fund=false \
    "$npm_bin" install --offline --ignore-scripts --no-audit --no-fund --package-lock=false \
    --prefix "$d/app" "$ms_tgz" "$zod_tgz" >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || { kv "npm.temp_install" "FAIL/BLOCKED (exit $rc)"; return; }
  kv "npm.temp_install" "PASS (scripts disabled)"

  (cd "$d/app" && env -i PATH="$minpath" HOME="$d/home" LANG=C "$node_bin" -e \
    'const ms=require("ms"); process.exit(ms("2s")===2000 ? 0 : 1)' >/dev/null 2>&1)
  rc=$?
  [ "$rc" -eq 0 ] && kv "node.CommonJS ms" "PASS" || kv "node.CommonJS ms" "FAIL (exit $rc)"

  cat > "$d/app/zod-test.mjs" <<'EOF_ZOD'
import { z } from "zod";
const result = z.number().int().safeParse(42);
if (!result.success || result.data !== 42) process.exit(1);
EOF_ZOD
  (cd "$d/app" && env -i PATH="$minpath" HOME="$d/home" LANG=C "$node_bin" ./zod-test.mjs >/dev/null 2>&1)
  rc=$?
  [ "$rc" -eq 0 ] && kv "node.ESM zod" "PASS" || kv "node.ESM zod" "FAIL (exit $rc)"
}

deno_npm_test_with() {
  local deno_bin=$1 label=$2 d rc
  ensure_probe_tmp || { kv "$label.temp_dir" "BLOCKED"; return; }
  d="$PROBE_TMP/$label"
  mkdir -p "$d/home" "$d/cache" || { kv "$label.temp_setup" "BLOCKED"; return; }

  bounded 45 env -i HOME="$d/home" DENO_DIR="$d/cache" DENO_NO_PROMPT=1 NO_COLOR=1 LANG=C \
    "$deno_bin" eval \
    'import ms from "npm:ms@2.1.3"; import { z } from "npm:zod@4.5.4"; const r=z.number().int().safeParse(42); if(ms("2s")!==2000 || !r.success || r.data!==42) Deno.exit(1);' \
    >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] && kv "$label.npm ms+zod" "PASS" || kv "$label.npm ms+zod" "FAIL/BLOCKED (exit $rc)"
}

deno_test() {
  section "DENO / NPM COMPATIBILITY"
  local os arch asset sha url zip actual deno_bin d rc
  if have deno; then
    kv "deno.preinstalled" "yes"
    deno_npm_test_with "$(command -v deno)" "deno.preinstalled"
    kv "deno.portable_download" "SKIP: preinstalled Deno already available"
    return
  fi

  kv "deno.preinstalled" "no"
  os=$(uname -s 2>/dev/null || echo unknown)
  arch=$(uname -m 2>/dev/null || echo unknown)
  case "$os:$arch" in
    Linux:x86_64|Linux:amd64) asset="deno-x86_64-unknown-linux-gnu.zip"; sha="$DENO_SHA_LINUX_X86_64" ;;
    Linux:aarch64|Linux:arm64) asset="deno-aarch64-unknown-linux-gnu.zip"; sha="$DENO_SHA_LINUX_AARCH64" ;;
    Darwin:x86_64|Darwin:amd64) asset="deno-x86_64-apple-darwin.zip"; sha="$DENO_SHA_DARWIN_X86_64" ;;
    Darwin:aarch64|Darwin:arm64) asset="deno-aarch64-apple-darwin.zip"; sha="$DENO_SHA_DARWIN_AARCH64" ;;
    *) kv "deno.portable_download" "SKIP: unsupported $os/$arch"; return ;;
  esac

  ensure_probe_tmp || { kv "deno.temp_dir" "BLOCKED"; return; }
  d="$PROBE_TMP/deno-portable"
  mkdir -p "$d/bin" "$d/home" "$d/cache" || { kv "deno.temp_setup" "BLOCKED"; return; }
  zip="$d/$asset"
  url="https://github.com/denoland/deno/releases/download/v${DENO_VERSION}/${asset}"
  kv "deno.portable_version" "$DENO_VERSION"
  kv "deno.portable_asset" "$asset"

  download_https "$url" "$zip"
  rc=$?
  [ "$rc" -eq 0 ] || { kv "deno.portable_download" "FAIL/BLOCKED (exit $rc)"; return; }
  kv "deno.portable_download" "PASS"

  actual=$(sha256_file "$zip" 2>/dev/null || true)
  [ -n "$actual" ] || { kv "deno.portable_sha256" "BLOCKED: hash utility absent"; return; }
  [ "$actual" = "$sha" ] || { kv "deno.portable_sha256" "FAIL: mismatch"; return; }
  kv "deno.portable_sha256" "PASS"

  if have unzip; then
    unzip -q "$zip" -d "$d/bin" >/dev/null 2>&1; rc=$?
  elif have python3; then
    python3 -m zipfile -e "$zip" "$d/bin" >/dev/null 2>&1; rc=$?
  elif have python; then
    python -m zipfile -e "$zip" "$d/bin" >/dev/null 2>&1; rc=$?
  else
    kv "deno.portable_extract" "BLOCKED: unzip/Python absent"; return
  fi
  [ "$rc" -eq 0 ] || { kv "deno.portable_extract" "FAIL (exit $rc)"; return; }
  deno_bin="$d/bin/deno"
  [ -f "$deno_bin" ] || { kv "deno.portable_extract" "FAIL: binary missing"; return; }
  chmod u+x "$deno_bin" 2>/dev/null || true
  kv "deno.portable_extract" "PASS"

  env -i HOME="$d/home" DENO_DIR="$d/cache" DENO_NO_PROMPT=1 NO_COLOR=1 LANG=C "$deno_bin" --version >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || { kv "deno.portable_execution" "FAIL/BLOCKED (exit $rc)"; return; }
  kv "deno.portable_execution" "PASS"
  deno_npm_test_with "$deno_bin" "deno.portable"
}

apt_hello_test() {
  section "APT SYSTEM PACKAGE TEST"
  local mode before=0 inst_bad rc hello_out after=0
  have apt-get || { kv "apt.present" "SKIP: apt-get absent"; return; }
  have dpkg-query || { kv "apt.dpkg_query" "SKIP: dpkg-query absent"; return; }
  ensure_probe_tmp || { kv "apt.temp_dir" "BLOCKED"; return; }
  mode=$(root_mode)
  APT_PRIV_MODE="$mode"
  kv "apt.privilege_mode" "$mode"

  if dpkg-query -W -f='${Status}' hello 2>/dev/null | grep -q '^install ok installed$'; then before=1; fi
  kv "apt.hello_preinstalled" "$([ "$before" -eq 1 ] && echo yes || echo no)"

  if [ "$before" -eq 1 ]; then
    hello_out=$(LC_ALL=C hello 2>/dev/null | sed -n '1p' || true)
    [ "$hello_out" = "Hello, world!" ] && kv "apt.hello_execution" "PASS" || kv "apt.hello_execution" "present; unexpected output"
    kv "apt.install_test" "SKIP: hello already installed"
    return
  fi

  bounded 30 apt-get -s -o Debug::NoLocking=true --no-install-recommends --no-upgrade install hello >"$PROBE_TMP/apt-sim.txt" 2>/dev/null
  rc=$?
  [ "$rc" -eq 0 ] || { kv "apt.simulation" "FAIL/BLOCKED (exit $rc)"; return; }
  kv "apt.simulation" "PASS"

  mkdir -p "$PROBE_TMP/apt-download"
  (cd "$PROBE_TMP/apt-download" && bounded 45 apt-get \
    -o Acquire::Retries=0 -o Acquire::http::Timeout=10 -o Acquire::https::Timeout=10 \
    download hello >/dev/null 2>&1)
  rc=$?
  [ "$rc" -eq 0 ] && kv "apt.download" "PASS" || kv "apt.download" "FAIL/BLOCKED (exit $rc)"

  if grep -q '^Remv ' "$PROBE_TMP/apt-sim.txt" 2>/dev/null; then
    kv "apt.install_test" "SKIP: simulation proposed removals"
    return
  fi
  inst_bad=$(awk '/^Inst / && $2 != "hello" {print $2}' "$PROBE_TMP/apt-sim.txt" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//' || true)
  if [ -n "$inst_bad" ]; then
    kv "apt.install_test" "SKIP: simulation proposed other package changes"
    return
  fi
  grep -q '^Inst hello ' "$PROBE_TMP/apt-sim.txt" 2>/dev/null || { kv "apt.install_test" "SKIP: simulation did not propose hello install"; return; }
  [ "$mode" != "blocked" ] || { kv "apt.install_test" "BLOCKED: no root/passwordless sudo"; return; }

  run_priv_bounded 75 "$mode" env DEBIAN_FRONTEND=noninteractive LC_ALL=C \
    apt-get -y --no-install-recommends --no-upgrade \
    -o Acquire::Retries=0 -o Acquire::http::Timeout=10 -o Acquire::https::Timeout=10 -o Dpkg::Use-Pty=0 \
    install hello >/dev/null 2>&1
  rc=$?
  if [ "$rc" -ne 0 ]; then
    kv "apt.install_test" "FAIL/BLOCKED (exit $rc)"
    if dpkg-query -W -f='${Status}' hello 2>/dev/null | grep -q '^install ok installed$'; then
      APT_HELLO_INSTALLED=1
      run_priv_bounded 60 "$mode" env DEBIAN_FRONTEND=noninteractive LC_ALL=C \
        apt-get -y -o Acquire::Retries=0 -o Dpkg::Use-Pty=0 purge hello >/dev/null 2>&1 || true
      if dpkg-query -W -f='${Status}' hello 2>/dev/null | grep -q '^install ok installed$'; then
        kv "apt.cleanup_after_failure" "FAIL: verify/remove hello manually"
      else
        APT_HELLO_INSTALLED=0
        kv "apt.cleanup_after_failure" "PASS: partial hello install removed"
      fi
    fi
    return
  fi
  kv "apt.install_test" "PASS"
  APT_HELLO_INSTALLED=1

  if dpkg-query -W -f='${Status}' hello 2>/dev/null | grep -q '^install ok installed$'; then after=1; fi
  hello_out=$(LC_ALL=C hello 2>/dev/null | sed -n '1p' || true)
  [ "$after" -eq 1 ] && [ "$hello_out" = "Hello, world!" ] && kv "apt.hello_execution" "PASS" || kv "apt.hello_execution" "FAIL"

  run_priv_bounded 60 "$mode" env DEBIAN_FRONTEND=noninteractive LC_ALL=C \
    apt-get -y -o Acquire::Retries=0 -o Dpkg::Use-Pty=0 purge hello >/dev/null 2>&1
  rc=$?
  if [ "$rc" -eq 0 ] && ! dpkg-query -W -f='${Status}' hello 2>/dev/null | grep -q '^install ok installed$'; then
    kv "apt.cleanup" "PASS: hello purged"
    APT_HELLO_INSTALLED=0
  else
    kv "apt.cleanup" "FAIL: verify/remove hello manually"
  fi
  kv "apt.cleanup_scope" "package removed; apt logs/cache metadata may remain changed"
}

section "PROBE"
kv "probe version" "$VERSION"
if have date; then kv "timestamp UTC" "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true)"; fi
kv "mode" "single standardized run"
kv "active tests" "temp write, local TCP, gcc compile, rootless namespaces/runtime info, CPU/ML/GPU execution, outbound HTTPS/DNS, sudo, apt hello, Python/npm/Deno packages"
kv "test packages" "$PY_PACKAGE; $MS_PACKAGE; $ZOD_PACKAGE; apt:hello"
kv "portable Deno fallback" "v$DENO_VERSION when Deno is absent"
kv "safety" "bounded tests; temp artifacts; guarded apt install+purge; no secret/private-file inspection"

section "OS / KERNEL"
if [ -r /etc/os-release ]; then
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
if [ -r /sys/fs/cgroup/cpu/cpu.cfs_quota_us ] && [ -r /sys/fs/cgroup/cpu/cpu.cfs_period_us ]; then
  q=$(read_file_line /sys/fs/cgroup/cpu/cpu.cfs_quota_us); p=$(read_file_line /sys/fs/cgroup/cpu/cpu.cfs_period_us)
  kv "cgroup v1 CPU quota" "$q / $p us"
fi
cpu_isa_inventory

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
  nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader 2>/dev/null | sed 's/^/  GPU: /' | head -n 8
else
  kv "nvidia-smi" "absent"
fi
kv "rocm-smi" "$([ -x "$(command -v rocm-smi 2>/dev/null || printf /nonexistent)" ] && echo present || echo absent)"
kv "rocminfo" "$([ -x "$(command -v rocminfo 2>/dev/null || printf /nonexistent)" ] && echo present || echo absent)"
if have lspci; then
  gpu=$(lspci 2>/dev/null | grep -Ei 'vga|3d controller|display controller' | head -n 8 || true)
  if [ -n "$gpu" ]; then printf '%s\n' "$gpu" | sed 's/^/  PCI GPU: /'; else kv "lspci GPU" "none visible"; fi
else
  kv "lspci" "unavailable"
fi

python_ml_inventory
cpu_ml_benchmark
gpu_ml_capability_test

section "DEVELOPMENT TOOLCHAIN"
for x in \
  python python3 pip pip3 uv pipx ipython jupyter pytest cython numba torchrun hf \
  node npm pnpm yarn bun deno corepack npx tsc ts-node \
  go rustc cargo swift swiftc kotlin kotlinc \
  gcc g++ gfortran clang cmake make ninja meson ant pkg-config autoconf automake \
  java javac dotnet ruby php R perl \
  git gh; do
  safe_version "$x"
done

section "INFRA / CONTAINER / ISOLATION TOOLS"
for x in docker podman buildah kubectl helm terraform ansible lsns unshare nsenter capsh getcap chroot findmnt setpriv newuidmap newgidmap fuse-overlayfs slirp4netns pasta runc crun bwrap proot rootlesskit dockerd-rootless.sh rocm-smi rocminfo; do safe_version "$x"; done

section "ARCHIVE / BINARY TOOLS"
for x in zip unzip tar gzip bzip2 xz zstd file strings readelf objdump nm; do safe_version "$x"; done

section "DATA / NETWORK CLIENTS"
for x in curl wget jq rg sqlite3 psql mysql redis-cli ssh ip ping nc socat rsync; do safe_version "$x"; done

section "BROWSER / DOCUMENT / MEDIA TOOLS"
for x in \
  chromium chromium-browser google-chrome google-chrome-stable firefox playwright xvfb-run \
  libreoffice soffice pandoc \
  ffmpeg ffprobe sox \
  convert magick tesseract \
  pdftotext pdfinfo pdftoppm pdfimages pdfunite gs \
  weasyprint cairosvg dot inkscape \
  latex pdflatex xelatex lualatex; do
  safe_version "$x"
done

section "CRYPTO / SIGNING TOOLS"
for x in openssl gpg; do safe_version "$x"; done

section "PRIVILEGE SURFACE"
uid=$(id -u 2>/dev/null || echo unknown)
kv "effective UID" "$uid"
kv "effective UID is root" "$([ "$uid" = "0" ] && echo yes || echo no)"
kv "sudo binary" "$([ -x "$(command -v sudo 2>/dev/null || printf /nonexistent)" ] && echo present || echo absent)"
if have sudo; then
  if sudo -n true >/dev/null 2>&1; then kv "passwordless sudo" "yes"; else rc=$?; kv "passwordless sudo" "no/blocked (exit $rc)"; fi
else
  kv "passwordless sudo" "not testable: sudo absent"
fi

rootless_level1_test
rootless_level2_inventory
rootless_level3_runtime

section "LOCAL NETWORK STACK"
kv "loopback interface" "$([ -e /sys/class/net/lo ] && echo present || echo unavailable)"
if have ss; then
  tcp_count=$(ss -ltnH 2>/dev/null | wc -l | tr -d ' ')
  udp_count=$(ss -lunH 2>/dev/null | wc -l | tr -d ' ')
  kv "TCP listeners count" "${tcp_count:-unknown}"
  kv "UDP listeners count" "${udp_count:-unknown}"
else
  kv "socket listener inventory" "ss unavailable"
fi
local_socket_test

section "OUTBOUND NETWORK TEST"
if have getent; then
  if bounded 8 getent ahosts example.com >/dev/null 2>&1; then kv "DNS example.com" "PASS"; else kv "DNS example.com" "BLOCKED/FAIL"; fi
else
  kv "DNS example.com" "SKIP: getent unavailable"
fi
if have curl; then
  code=$(curl -fsS -o /dev/null -w '%{http_code}' --proto '=https' --connect-timeout 3 --max-time 8 https://example.com/ 2>/dev/null || true)
  [ "$code" = "200" ] && kv "HTTPS example.com" "PASS (200)" || kv "HTTPS example.com" "BLOCKED/FAIL (${code:-no response})"
elif have wget; then
  if bounded 10 wget -q --https-only --spider --timeout=8 --tries=1 https://example.com/ >/dev/null 2>&1; then kv "HTTPS example.com" "PASS"; else kv "HTTPS example.com" "BLOCKED/FAIL"; fi
else
  kv "HTTPS example.com" "SKIP: curl/wget unavailable"
fi

section "TEMP WRITE TEST"
if ensure_probe_tmp; then
  f="$PROBE_TMP/write-test.bin"
  if dd if=/dev/zero of="$f" bs=1048576 count=1 conv=fsync status=none 2>/dev/null; then
    kv "1 MiB temp write/fsync" "PASS"
  else
    kv "1 MiB temp write/fsync" "FAIL"
  fi
  rm -f "$f" 2>/dev/null || true
  [ ! -e "$f" ] && kv "temp write cleanup" "PASS" || kv "temp write cleanup" "FAIL"
else
  kv "temporary directory" "BLOCKED: /tmp unavailable/not writable"
fi

gcc_compile_test
apt_hello_test
python_package_test
node_package_test
deno_test

section "CLEANUP"
if [ -n "$PROBE_TMP" ] && [ -d "$PROBE_TMP" ]; then
  cleanup_probe_tmp
  [ ! -e "$PROBE_TMP" ] && kv "temporary probe tree" "PASS: removed" || kv "temporary probe tree" "FAIL: remains"
else
  kv "temporary probe tree" "nothing created"
fi
PROBE_TMP=""

section "END"
kv "result" "probe completed"
