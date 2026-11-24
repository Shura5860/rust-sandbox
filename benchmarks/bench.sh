#!/usr/bin/env bash
# Reproducible startup latency benchmark for rust-sandbox (rsb)
# Compares: rsb cold start, rsb warm Python Zygote, and (if installed) bwrap / docker.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RSB="${ROOT_DIR}/target/release/rsb"
ITERS="${1:-20}"

if [[ ! -x "$RSB" ]]; then
    (cd "$ROOT_DIR" && cargo build --workspace --release)
fi

echo "=== Host Info ==="
"$RSB" info
echo ""

EXTRA_FLAGS=()
if ! "$RSB" run -- /bin/true >/dev/null 2>&1; then
    echo "Note: unprivileged userns unavailable; falling back to --no-ns (Landlock + Seccomp)."
    EXTRA_FLAGS=(--no-ns)
fi

echo "=== 1. rsb cold /bin/true ($ITERS runs) ==="
python3 - "$RSB" "$ITERS" "${EXTRA_FLAGS[@]}" <<'PY'
import statistics, subprocess, sys, time
rsb, n, extra = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
times = []
for _ in range(n):
    t0 = time.perf_counter()
    subprocess.run([rsb, "run", *extra, "--", "/bin/true"], check=True)
    times.append((time.perf_counter() - t0) * 1000.0)
print(f"rsb cold /bin/true: avg={statistics.mean(times):.2f} ms  median={statistics.median(times):.2f} ms  min={min(times):.2f} ms")
PY

echo ""
echo "=== 2. rsb Python Zygote Benchmark ($ITERS runs) ==="
"$RSB" zygote-bench "${EXTRA_FLAGS[@]}" --iters "$ITERS"

if command -v bwrap >/dev/null 2>&1; then
    echo ""
    echo "=== 3. bubblewrap (bwrap) /bin/true ($ITERS runs) ==="
    python3 - "$ITERS" <<'PY'
import statistics, subprocess, sys, time
n = int(sys.argv[1])
times = []
for _ in range(n):
    t0 = time.perf_counter()
    subprocess.run(["bwrap", "--ro-bind", "/", "/", "--unshare-all", "/bin/true"], check=True)
    times.append((time.perf_counter() - t0) * 1000.0)
print(f"bwrap /bin/true:    avg={statistics.mean(times):.2f} ms  median={statistics.median(times):.2f} ms  min={min(times):.2f} ms")
PY
fi
