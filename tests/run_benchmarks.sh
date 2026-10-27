#!/usr/bin/env bash
# Measure Equihash (200,9) verification cost on this host and write the results to bench-results/.
#
# Usage: tests/run_benchmarks.sh [OLD_ADDON NEW_ADDON]
#
# Without arguments it builds pool_bench and times the original verifier, AVX2 and (when the CPU
# supports it) AVX512 on the committed valid proofs, at 1 and 8 threads, five rounds each.
# With the paths of two built Node addons (the equihashverify.node from the original package and
# from this branch) it also times verify() through Node, first with glibc's default memory
# settings and then with raised malloc thresholds. Set NODE to the node binary the addons were
# built for (default: node on PATH). The 8-thread runs use every CPU: run on a quiet host.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=${OUT:-$root/bench-results}
node=${NODE:-node}
proofs=$root/tests/proofs.tsv
mkdir -p "$out"

if [ $# -ne 0 ] && [ $# -ne 2 ]; then
  echo "usage: $0 [OLD_ADDON NEW_ADDON]" >&2
  exit 2
fi
for addon in "$@"; do
  [ -f "$addon" ] || { echo "addon not found: $addon" >&2; exit 2; }
done

{
  grep -m1 'model name' /proc/cpuinfo || true
  echo "cpus: $(nproc)"
  ldd --version 2>&1 | sed -n 1p
  c++ --version 2>&1 | sed -n 1p
  if [ $# -eq 2 ]; then echo "node: $("$node" -v)"; fi
  echo "LD_PRELOAD=${LD_PRELOAD:-}"
  env | grep '^MALLOC_' || true
  echo "commit: $(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)"
} > "$out/env.txt"

echo "Building pool_bench (log: $out/build.log)"
cmake -S "$root" -B "$root/native-build" -DCMAKE_BUILD_TYPE=Release -DEQUIHASH_BUILD_BENCHMARK=ON > "$out/build.log" 2>&1
cmake --build "$root/native-build" -j"$(nproc)" --target pool_bench >> "$out/build.log" 2>&1

backends="legacy avx2"
if grep -qw avx512f /proc/cpuinfo; then backends="$backends avx512"; fi

echo "Timing $backends at 1 and 8 threads, 5 rounds"
: > "$out/pool_bench.csv"
for round in 1 2 3 4 5; do
  for threads in 1 8; do
    for backend in $backends; do
      "$root/native-build/pool_bench" "$backend" "$proofs" valid "$threads" 3000 2>> "$out/pool_bench.csv"
    done
  done
done

# Median CPU microseconds per share for each backend and thread count (column 7 is ns per share).
{
  echo "pool_bench, valid shares: median CPU us per share over 5 rounds"
  sort -t, -k1,1 -k3,3n -k7,7g "$out/pool_bench.csv" | awk -F, '
    function flush() { if (n) printf "  %-7s %s thread(s): %8.1f\n", key_backend, key_threads, v[int((n + 1) / 2)] / 1000 }
    $1 != key_backend || $3 != key_threads { flush(); key_backend = $1; key_threads = $3; n = 0 }
    { v[++n] = $7 }
    END { flush() }'
} > "$out/summary.txt"

if [ $# -eq 2 ]; then
  echo "Timing verify() through Node $("$node" -v), default and raised malloc thresholds"
  : > "$out/node.jsonl"
  for malloc in default raised; do
    settings=""
    if [ "$malloc" = raised ]; then settings="MALLOC_MMAP_THRESHOLD_=268435456 MALLOC_TRIM_THRESHOLD_=1073741824"; fi
    for round in 1 2 3; do
      env $settings "$node" "$root/tests/node_bench.js" "$1" "$proofs" 2000 "old,$malloc" >> "$out/node.jsonl"
      env $settings "$node" "$root/tests/node_bench.js" "$2" "$proofs" 2000 "new,$malloc" >> "$out/node.jsonl"
    done
  done
  "$node" -e '
    const rows = require("fs").readFileSync(process.argv[1], "utf8").trim().split("\n").map(JSON.parse);
    const median = xs => xs.sort((a, b) => a - b)[Math.floor(xs.length / 2)];
    console.log("Node verify(), valid shares: median CPU us per share over 3 rounds");
    for (const malloc of ["default", "raised"]) {
      const of = build => median(rows.filter(r => r.label === build + "," + malloc).map(r => r.cpu_us_per_share));
      console.log(`  ${malloc.padEnd(7)} malloc: old ${of("old").toFixed(1).padStart(8)}  new ${of("new").toFixed(1).padStart(8)}`);
    }' "$out/node.jsonl" >> "$out/summary.txt"
fi

cat "$out/summary.txt"
echo "Results are in $out; please send env.txt, pool_bench.csv, summary.txt and node.jsonl if present."
