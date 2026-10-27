# Equihash - Zcash Implementation
nodejs native binding to check for valid Equihash solutions

# Dependencies
````
sudo apt-get install build-essential libsodium-dev libboost-system-dev
````

# Usage
````javascript
var ev = require('bindings')('equihashverify.node');

var header = new Buffer(..., 'hex');
var solution = new Buffer(..., 'hex'); //do not include byte size preamble "fd4005"

ev.verify(header, solution, n, k);
//returns boolean
````

# Backward compatibility
````javascript
ev.verify(header, solution);
````

# Test Suite:
````
sudo npm install -g mocha
npm install
mocha
````


## Native C++ verification

The `(200,9)` verifier uses a bounded tree walk and four-lane BLAKE2b hashing.
The public entry point automatically selects AVX2, then scalar, according to
CPU and OS support. AVX512 requires explicit opt-in. All backends use identical proof checks. Other parameter sets
retain their existing verifier. No Rust toolchain is needed.

On Ubuntu install `build-essential cmake libsodium-dev libboost-dev`, then:

```sh
cmake -S . -B native-build -DCMAKE_BUILD_TYPE=Release
cmake --build native-build -j8
ctest --test-dir native-build --output-on-failure
```

Include `crypto/equihash_avx2.h`, call
`VerifyEquihash2009(header, header_len, solution, solution_len)`, and link the
native library, libsodium and pthread. Native code requires C++11. The header
must contain exactly 140 bytes including the nonce; the solution is 1,344 bytes
without its CompactSize prefix. Buffers are borrowed for the call. Null pointers
and incorrect lengths return false. Calls are concurrent and do not allocate or
log. Proof validity does not establish share difficulty, freshness or credit.

Only the SIMD kernels have architecture-specific target attributes. Do not add
global `-mavx2` or `-march=native` flags for a mixed fleet. Set
`EQUIHASH_REQUIRE_AVX2=ON` during hardware qualification to fail if the kernel
cannot execute; that option does not change runtime selection.

The native tests compare the public entry point and explicit kernels against the
legacy verifier and libsodium. `tests/reference.py --check` regenerates proof and
hash oracles from the committed seed proofs using independent Python hashlib.
Enable `EQUIHASH_BUILD_BENCHMARK=ON` to build `pool_bench`; compare backends on
the same quiet host. `tests/run_benchmarks.sh` builds it, times the original
verifier, AVX2 and AVX512 at 1 and 8 threads, and writes `bench-results/`:

```sh
tests/run_benchmarks.sh
# Also time verify() through Node, given the original and this branch's built addons:
NODE=/path/to/node tests/run_benchmarks.sh /path/to/old/equihashverify.node /path/to/new/equihashverify.node
```

The original verifier's cost depends on glibc's memory handling: in a Node
process it can return its working memory to the system after every call, which
the script shows by repeating the Node timings with raised malloc thresholds.
The algorithm follows Common revision
`7759b1f5f8b2597599e39610558eaafca752b4b6` and RFC 7693.

This change keeps the existing Node package and toolchain requirements. Modern
Node support and addon compatibility fixes are maintained in the follow-up PR.

## AVX512 and reference qualification

AVX512 hashes eight leaf groups per call and is disabled in default dispatch.
Set `EQUIHASH_ENABLE_AVX512=1` before starting the service to prefer AVX512 when
runtime detection permits execution; unsupported hosts still use AVX2 or scalar:

```sh
EQUIHASH_ENABLE_AVX512=1 ./pool-service
# The Node addon inherits the same setting:
EQUIHASH_ENABLE_AVX512=1 node pool.js
```

Only the value `1` enables this path. The setting is read on the first native
verification call and cached. Changing it later requires restarting the process.
Do not add global AVX512 compiler flags. `EQUIHASH_REQUIRE_AVX512=ON` makes
qualification fail when AVX512 is unavailable; it does not force runtime use.
The benchmark accepts `avx512` for an explicit comparison with `avx2` or scalar.

The optional `tests/check_rust.py` comparison uses a clean local Common checkout
at `7759b1f5f8b2597599e39610558eaafca752b4b6`. It builds outside that checkout
and compares its verifier with the public entry point and explicit kernels:

```sh
python3 tests/check_rust.py --common /path/to/common --build-dir /tmp/equihash-rust-check
```

Use `--require-avx2` or `--require-avx512` to require hardware qualification;
`--offline` uses cached Cargo dependencies. Ordinary native builds need no Rust.
