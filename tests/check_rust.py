"""Build a pinned local Common reference and run the native differential test.

The Common checkout is read-only. All Cargo, bridge and CMake outputs go in the
explicit build directory. No Rust dependency is added to ordinary builds.
"""
import argparse
from pathlib import Path
import subprocess
import sys

COMMON_REVISION = "7759b1f5f8b2597599e39610558eaafca752b4b6"


def run(command, *, cwd=None):
    subprocess.run(command, cwd=cwd, check=True, timeout=300)


def check_checkout(common):
    revision = subprocess.check_output(
        ["git", "-C", str(common), "rev-parse", "HEAD"], text=True, timeout=30
    ).strip()
    changes = subprocess.check_output(
        ["git", "-C", str(common), "status", "--porcelain"], text=True, timeout=30
    ).strip()
    if revision != COMMON_REVISION or changes:
        raise ValueError(f"Common must be clean at {COMMON_REVISION}; checkout was not changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--common", required=True, type=Path)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--offline", action="store_true", help="Use cached Cargo dependencies only")
    parser.add_argument("--require-avx2", action="store_true")
    parser.add_argument("--require-avx512", action="store_true")
    args = parser.parse_args()
    source = Path(__file__).resolve().parent.parent
    common, build = args.common.resolve(), args.build_dir.resolve()
    check_checkout(common)
    build.mkdir(parents=True, exist_ok=True)
    cargo_target = build / "rust"
    library = build / ("librust_reference.dylib" if sys.platform == "darwin" else "librust_reference.so")
    cargo = ["cargo", "build", "--release", "--locked", "-p", "zakura-equihash",
             "--target-dir", str(cargo_target)]
    if args.offline:
        cargo.append("--offline")
    run(cargo, cwd=common)
    run(["rustc", "--edition=2024", "--crate-type=cdylib", "-O",
         str(source / "tests/rust_reference.rs"), "--extern",
         f"equihash={cargo_target / 'release/libequihash.rlib'}", "-L",
         f"dependency={cargo_target / 'release/deps'}", "-o", str(library)], cwd=common)
    check_checkout(common)
    native = build / "native"
    run(["cmake", "-S", str(source), "-B", str(native), "-DCMAKE_BUILD_TYPE=Release",
         f"-DEQUIHASH_RUST_REFERENCE_LIBRARY={library}",
         f"-DEQUIHASH_REQUIRE_AVX2={'ON' if args.require_avx2 else 'OFF'}",
         f"-DEQUIHASH_REQUIRE_AVX512={'ON' if args.require_avx512 else 'OFF'}"])
    run(["cmake", "--build", str(native), "--target", "rust_differential", "-j2"])
    print(f"Comparing against Common {COMMON_REVISION}", flush=True)
    run(["ctest", "--test-dir", str(native), "-R", "^rust_differential$", "-V", "--output-on-failure"])


if __name__ == "__main__":
    main()
