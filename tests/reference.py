"""Independent hashlib reference and reproducible malformed-proof corpus.

Seed proofs are fixed inputs in seeds.tsv. This script neither solves proofs nor
uses either C++ verifier. Equihash ordering compares each sibling's first index;
global distinctness makes that equivalent to lexicographic subtree ordering.
"""
import argparse
import hashlib
import struct
from pathlib import Path

PERSON = b"ZcashPoW" + struct.pack("<II", 200, 9)

def decode_indices(solution):
    if len(solution) != 1344:
        raise ValueError("A solution has 512 packed 21-bit indices")
    value = int.from_bytes(solution, "big")
    return [(value >> (21 * (511 - i))) & 0x1fffff for i in range(512)]

def encode_indices(indices):
    value = 0
    for index in indices:
        value = (value << 21) | index
    return value.to_bytes(1344, "big")

def classify(header, solution):
    """Return the first failing invariant, or 'valid'."""
    if len(header) != 140 or len(solution) != 1344:
        return "length"
    indices = decode_indices(solution)
    if len(set(indices)) != 512:
        return "duplicate"
    for height in range(9):
        width = 1 << height
        for start in range(0, 512, 2 * width):
            if indices[start] >= indices[start + width]:
                return "ordering"
    rows = []
    for index in indices:
        digest = hashlib.blake2b(header + struct.pack("<I", index // 2),
                                 digest_size=50, person=PERSON).digest()
        leaf = int.from_bytes(digest[25 * (index % 2):25 * (index % 2 + 1)], "big")
        rows.append([(leaf >> (20 * (9 - i))) & 0xfffff for i in range(10)])
    for _ in range(9):
        merged = []
        for left, right in zip(rows[::2], rows[1::2]):
            if left[0] != right[0]:
                return "collision"
            merged.append([a ^ b for a, b in zip(left[1:], right[1:])])
        rows = merged
    return "valid" if rows == [[0]] else "root"

def make_cases(directory):
    cases = []
    for line in (directory / "seeds.tsv").read_text().splitlines():
        name, verdict, header_hex, solution_hex = line.split()
        header, solution = bytes.fromhex(header_hex), bytes.fromhex(solution_hex)
        reason = classify(header, solution)
        expected_reason = "valid" if verdict == "valid" else "root"
        if reason != expected_reason:
            raise ValueError(f"Seed {name}: expected {expected_reason}, got {reason}")
        cases.append((name, verdict, header, solution))
    _, _, header, solution = cases[0]
    indices = decode_indices(solution)
    for height in range(9):
        starts = {0: [2, 126, 510], 4: [32, 160, 480], 8: [0]}.get(height, [2 * (1 << height)])
        width = 1 << height
        for start in starts:
            swapped = indices.copy()
            swapped[start:start + 2 * width] = (indices[start + width:start + 2 * width]
                                                + indices[start:start + width])
            encoded = encode_indices(swapped)
            if classify(header, encoded) != "ordering":
                raise ValueError("Swapping siblings must fail ordering")
            cases.append((f"swap-height-{height}-start-{start}", "invalid", header, encoded))
            duplicated = indices.copy()
            duplicated[start + width:start + 2 * width] = indices[start:start + width]
            encoded = encode_indices(duplicated)
            if classify(header, encoded) != "duplicate":
                raise ValueError("Duplicating a subtree must fail distinctness")
            cases.append((f"duplicate-height-{height}-start-{start}", "invalid", header, encoded))
    for index in [3, 127, 255, 511]:
        duplicate = indices.copy()
        duplicate[index] = duplicate[1]
        cases.append((f"duplicate-index-{index}", "invalid", header, encode_indices(duplicate)))
    for byte in [0, 107, 108, 128, 139]:
        changed = bytearray(header)
        changed[byte] ^= 1
        if classify(changed, solution) != "collision":
            raise ValueError("Changed header must fail collisions")
        cases.append((f"header-byte-{byte}", "invalid", bytes(changed), solution))
    for byte in [0, 1343]:
        changed = bytearray(solution)
        changed[byte] ^= 1
        if classify(header, changed) == "valid":
            raise ValueError("Changed proof unexpectedly valid")
        cases.append((f"solution-byte-{byte}", "invalid", header, bytes(changed)))
    return cases

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if proofs.tsv differs from regeneration")
    args = parser.parse_args(argv)
    directory = Path(__file__).resolve().parent
    cases = make_cases(directory)
    text = "".join(f"{name}\t{verdict}\t{header.hex()}\t{solution.hex()}\n"
                   for name, verdict, header, solution in cases)
    path = directory / "proofs.tsv"
    if args.check:
        if path.read_text() != text:
            raise SystemExit("proofs.tsv differs; regenerate with python3 tests/reference.py")
    else:
        path.write_text(text)
    hash_lines = []
    for _, verdict, header, _ in cases:
        if verdict != "valid":
            continue
        for group in [0, 1, 1048574, 1048575]:
            digest = hashlib.blake2b(header + struct.pack("<I", group),
                                     digest_size=50, person=PERSON).digest()
            hash_lines.append(f"{header.hex()}\t{group}\t{digest.hex()}\n")
    hash_text = "".join(hash_lines)
    hash_path = directory / "hashes.tsv"
    if args.check:
        if hash_path.read_text() != hash_text:
            raise SystemExit("hashes.tsv differs; regenerate reference vectors")
    else:
        hash_path.write_text(hash_text)
    print(f"Checked {len(cases)} independently classified proof vectors and {len(hash_lines)} hashes")

if __name__ == "__main__":
    main()
