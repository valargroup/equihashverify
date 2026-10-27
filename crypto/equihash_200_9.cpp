// Copyright (c) 2026 The Zakura developers
// Distributed under the MIT license; see LICENSE.
// BLAKE2b (RFC 7693) and tree walk adapted from Common 7759b1f5,
// crates/equihash/src/{leaf_hash,verify}.rs. All inputs are public proof data.
#include "equihash_200_9_internal.h"
#include "equihash_avx2.h"
#include <algorithm>
#include <cstdlib>
#include <cstring>
namespace equihash2009 {
const uint64_t IV[8] = {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
                        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
                        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
                        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
const unsigned char SIGMA[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};
uint64_t rotate(uint64_t x, unsigned n) { return (x >> n) | (x << (64 - n)); }
void mix(uint64_t *v, int a, int b, int c, int d, uint64_t x, uint64_t y) {
  v[a] += v[b] + x;
  v[d] = rotate(v[d] ^ v[a], 32);
  v[c] += v[d];
  v[b] = rotate(v[b] ^ v[c], 24);
  v[a] += v[b] + y;
  v[d] = rotate(v[d] ^ v[a], 16);
  v[c] += v[d];
  v[b] = rotate(v[b] ^ v[c], 63);
}
// Hash the first 128-byte header block once per proof, using little-endian
// loads.
void InitialiseMidstate(const uint8_t *header, uint64_t *h) {
  uint8_t param[64] = {};
  param[0] = 50;
  param[2] = 1;
  param[3] = 1;
  std::memcpy(param + 48, "ZcashPoW", 8);
  param[56] = 200;
  param[60] = 9;
  uint64_t v[16], m[16];
  for (int i = 0; i < 8; ++i) {
    h[i] = IV[i] ^ Load64(param + 8 * i);
    v[i] = h[i];
    v[i + 8] = IV[i];
  }
  v[12] ^= 128;
  for (int i = 0; i < 16; ++i)
    m[i] = Load64(header + 8 * i);
  for (const auto &s : SIGMA) {
    mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (int i = 0; i < 8; ++i)
    h[i] ^= v[i] ^ v[i + 8];
}
// Scalar twin of the four-lane final-block compressor, with identical inputs.
void ScalarHashFour(const uint64_t *h, const uint8_t *tail,
                    const uint32_t *groups, uint8_t out[4][64]) {
  uint8_t block[128] = {};
  std::memcpy(block, tail, 12);
  for (size_t lane = 0; lane < 4; ++lane) {
    for (unsigned b = 0; b < 4; ++b)
      block[12 + b] = uint8_t(groups[lane] >> (8 * b));
    uint64_t v[16], m[16];
    for (size_t i = 0; i < 8; ++i) {
      v[i] = h[i];
      v[i + 8] = IV[i];
    }
    v[12] ^= 144;
    v[14] = ~v[14];
    for (size_t i = 0; i < 16; ++i)
      m[i] = Load64(block + 8 * i);
    for (const auto &s : SIGMA) {
      mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
      mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
      mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
      mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
      mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
      mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
      mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
      mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (size_t i = 0; i < 8; ++i) {
      const uint64_t word = h[i] ^ v[i] ^ v[i + 8];
      for (unsigned b = 0; b < 8; ++b)
        out[lane][8 * i + b] = uint8_t(word >> (8 * b));
    }
  }
}
// A bounded tree walk: 512 21-bit indices, ten pending rows, 64 leaf hashes.
// Ordering and distinctness are checked before hashing; every merge checks
// its 20-bit collision. All CPUs run this same bounded tree walk.
bool DecodeAndCheckIndices(const uint8_t *solution,
                           std::array<uint32_t, 512> &indices) {
  uint64_t acc = 0;
  unsigned bits = 0;
  size_t at = 0;
  for (size_t i = 0; i < 1344; ++i) {
    acc = (acc << 8) | solution[i];
    bits += 8;
    if (bits >= 21) {
      bits -= 21;
      indices[at++] = uint32_t((acc >> bits) & 0x1fffff);
    }
  }
  auto sorted = indices;
  std::sort(sorted.begin(), sorted.end());
  if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end())
    return false;
  for (size_t height = 0; height < 9; ++height) {
    const size_t width = size_t(1) << height;
    for (size_t start = 0; start < indices.size(); start += 2 * width)
      if (indices[start] >= indices[start + width])
        return false;
  }
  return true;
}
namespace {
template <size_t Lanes>
bool VerifyWithHashGroups(HashGroups hash_groups, const uint8_t *header,
                          size_t header_len, const uint8_t *solution,
                          size_t solution_len) {
  static_assert(Lanes == 4 || Lanes == 8,
                "Hash groups must fill the 64-leaf batch");
  if (!hash_groups || !header || !solution || header_len != 140 ||
      solution_len != 1344)
    return false;
  std::array<uint32_t, 512> indices;
  if (!DecodeAndCheckIndices(solution, indices))
    return false;
  uint64_t h[8];
  InitialiseMidstate(header, h);
  uint8_t pending[10][30] = {}, row[30], digests[64][64];
  for (size_t batch = 0; batch < 512; batch += 64) {
    for (size_t j = 0; j < 64; j += Lanes) {
      uint32_t groups[Lanes];
      for (size_t lane = 0; lane < Lanes; ++lane)
        groups[lane] = indices[batch + j + lane] / 2;
      hash_groups(h, header + 128, groups, digests + j);
    }
    for (size_t j = 0; j < 64; ++j) {
      size_t leaf = batch + j;
      const uint8_t *digest = digests[j] + (indices[leaf] % 2) * 25;
      uint64_t value = 0;
      unsigned held = 0;
      size_t pos = 0;
      for (size_t k = 0; k < 25; ++k) {
        value = (value << 8) | digest[k];
        held += 8;
        if (held >= 20) {
          held -= 20;
          uint32_t x = uint32_t((value >> held) & 0xfffff);
          row[pos++] = uint8_t(x >> 16);
          row[pos++] = uint8_t(x >> 8);
          row[pos++] = uint8_t(x);
        }
      }
      size_t height = 0;
      while ((leaf >> height) & 1) {
        const size_t len = 30 - height * 3;
        if (std::memcmp(pending[height], row, 3) != 0)
          return false;
        for (size_t k = 0; k < len - 3; ++k)
          row[k] = pending[height][k + 3] ^ row[k + 3];
        ++height;
      }
      std::memcpy(pending[height], row, 30 - height * 3);
    }
  }
  return pending[9][0] == 0 && pending[9][1] == 0 && pending[9][2] == 0;
}
} // namespace

bool VerifyWithHashFour(HashFour hash, const uint8_t *header, size_t header_len,
                        const uint8_t *solution, size_t solution_len) {
  return VerifyWithHashGroups<4>(hash, header, header_len, solution,
                                 solution_len);
}
bool VerifyWithHashEight(HashEight hash, const uint8_t *header,
                         size_t header_len, const uint8_t *solution,
                         size_t solution_len) {
  return VerifyWithHashGroups<8>(hash.function_, header, header_len, solution,
                                 solution_len);
}

HashFour SelectedHashFour() {
  static const HashFour selected = [] {
    const HashFour avx2 = Avx2HashFour();
    return avx2 ? avx2 : ScalarHashFour;
  }();
  return selected;
}
} // namespace equihash2009
bool Equihash2009HasAvx2() { return equihash2009::Avx2HashFour() != nullptr; }
bool VerifyEquihash2009(const uint8_t *header, size_t header_len,
                        const uint8_t *solution, size_t solution_len) {
  static const auto wide = [] {
    const char *enabled = std::getenv("EQUIHASH_ENABLE_AVX512");
    return enabled && std::strcmp(enabled, "1") == 0
               ? equihash2009::Avx512HashEight()
               : equihash2009::HashEight();
  }();
  if (wide)
    return equihash2009::VerifyWithHashEight(wide, header, header_len, solution,
                                            solution_len);
  return equihash2009::VerifyWithHashFour(equihash2009::SelectedHashFour(),
                                          header, header_len, solution,
                                          solution_len);
}
