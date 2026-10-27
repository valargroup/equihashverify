// Copyright (c) 2026 The Zakura developers
// Distributed under the MIT license; see LICENSE.
#include "equihash_200_9_internal.h"
#include <cstring>
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#define EQUIHASH_AVX2_TARGET __attribute__((target("avx2")))
namespace equihash2009 {
namespace {
template <int N> EQUIHASH_AVX2_TARGET inline __m256i ror(__m256i x) {
  return _mm256_or_si256(_mm256_srli_epi64(x, N), _mm256_slli_epi64(x, 64 - N));
}
EQUIHASH_AVX2_TARGET inline void mix4(__m256i *v, int a, int b, int c, int d,
                                      __m256i x, __m256i y) {
  v[a] = _mm256_add_epi64(_mm256_add_epi64(v[a], v[b]), x);
  v[d] = ror<32>(_mm256_xor_si256(v[d], v[a]));
  v[c] = _mm256_add_epi64(v[c], v[d]);
  v[b] = ror<24>(_mm256_xor_si256(v[b], v[c]));
  v[a] = _mm256_add_epi64(_mm256_add_epi64(v[a], v[b]), y);
  v[d] = ror<16>(_mm256_xor_si256(v[d], v[a]));
  v[c] = _mm256_add_epi64(v[c], v[d]);
  v[b] = ror<63>(_mm256_xor_si256(v[b], v[c]));
}
// Each lane hashes a distinct leaf group. The final message is 12 header bytes
// followed by a little-endian 32-bit group index, with total input length 144.
EQUIHASH_AVX2_TARGET void hashes4(const uint64_t *h, const uint8_t *tail,
                                  const uint32_t *groups, uint8_t out[4][64]) {
  __m256i v[16], m[16];
  for (int i = 0; i < 8; ++i) {
    v[i] = _mm256_set1_epi64x(h[i]);
    v[i + 8] = _mm256_set1_epi64x(IV[i]);
  }
  v[12] = _mm256_xor_si256(v[12], _mm256_set1_epi64x(144));
  v[14] = _mm256_xor_si256(v[14], _mm256_set1_epi64x(-1));
  m[0] = _mm256_set1_epi64x(Load64(tail));
  uint32_t low;
  std::memcpy(&low, tail + 8, 4);
  uint64_t words[4];
  for (int i = 0; i < 4; ++i)
    words[i] = uint64_t(low) | (uint64_t(groups[i]) << 32);
  m[1] = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(words));
  for (int i = 2; i < 16; ++i)
    m[i] = _mm256_setzero_si256();
  for (const auto &s : SIGMA) {
    mix4(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    mix4(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    mix4(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    mix4(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    mix4(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    mix4(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    mix4(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    mix4(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (int i = 0; i < 8; ++i) {
    __m256i word = _mm256_xor_si256(_mm256_set1_epi64x(h[i]),
                                    _mm256_xor_si256(v[i], v[i + 8]));
    _mm256_storeu_si256(reinterpret_cast<__m256i *>(words), word);
    for (int lane = 0; lane < 4; ++lane)
      std::memcpy(out[lane] + i * 8, &words[lane], 8);
  }
}
} // namespace
HashFour Avx2HashFour() {
  static const HashFour kernel = []() -> HashFour {
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx2") ? hashes4 : nullptr;
  }();
  return kernel;
}
} // namespace equihash2009
#undef EQUIHASH_AVX2_TARGET
#else
namespace equihash2009 {
HashFour Avx2HashFour() { return nullptr; }
} // namespace equihash2009
#endif
