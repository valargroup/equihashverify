// Copyright (c) 2026 The Zakura developers
// Distributed under the MIT license; see LICENSE.
#include "equihash_200_9_internal.h"
#include <cstring>
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#define EQUIHASH_AVX512_TARGET __attribute__((target("avx512f")))
namespace equihash2009 {
namespace {
template <int N> EQUIHASH_AVX512_TARGET inline __m512i ror(__m512i x) {
  return _mm512_ror_epi64(x, N);
}
EQUIHASH_AVX512_TARGET inline void mix8(__m512i *v, int a, int b, int c, int d,
                                        __m512i x, __m512i y) {
  v[a] = _mm512_add_epi64(_mm512_add_epi64(v[a], v[b]), x);
  v[d] = ror<32>(_mm512_xor_si512(v[d], v[a]));
  v[c] = _mm512_add_epi64(v[c], v[d]);
  v[b] = ror<24>(_mm512_xor_si512(v[b], v[c]));
  v[a] = _mm512_add_epi64(_mm512_add_epi64(v[a], v[b]), y);
  v[d] = ror<16>(_mm512_xor_si512(v[d], v[a]));
  v[c] = _mm512_add_epi64(v[c], v[d]);
  v[b] = ror<63>(_mm512_xor_si512(v[b], v[c]));
}
// Eight independent BLAKE2b groups; only AVX-512F instructions are required.
// Each lane hashes a distinct leaf group. The final message is 12 header bytes
// followed by a little-endian 32-bit group index, with total input length 144.
EQUIHASH_AVX512_TARGET void hashes8(const uint64_t *h, const uint8_t *tail,
                                    const uint32_t *groups,
                                    uint8_t out[8][64]) {
  __m512i v[16], m[16];
  for (int i = 0; i < 8; ++i) {
    v[i] = _mm512_set1_epi64(h[i]);
    v[i + 8] = _mm512_set1_epi64(IV[i]);
  }
  v[12] = _mm512_xor_si512(v[12], _mm512_set1_epi64(144));
  v[14] = _mm512_xor_si512(v[14], _mm512_set1_epi64(-1));
  m[0] = _mm512_set1_epi64(Load64(tail));
  uint32_t low;
  std::memcpy(&low, tail + 8, 4);
  uint64_t words[8];
  for (int i = 0; i < 8; ++i)
    words[i] = uint64_t(low) | (uint64_t(groups[i]) << 32);
  m[1] = _mm512_loadu_si512(reinterpret_cast<const __m512i *>(words));
  for (int i = 2; i < 16; ++i)
    m[i] = _mm512_setzero_si512();
  for (const auto &s : SIGMA) {
    mix8(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    mix8(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    mix8(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    mix8(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    mix8(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    mix8(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    mix8(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    mix8(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (int i = 0; i < 8; ++i) {
    __m512i word = _mm512_xor_si512(_mm512_set1_epi64(h[i]),
                                    _mm512_xor_si512(v[i], v[i + 8]));
    _mm512_storeu_si512(reinterpret_cast<__m512i *>(words), word);
    for (int lane = 0; lane < 8; ++lane)
      std::memcpy(out[lane] + i * 8, &words[lane], 8);
  }
}
} // namespace
HashEight Avx512HashEight() {
  static const HashEight kernel = []() -> HashEight {
    __builtin_cpu_init();
    return HashEight(__builtin_cpu_supports("avx512f") ? hashes8 : nullptr);
  }();
  return kernel;
}
} // namespace equihash2009
#undef EQUIHASH_AVX512_TARGET
#else
namespace equihash2009 {
HashEight Avx512HashEight() { return HashEight(); }
} // namespace equihash2009
#endif
