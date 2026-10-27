// Internal implementation boundary shared by the walk, hash kernels and tests.
#ifndef EQUIHASH_200_9_INTERNAL_H
#define EQUIHASH_200_9_INTERNAL_H
#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>
namespace equihash2009 {
extern const uint64_t IV[8];
extern const unsigned char SIGMA[12][16];
inline uint64_t Load64(const uint8_t *p) {
  uint64_t value = 0;
  for (unsigned i = 0; i < 8; ++i)
    value |= uint64_t(p[i]) << (8 * i);
  return value;
}
using HashGroups = void (*)(const uint64_t *, const uint8_t *, const uint32_t *,
                            uint8_t (*)[64]);
using HashFour = HashGroups;
void InitialiseMidstate(const uint8_t *header, uint64_t *state);
void ScalarHashFour(const uint64_t *state, const uint8_t *tail,
                    const uint32_t *groups, uint8_t out[4][64]);
// Returns nullptr if this build or CPU cannot execute the AVX2 kernel.
HashFour Avx2HashFour();
HashFour SelectedHashFour();
// A nominal eight-lane callback. Raw functions require explicit construction;
// it cannot be passed accidentally to a four-lane walk, or vice versa.
class HashEight {
public:
  explicit HashEight(HashGroups function = nullptr) : function_(function) {}
  explicit operator bool() const { return function_ != nullptr; }
  void operator()(const uint64_t *state, const uint8_t *tail,
                  const uint32_t (&groups)[8], uint8_t (&out)[8][64]) const {
    function_(state, tail, groups, out);
  }
  bool operator==(HashEight other) const {
    return function_ == other.function_;
  }
  bool operator!=(HashEight other) const { return !(*this == other); }

private:
  HashGroups function_;
  friend bool VerifyWithHashEight(HashEight, const uint8_t *, size_t,
                                  const uint8_t *, size_t);
};
static_assert(!std::is_convertible<HashFour, HashEight>::value,
              "Four-lane callbacks must not enter the eight-lane walk");
static_assert(!std::is_convertible<HashEight, HashFour>::value,
              "Eight-lane callbacks must not enter the four-lane walk");
// Empty unless both the build and CPU support AVX-512F.
HashEight Avx512HashEight();
// Uses the same tree-check source with eight leaf hashes per kernel call.
bool VerifyWithHashEight(HashEight hash, const uint8_t *header,
                         size_t header_len, const uint8_t *solution,
                         size_t solution_len);
// solution points to exactly 1344 readable bytes. Output contains 512 indices.
bool DecodeAndCheckIndices(const uint8_t *solution,
                           std::array<uint32_t, 512> &indices);
// Explicit kernel selection for native tests and benchmarks; never falls back.
bool VerifyWithHashFour(HashFour hash_four, const uint8_t *header,
                        size_t header_len, const uint8_t *solution,
                        size_t solution_len);
} // namespace equihash2009
#endif
