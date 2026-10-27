// Exercise each selected kernel directly against libsodium, never via fallback.
#include "crypto/equihash_200_9_internal.h"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <random>
#include <sodium.h>
#include <vector>
int main(int argc, char **argv) {
  if (sodium_init() < 0)
    return 2;
  const bool require_avx2 =
      argc == 2 && std::string(argv[1]) == "--require-avx2";
  if (argc > 2 || (argc == 2 && !require_avx2))
    return 2;
  using namespace equihash2009;
  std::vector<std::pair<const char *, HashFour>> kernels{
      {"scalar", ScalarHashFour}};
  const auto avx2 = Avx2HashFour();
  if (require_avx2 && !avx2) {
    std::cerr << "AVX2 required but unavailable\n";
    return 1;
  }
  if (avx2)
    kernels.emplace_back("avx2", avx2);
  for (const auto &kernel : kernels) {
    std::mt19937_64 rng(0x5141191);
    for (size_t trial = 0; trial < 256; ++trial) {
      uint8_t header[140];
      for (auto &b : header)
        b = static_cast<uint8_t>(rng());
      uint64_t h[8];
      InitialiseMidstate(header, h);
      uint32_t groups[4] = {
          0, 1, 1048575,
          (trial % 2 ? 1048574u : static_cast<uint32_t>(rng() & 1048575))};
      std::shuffle(groups, groups + 4, rng);
      uint8_t actual[4][64];
      kernel.second(h, header + 128, groups, actual);
      uint8_t personal[16] = {};
      std::memcpy(personal, "ZcashPoW", 8);
      personal[8] = 200;
      personal[12] = 9;
      for (size_t lane = 0; lane < 4; ++lane) {
        crypto_generichash_blake2b_state state;
        uint8_t expected[50], group[4];
        for (unsigned i = 0; i < 4; ++i)
          group[i] = uint8_t(groups[lane] >> (8 * i));
        if (crypto_generichash_blake2b_init_salt_personal(
                &state, nullptr, 0, 50, nullptr, personal) != 0)
          return 1;
        crypto_generichash_blake2b_update(&state, header, 140);
        crypto_generichash_blake2b_update(&state, group, 4);
        crypto_generichash_blake2b_final(&state, expected, 50);
        if (std::memcmp(expected, actual[lane], 50) != 0) {
          std::cerr << kernel.first << " hash mismatch " << trial << " " << lane
                    << "\n";
          return 1;
        }
      }
    }
    std::cerr << kernel.first << ": 1024 leaf hashes match libsodium\n";
  }
  return 0;
}
