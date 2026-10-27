// Explicit eight-lane tests. Scalar control runs even without AVX-512 hardware.
#include "crypto/equihash.h"
#include "crypto/equihash_200_9_internal.h"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <thread>
#include <vector>
namespace {
using namespace equihash2009;
struct Proof {
  std::string name;
  bool valid;
  std::vector<uint8_t> header, solution;
};
std::atomic<size_t> hash_calls(0);
void ScalarEight(const uint64_t *state, const uint8_t *tail,
                 const uint32_t *groups, uint8_t out[8][64]) {
  ScalarHashFour(state, tail, groups, out);
  ScalarHashFour(state, tail, groups + 4, out + 4);
}
void ZeroEight(const uint64_t *, const uint8_t *, const uint32_t *,
               uint8_t out[8][64]) {
  ++hash_calls;
  std::memset(out, 0, 8 * 64);
}
template <size_t Height>
void CollisionEight(const uint64_t *, const uint8_t *, const uint32_t *groups,
                    uint8_t out[8][64]) {
  ++hash_calls;
  std::memset(out, 0, 8 * 64);
  for (size_t lane = 0; lane < 8; ++lane)
    if (groups[lane] == 0)
      out[lane][20 * Height / 8] = uint8_t(0x80 >> (20 * Height % 8));
}
std::vector<uint8_t> decode(const std::string &hex) {
  if (hex.size() % 2)
    throw std::runtime_error("Odd hex length");
  std::vector<uint8_t> bytes;
  for (size_t i = 0; i < hex.size(); i += 2)
    bytes.push_back(uint8_t(std::stoul(hex.substr(i, 2), nullptr, 16)));
  return bytes;
}
bool original(const Proof &p) {
  eh_HashState state;
  EhInitialiseState(200, 9, state);
  crypto_generichash_blake2b_update(&state, p.header.data(), 140);
  return Eh200_9.IsValidSolution(state, p.solution);
}
bool every_collision(const Proof &seed) {
  std::vector<uint8_t> solution(1344, 0);
  for (size_t index = 0; index < 512; ++index)
    for (size_t bit = 0; bit < 21; ++bit) {
      const size_t at = index * 21 + bit;
      solution[at / 8] |= uint8_t(((index >> (20 - bit)) & 1) << (7 - at % 8));
    }
  if (!VerifyWithHashEight(HashEight(ZeroEight), seed.header.data(), 140,
                           solution.data(), 1344))
    return false;
  const HashGroups faults[] = {CollisionEight<0>, CollisionEight<1>,
                               CollisionEight<2>, CollisionEight<3>,
                               CollisionEight<4>, CollisionEight<5>,
                               CollisionEight<6>, CollisionEight<7>,
                               CollisionEight<8>, CollisionEight<9>};
  for (size_t height = 0; height < 10; ++height) {
    hash_calls = 0;
    if (VerifyWithHashEight(HashEight(faults[height]), seed.header.data(), 140,
                            solution.data(), 1344))
      return false;
    const size_t leaves =
        std::min(size_t(512), std::max(size_t(64), size_t(2) << height));
    if (hash_calls != leaves / 8)
      return false;
  }
  return true;
}
bool check_hashes(HashEight hash) {
  std::mt19937_64 rng(0x5125141191ULL);
  for (size_t trial = 0; trial < 256; ++trial) {
    uint8_t header[140], actual[8][64];
    for (auto &byte : header)
      byte = uint8_t(rng());
    uint32_t groups[8] = {0, 1, 1048574, 1048575};
    for (size_t lane = 4; lane < 8; ++lane)
      groups[lane] = uint32_t(rng() & 1048575);
    std::shuffle(groups, groups + 8, rng);
    uint64_t state[8];
    InitialiseMidstate(header, state);
    hash(state, header + 128, groups, actual);
    uint8_t personal[16] = {};
    std::memcpy(personal, "ZcashPoW", 8);
    personal[8] = 200;
    personal[12] = 9;
    for (size_t lane = 0; lane < 8; ++lane) {
      eh_HashState reference;
      uint8_t expected[50], group[4];
      for (size_t byte = 0; byte < 4; ++byte)
        group[byte] = uint8_t(groups[lane] >> (8 * byte));
      if (crypto_generichash_blake2b_init_salt_personal(&reference, nullptr, 0,
                                                        50, nullptr, personal))
        return false;
      crypto_generichash_blake2b_update(&reference, header, 140);
      crypto_generichash_blake2b_update(&reference, group, 4);
      crypto_generichash_blake2b_final(&reference, expected, 50);
      if (std::memcmp(actual[lane], expected, 50)) {
        std::cerr << "Eight-lane digest mismatch, trial " << trial << " lane "
                  << lane << '\n';
        return false;
      }
    }
  }
  return true;
}
} // namespace
int main(int argc, char **argv) {
  if ((argc != 2 && argc != 3) || sodium_init() < 0)
    return 2;
  const bool required = argc == 3 && std::string(argv[2]) == "--require-avx512";
  if (argc == 3 && !required)
    return 2;
  std::array<HashEight, 16> first;
  std::vector<std::thread> initializers;
  for (size_t i = 0; i < first.size(); ++i)
    initializers.emplace_back([&, i] { first[i] = Avx512HashEight(); });
  for (auto &thread : initializers)
    thread.join();
  for (auto pointer : first)
    if (pointer != first[0])
      return 1;
  const auto wide = Avx512HashEight();
  if (required && !wide) {
    std::cerr << "AVX-512 required but unavailable\n";
    return 1;
  }
  std::vector<std::pair<const char *, HashEight>> kernels{
      {"scalar-eight", HashEight(ScalarEight)}};
  if (wide)
    kernels.emplace_back("avx512", wide);
  std::ifstream input(argv[1]);
  if (!input || !freopen("/dev/null", "w", stdout))
    return 2;
  std::vector<Proof> proofs;
  std::string line;
  while (std::getline(input, line)) {
    std::istringstream fields(line);
    std::string name, verdict, header, solution;
    if (!(fields >> name >> verdict >> header >> solution))
      return 2;
    proofs.push_back(
        {name, verdict == "valid", decode(header), decode(solution)});
  }
  if (proofs.empty() || !every_collision(proofs[0]))
    return 1;
  std::mt19937_64 rng(0x5141191);
  for (size_t i = 0; i < 512; ++i) {
    auto p = proofs[0];
    p.solution[rng() % p.solution.size()] ^= uint8_t(1u << (rng() % 8));
    p.valid = original(p);
    p.name = "mutated-proof";
    proofs.push_back(p);
  }
  for (const auto &kernel : kernels) {
    if (!check_hashes(kernel.second))
      return 1;
    uint8_t byte = 0;
    for (size_t length :
         {size_t(0), size_t(108), size_t(139), size_t(141), size_t(-1)})
      if (VerifyWithHashEight(kernel.second, &byte, length, &byte, 1344))
        return 1;
    for (size_t length : {size_t(0), size_t(1343), size_t(1345), size_t(-1)})
      if (VerifyWithHashEight(kernel.second, &byte, 140, &byte, length))
        return 1;
    if (VerifyWithHashEight(kernel.second, nullptr, 140, &byte, 1344) ||
        VerifyWithHashEight(kernel.second, &byte, 140, nullptr, 1344))
      return 1;
    for (const auto &p : proofs) {
      if (original(p) != p.valid ||
          VerifyWithHashEight(kernel.second, p.header.data(), p.header.size(),
                              p.solution.data(),
                              p.solution.size()) != p.valid) {
        std::cerr << kernel.first << " proof disagreement: " << p.name << '\n';
        return 1;
      }
      if (p.name.find("swap-") == 0 || p.name.find("duplicate-") == 0) {
        hash_calls = 0;
        if (VerifyWithHashEight(HashEight(ZeroEight), p.header.data(),
                                p.header.size(), p.solution.data(),
                                p.solution.size()) ||
            hash_calls != 0)
          return 1;
      }
    }
    std::atomic<size_t> failures(0);
    std::vector<std::thread> workers;
    for (size_t i = 0; i < 8; ++i)
      workers.emplace_back([&] {
        for (const auto &p : proofs)
          if (VerifyWithHashEight(kernel.second, p.header.data(),
                                  p.header.size(), p.solution.data(),
                                  p.solution.size()) != p.valid)
            ++failures;
      });
    for (auto &thread : workers)
      thread.join();
    std::cerr << kernel.first << ": 2048 digests match libsodium, "
              << proofs.size() << " proofs, concurrent_failures=" << failures
              << '\n';
    if (failures)
      return 1;
  }
  std::cerr << "AVX-512 available=" << bool(wide) << '\n';
  return 0;
}
