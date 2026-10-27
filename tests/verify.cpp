// Native-only proof and concurrency tests against the original verifier.
#include "crypto/equihash.h"
#include "crypto/equihash_200_9_internal.h"
#include "crypto/equihash_avx2.h"
#include <atomic>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <thread>
struct Proof {
  std::string name;
  bool valid;
  std::vector<uint8_t> header, solution;
};
std::vector<uint8_t> decode(const std::string &hex) {
  std::vector<uint8_t> out;
  for (size_t i = 0; i < hex.size(); i += 2)
    out.push_back(
        static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
  return out;
}
bool original(const Proof &p) {
  eh_HashState state;
  EhInitialiseState(200, 9, state);
  crypto_generichash_blake2b_update(&state, p.header.data(), 140);
  return Eh200_9.IsValidSolution(state, p.solution);
}
bool candidate(const Proof &p) {
  return VerifyEquihash2009(p.header.data(), p.header.size(), p.solution.data(),
                            p.solution.size());
}

namespace {
std::atomic<size_t> hash_calls(0);
void CountHashes(const uint64_t *, const uint8_t *, const uint32_t *,
                 uint8_t out[4][64]) {
  ++hash_calls;
  std::memset(out, 0, 4 * 64);
}
template <size_t Height>
void CollisionAtHeight(const uint64_t *, const uint8_t *,
                       const uint32_t *groups, uint8_t out[4][64]) {
  ++hash_calls;
  std::memset(out, 0, 4 * 64);
  for (size_t lane = 0; lane < 4; ++lane)
    if (groups[lane] == 0)
      out[lane][20 * Height / 8] = uint8_t(0x80 >> (20 * Height % 8));
}
// A deterministic injected leaf-hasher isolates each collision/root check.
// Real BLAKE2b proof decisions are checked separately against fixed vectors.
bool CheckEveryCollision(const Proof &seed) {
  std::vector<uint8_t> solution(1344, 0);
  for (size_t index = 0; index < 512; ++index)
    for (size_t bit = 0; bit < 21; ++bit) {
      const size_t at = index * 21 + bit;
      solution[at / 8] |= uint8_t(((index >> (20 - bit)) & 1) << (7 - at % 8));
    }
  using namespace equihash2009;
  if (!VerifyWithHashFour(CountHashes, seed.header.data(), 140, solution.data(),
                          1344))
    return false;
  const HashFour failures[] = {CollisionAtHeight<0>, CollisionAtHeight<1>,
                               CollisionAtHeight<2>, CollisionAtHeight<3>,
                               CollisionAtHeight<4>, CollisionAtHeight<5>,
                               CollisionAtHeight<6>, CollisionAtHeight<7>,
                               CollisionAtHeight<8>, CollisionAtHeight<9>};
  for (size_t height = 0; height < 10; ++height) {
    hash_calls = 0;
    if (VerifyWithHashFour(failures[height], seed.header.data(), 140,
                           solution.data(), 1344))
      return false;
    const size_t leaves_to_failure = std::max(size_t(64), size_t(2) << height);
    const size_t expected_calls = std::min(size_t(512), leaves_to_failure) / 4;
    if (hash_calls != expected_calls)
      return false;
  }
  return true;
}
} // namespace
int main(int argc, char **argv) {
  if ((argc != 2 && argc != 3) || sodium_init() < 0)
    return 2;
  using namespace equihash2009;
  const bool require_avx2 =
      argc == 3 && std::string(argv[2]) == "--require-avx2";
  if (argc == 3 && !require_avx2)
    return 2;
  std::vector<std::thread> initializers;
  std::array<HashFour, 16> selected;
  for (size_t i = 0; i < selected.size(); ++i)
    initializers.emplace_back([&, i] { selected[i] = SelectedHashFour(); });
  for (auto &thread : initializers)
    thread.join();
  for (auto kernel : selected)
    if (kernel != selected[0])
      return 1;
  const auto avx2 = Avx2HashFour();
  if (require_avx2 && !avx2) {
    std::cerr << "AVX2 required but unavailable\n";
    return 1;
  }
  std::vector<HashFour> kernels{ScalarHashFour};
  if (avx2)
    kernels.push_back(avx2);
  if (SelectedHashFour() != (avx2 ? avx2 : ScalarHashFour))
    return 1;
  if (!freopen("/dev/null", "w", stdout))
    return 2;
  std::ifstream input(argv[1]);
  if (!input)
    return 2;
  std::vector<Proof> cases;
  std::string line;
  while (std::getline(input, line)) {
    std::istringstream s(line);
    std::string name, verdict, header, solution;
    if (!(s >> name >> verdict >> header >> solution))
      return 2;
    cases.push_back(
        {name, verdict == "valid", decode(header), decode(solution)});
  }
  if (cases.empty())
    return 2;
  uint8_t byte = 0;
  for (size_t len : std::vector<size_t>{0, 108, 139, 141, size_t(-1)})
    if (VerifyEquihash2009(&byte, len, &byte, 1344))
      return 1;
  for (size_t len : std::vector<size_t>{0, 1343, 1345, size_t(-1)})
    if (VerifyEquihash2009(&byte, 140, &byte, len))
      return 1;
  if (VerifyEquihash2009(nullptr, 140, &byte, 1344) ||
      VerifyEquihash2009(&byte, 140, nullptr, 1344))
    return 1;
  std::mt19937_64 rng(0x5141191);
  for (size_t i = 0; i < 512; ++i) {
    auto p = cases[0];
    p.solution[rng() % p.solution.size()] ^= uint8_t(1u << (rng() % 8));
    p.valid = original(p);
    p.name = "mutated-proof";
    cases.push_back(p);
  }
  uint8_t short_buffer = 0;
  for (const auto kernel : kernels) {
    for (size_t len : std::vector<size_t>{0, 108, 139, 141, size_t(-1)})
      if (VerifyWithHashFour(kernel, &short_buffer, len, &short_buffer, 1344))
        return 1;
    for (size_t len : std::vector<size_t>{0, 1343, 1345, size_t(-1)})
      if (VerifyWithHashFour(kernel, &short_buffer, 140, &short_buffer, len))
        return 1;
    if (VerifyWithHashFour(kernel, nullptr, 140, &short_buffer, 1344) ||
        VerifyWithHashFour(kernel, &short_buffer, 140, nullptr, 1344))
      return 1;
  }
  if (!CheckEveryCollision(cases[0]))
    return 1;
  size_t valid = 0;
  for (const auto &p : cases) {
    if (original(p) != p.valid || candidate(p) != p.valid) {
      std::cerr << "disagreement: " << p.name << "\n";
      return 1;
    }
    for (const auto kernel : kernels) {
      if (VerifyWithHashFour(kernel, p.header.data(), p.header.size(),
                             p.solution.data(), p.solution.size()) != p.valid) {
        std::cerr << "explicit kernel disagreement: " << p.name << "\n";
        return 1;
      }
    }
    if (p.name.find("swap-") == 0 || p.name.find("duplicate-") == 0) {
      std::array<uint32_t, 512> decoded;
      hash_calls = 0;
      if (DecodeAndCheckIndices(p.solution.data(), decoded) ||
          VerifyWithHashFour(CountHashes, p.header.data(), p.header.size(),
                             p.solution.data(), p.solution.size()) ||
          hash_calls != 0)
        return 1;
    }
    valid += p.valid;
  }
  std::atomic<size_t> failures(0);
  std::vector<std::thread> workers;
  for (size_t t = 0; t < 8; ++t)
    workers.emplace_back([&] {
      for (const auto &p : cases)
        for (const auto kernel : kernels)
          if (VerifyWithHashFour(kernel, p.header.data(), p.header.size(),
                                 p.solution.data(),
                                 p.solution.size()) != p.valid ||
              candidate(p) != p.valid)
            ++failures;
    });
  for (auto &t : workers)
    t.join();
  std::cerr << "checked=" << cases.size() << " valid=" << valid
            << " AVX2=" << Equihash2009HasAvx2()
            << " concurrent_failures=" << failures << "\n";
  return failures ? 1 : 0;
}
