// No third-party runtime is needed: suitable for cross-architecture execution.
#include "crypto/equihash_200_9_internal.h"
#include "crypto/equihash_avx2.h"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>
std::vector<uint8_t> decode(const std::string &hex) {
  if (hex.size() % 2)
    throw std::runtime_error("odd hex length");
  std::vector<uint8_t> bytes;
  for (size_t i = 0; i < hex.size(); i += 2)
    bytes.push_back(uint8_t(std::stoul(hex.substr(i, 2), nullptr, 16)));
  return bytes;
}
int main(int argc, char **argv) {
  if (argc != 3)
    return 2;
  using namespace equihash2009;
  std::ifstream proofs(argv[1]), hashes(argv[2]);
  if (!proofs || !hashes)
    return 2;
  std::string line;
  size_t proof_count = 0, hash_count = 0;
  while (std::getline(proofs, line)) {
    std::istringstream row(line);
    std::string name, verdict, header_hex, solution_hex;
    if (!(row >> name >> verdict >> header_hex >> solution_hex))
      return 2;
    const auto header = decode(header_hex), solution = decode(solution_hex);
    for (const HashFour kernel : {ScalarHashFour, SelectedHashFour()})
      if (VerifyWithHashFour(kernel, header.data(), header.size(),
                             solution.data(),
                             solution.size()) != (verdict == "valid")) {
        std::cerr << "portable disagreement: " << name << '\n';
        return 1;
      }
    ++proof_count;
  }
  while (std::getline(hashes, line)) {
    std::istringstream row(line);
    std::string header_hex, expected_hex;
    uint32_t group;
    if (!(row >> header_hex >> group >> expected_hex))
      return 2;
    const auto header = decode(header_hex), expected = decode(expected_hex);
    if (header.size() != 140 || expected.size() != 50 || group > 1048575)
      return 2;
    uint64_t state[8];
    InitialiseMidstate(header.data(), state);
    const uint32_t groups[4] = {group, group, group, group};
    uint8_t actual[4][64];
    ScalarHashFour(state, header.data() + 128, groups, actual);
    for (const auto &lane : actual)
      if (std::memcmp(lane, expected.data(), 50))
        return 1;
    ++hash_count;
  }
  if (!proof_count || !hash_count)
    return 2;
  std::cout << "portable: " << proof_count << " proofs, " << hash_count
            << " digests; AVX2=" << Equihash2009HasAvx2() << '\n';
  return 0;
}
