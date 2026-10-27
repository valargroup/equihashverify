// Exercise the production dispatcher with controlled kernel availability.
// This executable links the real tree walk and scalar kernel, replacing only
// the hardware kernel providers so every dispatch path runs on every CPU.
#include "crypto/equihash_200_9_internal.h"
#include "crypto/equihash_avx2.h"
#include <atomic>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {
std::string available;
std::atomic<size_t> four_calls(0), eight_calls(0);
void Four(const uint64_t *, const uint8_t *, const uint32_t *, uint8_t out[4][64]) {
  ++four_calls;
  std::memset(out, 0, 4 * 64);
}
void Eight(const uint64_t *, const uint8_t *, const uint32_t *, uint8_t out[8][64]) {
  ++eight_calls;
  std::memset(out, 0, 8 * 64);
}
std::vector<uint8_t> decode(const std::string &hex) {
  std::vector<uint8_t> bytes;
  for (size_t i = 0; i < hex.size(); i += 2)
    bytes.push_back(uint8_t(std::stoul(hex.substr(i, 2), nullptr, 16)));
  return bytes;
}
} // namespace

namespace equihash2009 {
HashFour Avx2HashFour() { return available == "scalar" ? nullptr : Four; }
HashEight Avx512HashEight() {
  return HashEight(available == "avx512" ? Eight : nullptr);
}
} // namespace equihash2009

int main(int argc, char **argv) {
  if (argc != 4)
    return 2;
  available = argv[2];
  const std::string policy = argv[3];
  if (policy != "default" && policy != "enabled")
    return 2;
  if (available != "scalar" && available != "avx2" && available != "avx512")
    return 2;
  std::ifstream input(argv[1]);
  std::string line, name, verdict, header_hex, solution_hex;
  if (!std::getline(input, line))
    return 2;
  std::istringstream fields(line);
  if (!(fields >> name >> verdict >> header_hex >> solution_hex) || verdict != "valid")
    return 2;
  const auto header = decode(header_hex), solution = decode(solution_hex);
  std::atomic<size_t> failures(0);
  std::vector<std::thread> threads;
  for (size_t i = 0; i < 8; ++i)
    threads.emplace_back([&] {
      if (!VerifyEquihash2009(header.data(), header.size(), solution.data(), solution.size()))
        ++failures;
    });
  for (auto &thread : threads)
    thread.join();
  const size_t expected_eight =
      available == "avx512" && policy == "enabled" ? 8 * 64 : 0;
  const size_t expected_four =
      available != "scalar" && !expected_eight ? 8 * 128 : 0;
  if (failures || four_calls != expected_four || eight_calls != expected_eight) {
    std::cerr << "Wrong automatic backend: " << available << ", four=" << four_calls
              << ", eight=" << eight_calls << ", failures=" << failures << '\n';
    return 1;
  }
  if (VerifyEquihash2009(nullptr, 140, solution.data(), 1344) ||
      VerifyEquihash2009(header.data(), 139, solution.data(), 1344) ||
      VerifyEquihash2009(header.data(), 140, solution.data(), 1343) ||
      VerifyEquihash2009(header.data(), 140, nullptr, 1344) ||
      four_calls != expected_four || eight_calls != expected_eight)
    return 1;
  std::cout << "Availability=" << available << ", AVX512 policy=" << policy
            << ": dispatch and concurrent initialization passed\n";
}
