// Compare every available production kernel with the pinned Rust verifier.
#include "crypto/equihash_200_9_internal.h"
#include "crypto/equihash_avx2.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <vector>

extern "C" int rust_reference_verify(const uint8_t *, size_t, const uint8_t *, size_t);
namespace {
using namespace equihash2009;
struct Proof {
  std::vector<uint8_t> header, solution;
};
size_t checked = 0;
const auto avx2 = Avx2HashFour();
const auto avx512 = Avx512HashEight();

bool compare(const uint8_t *header, size_t header_len, const uint8_t *solution,
             size_t solution_len) {
  ++checked;
  const int reference = rust_reference_verify(header, header_len, solution, solution_len);
  if (reference != 0 && reference != 1)
    throw std::runtime_error("Rust reference panicked");
  const bool expected = reference == 1;
  for (HashFour kernel : {ScalarHashFour, avx2}) {
    if (kernel && VerifyWithHashFour(kernel, header, header_len, solution, solution_len) != expected)
      throw std::runtime_error("Four-lane verifier disagrees with Rust");
  }
  if (avx512 && VerifyWithHashEight(avx512, header, header_len, solution, solution_len) != expected)
    throw std::runtime_error("Eight-lane verifier disagrees with Rust");
  if (VerifyEquihash2009(header, header_len, solution, solution_len) != expected)
    throw std::runtime_error("Public verifier disagrees with Rust");
  return expected;
}
bool compare(const Proof &proof) {
  return compare(proof.header.data(), proof.header.size(), proof.solution.data(), proof.solution.size());
}
std::vector<uint8_t> decode(const std::string &hex) {
  if (hex.size() % 2)
    throw std::runtime_error("Odd hex length in corpus");
  std::vector<uint8_t> bytes;
  for (size_t i = 0; i < hex.size(); i += 2)
    bytes.push_back(uint8_t(std::stoul(hex.substr(i, 2), nullptr, 16)));
  return bytes;
}
std::vector<uint8_t> encode(const std::array<uint32_t, 512> &indices) {
  std::vector<uint8_t> bytes(1344, 0);
  for (size_t index = 0; index < indices.size(); ++index)
    for (size_t bit = 0; bit < 21; ++bit) {
      const size_t at = index * 21 + bit;
      bytes[at / 8] |= uint8_t(((indices[index] >> (20 - bit)) & 1) << (7 - at % 8));
    }
  return bytes;
}
} // namespace

int main(int argc, char **argv) {
  try {
    if (argc < 2)
      throw std::runtime_error("Expected proof corpus path");
    for (int i = 2; i < argc; ++i) {
      const std::string option = argv[i];
      if (option == "--require-avx2" && avx2)
        continue;
      if (option == "--require-avx512" && avx512)
        continue;
      throw std::runtime_error("Unknown option or required kernel unavailable: " + option);
    }
    std::ifstream input(argv[1]);
    if (!input)
      throw std::runtime_error("Cannot open proof corpus");
    std::vector<Proof> valid;
    std::string line;
    while (std::getline(input, line)) {
      std::istringstream fields(line);
      std::string name, verdict, header, solution;
      if (!(fields >> name >> verdict >> header >> solution) ||
          (verdict != "valid" && verdict != "invalid"))
        throw std::runtime_error("Malformed proof corpus row");
      Proof proof{decode(header), decode(solution)};
      if (proof.header.size() != 140 || proof.solution.size() != 1344 ||
          compare(proof) != (verdict == "valid"))
        throw std::runtime_error("Corpus expectation disagrees: " + name);
      if (verdict == "valid")
        valid.push_back(proof);
    }
    if (valid.empty())
      throw std::runtime_error("Corpus must contain a valid proof");
    // Every header bit and every sibling swap/duplication for each valid proof.
    for (const auto &proof : valid) {
      for (size_t byte = 0; byte < proof.header.size(); ++byte)
        for (unsigned bit = 0; bit < 8; ++bit) {
          auto changed = proof;
          changed.header[byte] ^= uint8_t(1u << bit);
          compare(changed);
        }
      std::array<uint32_t, 512> indices;
      if (!DecodeAndCheckIndices(proof.solution.data(), indices))
        throw std::runtime_error("Valid proof failed index checks");
      for (size_t width = 1; width < indices.size(); width *= 2)
        for (size_t start = 0; start < indices.size(); start += 2 * width) {
          auto changed = indices;
          std::swap_ranges(changed.begin() + start, changed.begin() + start + width,
                           changed.begin() + start + width);
          compare(Proof{proof.header, encode(changed)});
          changed = indices;
          std::copy_n(indices.begin() + start, width, changed.begin() + start + width);
          compare(Proof{proof.header, encode(changed)});
        }
    }
    for (size_t byte = 0; byte < valid[0].solution.size(); ++byte)
      for (unsigned bit = 0; bit < 8; ++bit) {
        auto changed = valid[0];
        changed.solution[byte] ^= uint8_t(1u << bit);
        compare(changed);
      }
    // Sorted distinct random indices get past the inexpensive rejection checks.
    std::mt19937_64 random(0xface123);
    for (size_t trial = 0; trial < 5000; ++trial) {
      Proof proof{std::vector<uint8_t>(140), std::vector<uint8_t>(1344)};
      for (auto &byte : proof.header)
        byte = uint8_t(random());
      std::array<uint32_t, 512> indices;
      for (size_t i = 0; i < indices.size(); ++i)
        indices[i] = uint32_t(i * 4096 + random() % 4096);
      proof.solution = encode(indices);
      compare(proof);
      for (auto &byte : proof.solution)
        byte = uint8_t(random());
      compare(proof);
    }
    uint8_t byte = 0;
    compare(nullptr, 140, &byte, 1344);
    compare(&byte, 140, nullptr, 1344);
    for (size_t length : {size_t(0), size_t(139), size_t(141), size_t(-1)})
      compare(&byte, length, &byte, 1344);
    for (size_t length : {size_t(0), size_t(1343), size_t(1345), size_t(-1)})
      compare(&byte, 140, &byte, length);
    std::cout << checked << " cases match pinned Rust; AVX2=" << bool(avx2)
              << " AVX512=" << bool(avx512) << '\n';
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "Case " << checked << ": " << error.what() << '\n';
    return 1;
  }
}
