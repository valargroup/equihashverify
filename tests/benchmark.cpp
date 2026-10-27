#include "crypto/equihash.h"
#include "crypto/equihash_200_9_internal.h"
#include "crypto/equihash_avx2.h"
#include <algorithm>
#include <atomic>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
#include <time.h>
#include <vector>
struct Proof {
  bool valid;
  std::vector<uint8_t> header, solution;
};
uint64_t ns(clockid_t clock) {
  timespec t;
  if (clock_gettime(clock, &t))
    throw std::runtime_error("clock failed");
  return uint64_t(t.tv_sec) * 1000000000 + uint64_t(t.tv_nsec);
}
std::vector<uint8_t> decode(const std::string &s) {
  std::vector<uint8_t> bytes;
  for (size_t i = 0; i < s.size(); i += 2)
    bytes.push_back(uint8_t(std::stoul(s.substr(i, 2), nullptr, 16)));
  return bytes;
}
bool legacy(const Proof &p) {
  eh_HashState state;
  EhInitialiseState(200, 9, state);
  crypto_generichash_blake2b_update(&state, p.header.data(), 140);
  return Eh200_9.IsValidSolution(state, p.solution);
}
int main(int argc, char **argv) {
  if (argc != 6 || sodium_init() < 0)
    return 2;
  const std::string backend = argv[1], workload = argv[3];
  const size_t threads = std::stoul(argv[4]), iterations = std::stoul(argv[5]);
  if (!threads || threads > 8 || !iterations || iterations > 1000000)
    return 2;
  const auto kernel = backend == "scalar" ? equihash2009::ScalarHashFour
                                          : equihash2009::Avx2HashFour();
  if (backend != "legacy" && backend != "scalar" && backend != "avx2" &&
      backend != "avx512")
    return 2;
  const auto wide = equihash2009::Avx512HashEight();
  if (backend == "avx512" && !wide)
    return 2;
  if (backend != "legacy" && backend != "avx512" && !kernel)
    return 2;
  std::ifstream input(argv[2]);
  std::string line;
  std::vector<Proof> cases;
  while (std::getline(input, line)) {
    std::istringstream fields(line);
    std::string name, verdict, header, solution;
    if (!(fields >> name >> verdict >> header >> solution))
      return 2;
    if ((workload == "valid" && verdict == "valid") ||
        (workload == "early" && name == "duplicate-index-511") ||
        (workload == "late" && name == "root-nonzero") ||
        (workload == "order" && name == "swap-height-8-start-0"))
      cases.push_back({verdict == "valid", decode(header), decode(solution)});
  }
  if (cases.empty() || !freopen("/dev/null", "w", stdout))
    return 2;
  auto verify = [&](const Proof &p) {
    if (backend == "avx512")
      return equihash2009::VerifyWithHashEight(
          wide, p.header.data(), p.header.size(), p.solution.data(),
          p.solution.size());
    return backend == "legacy" ? legacy(p)
                               : equihash2009::VerifyWithHashFour(
                                     kernel, p.header.data(), p.header.size(),
                                     p.solution.data(), p.solution.size());
  };
  for (size_t warmup = 0; warmup < 64; ++warmup)
    if (verify(cases[warmup % cases.size()]) !=
        cases[warmup % cases.size()].valid)
      return 1;
  std::vector<std::vector<uint64_t>> latencies(
      threads, std::vector<uint64_t>(iterations));
  std::atomic<size_t> ready(0), failures(0);
  std::atomic<bool> go(false);
  std::vector<std::thread> workers;
  for (size_t thread = 0; thread < threads; ++thread)
    workers.emplace_back([&, thread] {
      const uint64_t warm_until = ns(CLOCK_MONOTONIC) + 50000000;
      size_t warmup = 0;
      do {
        const auto &proof = cases[(warmup++ + thread) % cases.size()];
        if (verify(proof) != proof.valid)
          ++failures;
      } while (ns(CLOCK_MONOTONIC) < warm_until);
      ++ready;
      while (!go.load(std::memory_order_acquire))
        std::this_thread::yield();
      for (size_t i = 0; i < iterations; ++i) {
        const auto &proof = cases[(i + thread) % cases.size()];
        const uint64_t start = ns(CLOCK_MONOTONIC);
        if (verify(proof) != proof.valid)
          ++failures;
        latencies[thread][i] = ns(CLOCK_MONOTONIC) - start;
      }
    });
  while (ready != threads)
    std::this_thread::yield();
  const uint64_t cpu_start = ns(CLOCK_PROCESS_CPUTIME_ID),
                 wall_start = ns(CLOCK_MONOTONIC);
  go.store(true, std::memory_order_release);
  for (auto &thread : workers)
    thread.join();
  const uint64_t wall = ns(CLOCK_MONOTONIC) - wall_start;
  const uint64_t cpu = ns(CLOCK_PROCESS_CPUTIME_ID) - cpu_start;
  std::vector<uint64_t> samples;
  for (const auto &latency : latencies)
    samples.insert(samples.end(), latency.begin(), latency.end());
  std::sort(samples.begin(), samples.end());
  auto quantile = [&](size_t percent) {
    return samples[(samples.size() - 1) * percent / 100];
  };
  std::cerr << backend << ',' << workload << ',' << threads << ','
            << samples.size() << ',' << wall << ',' << cpu << ','
            << double(cpu) / samples.size() << ',' << quantile(50) << ','
            << quantile(95) << ',' << quantile(99) << ',' << failures << '\n';
  return failures ? 1 : 0;
}
