#include <benchmark/benchmark.h>

#include <random>
#include <thread>
#include <vector>

void stdmalloc_benchmark(benchmark::State& state) {
  const auto max_size = state.range(0);
  std::mt19937 rng(std::random_device{}());
  std::uniform_int_distribution<size_t> size_dist(1, max_size);

  for (auto _ : state) {
    void* ptr = std::malloc(size_dist(rng));
    benchmark::DoNotOptimize(ptr);
    std::free(ptr);
  }
}

BENCHMARK(stdmalloc_benchmark)
    ->Iterations(1000000)
    ->Args({32 * 1024})
    ->Args({64 * 1024})
    ->Args({128 * 1024})
    ->Args({256 * 1024})
    ->Threads(1)
    ->Threads(4)
    ->Threads(16)
    ->Threads(64)
    ->UseRealTime();

BENCHMARK_MAIN();
