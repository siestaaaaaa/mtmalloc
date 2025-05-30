#include <benchmark/benchmark.h>

#include <random>
#include <thread>
#include <vector>

#include "mtmalloc.h"

void mtmalloc_benchmark(benchmark::State& state) {
    const auto max_size = state.range(0);
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<size_t> size_dist(0, max_size);

    for (auto _ : state) {
        void* ptr = mtmalloc::malloc(size_dist(rng));
        benchmark::DoNotOptimize(ptr);
        mtmalloc::free(ptr);
    }
}

BENCHMARK(mtmalloc_benchmark)
    ->Iterations(1000000)
    ->Args({32 * 1024})
    ->Args({64 * 1024})
    ->Args({128 * 1024})
    ->Args({256 * 1024})
    ->Threads(2)
    ->Threads(4)
    ->Threads(8)
    ->Threads(16)
    ->Threads(32)
    ->Threads(64);

BENCHMARK_MAIN();
