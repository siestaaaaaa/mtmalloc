#include <random>
#include <benchmark/benchmark.h>
#include <mimalloc.h>

void mimalloc_benchmark(benchmark::State& state) {
    const auto max_size = state.range(0);
    std::uniform_int_distribution<size_t> size_dist(0, max_size);

    std::mt19937 rng(42);
    for (auto _ : state) {
        void* ptr = mi_malloc(size_dist(rng));
        benchmark::DoNotOptimize(ptr);
        mi_free(ptr);
    }
}

BENCHMARK(mimalloc_benchmark)
->Iterations(1000000)
->Args({ 32 * 1024 })
->Args({ 64 * 1024 })
->Args({ 128 * 1024 })
->Args({ 256 * 1024 })
->Threads(2)
->Threads(4)
->Threads(8)
->Threads(16)
->Threads(32);

int main(int argc, char* argv[]) {
    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
}
