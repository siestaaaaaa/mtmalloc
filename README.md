# mtmalloc : multi-threaded malloc

mtmalloc is a header-only, high-performance memory allocator designed for multi-threaded C++ applications.

It's extremely easy to setup. Just include the **mtmalloc.h** file in your code!

> Please ensure your compiler supports C++17 or later standards, and use O2 or higher optimization level.

# Benchmark

Run on (16 X 3793 MHz CPU s), Windows 10

Memory: 32GB

Iterations: 1000000

|  size  | threads | mtmalloc | malloc | jemalloc | mimalloc | tcmalloc |
|:------:|:-------:|:--------:|:------:|:--------:|:--------:|:--------:|
| 0 ~ 32K|    2    |   19ns   |   360ns|    61ns  |   38ns   |    14ns  |
| 0 ~ 32K|    4    |   29ns   |   772ns|    82ns  |   47ns   |    25ns  |
| 0 ~ 32K|    8    |   57ns   |  2218ns|   129ns  |   83ns   |    45ns  |
| 0 ~ 32K|   16    |  150ns   |  7215ns|   169ns  |  162ns   |   132ns  |
| 0 ~ 32K|   32    |  292ns   | 13942ns|   299ns  |  294ns   |   257ns  |
| 0 ~ 64K|    2    |   20ns   |  1264ns|   147ns  |  141ns   |    13ns  |
| 0 ~ 64K|    4    |   33ns   |  2734ns|   154ns  |  147ns   |    25ns  |
| 0 ~ 64K|    8    |   77ns   |  5589ns|   190ns  |  163ns   |    51ns  |
| 0 ~ 64K|   16    |  152ns   | 15002ns|   286ns  |  269ns   |   134ns  |
| 0 ~ 64K|   32    |  329ns   | 27032ns|   522ns  |  468ns   |   256ns  |
|0 ~ 128K|    2    |   32ns   |  1771ns|   194ns  |  158ns   |    13ns  |
|0 ~ 128K|    4    |   50ns   |  4117ns|   208ns  |  162ns   |    25ns  |
|0 ~ 128K|    8    |  105ns   |  8573ns|   239ns  |  186ns   |    52ns  |
|0 ~ 128K|   16    |  237ns   | 25888ns|   359ns  |  284ns   |   133ns  |
|0 ~ 128K|   32    |  473ns   | 53676ns|   656ns  |  523ns   |   245ns  |
|0 ~ 256K|    2    |   63ns   |  3770ns|   212ns  |  168ns   |    16ns  |
|0 ~ 256K|    4    |  102ns   |  9853ns|   222ns  |  175ns   |    25ns  |
|0 ~ 256K|    8    |  165ns   | 17515ns|   251ns  |  201ns   |    57ns  |
|0 ~ 256K|   16    |  352ns   | 42019ns|   387ns  |  291ns   |   621ns  |
|0 ~ 256K|   32    |  758ns   | 89222ns|   714ns  |  523ns   |  7967ns  |

# Introduction

This project draws inspiration from tcmalloc and adopts a three-level cache structure, which effectively reduces lock contention and context switching during memory allocation in multi-threaded environments. Each level of the cache uses open hashing to manage memory blocks of varying sizes and employs an object pool to accelerate metadata allocation.

- The thread cache leverages thread-local storage to provide a dedicated cache for each thread. Each thread can allocate and deallocate memory from its own cache without contending with other threads, which reduces synchronization overhead and improves performance in multi-threaded applications.
- The central cache acts as an intermediary between the thread caches and the page heap. It is responsible for scheduling resources between these two levels. To ensure thread safety, the central cache employs bucket-based locking, which minimizes contention by locking the specific bucket rather than the entire cache structure.
- The page heap manages memory at the page level requested from OS, and reduces external fragmentation through a buddy-system-like technique. When allocating memory, it splits a larger chunk into smaller blocks as needed, and when deallocating, it merges adjacent free blocks into a larger chunk.

For more information, you can refer to the source code.

# API

> This project currently provides C-Style API, allowing user to encapsulate as needed.

## `malloc()`

```cpp
void* malloc(size_t bytes);
```

`malloc()` allocates `bytes` uninitialized memory and returns the starting address.

- if `bytes == 0`: return `nullptr`

## `calloc()`

```cpp
void* calloc(size_t num, size_t bytes);
```

The differrence between `calloc()` and `malloc()` is that `calloc()` does zero-initialize all bytes of the allocated memory.

- if `num == 0 or bytes == 0`: return `nullptr`

## `free()`

```cpp
void free(void* ptr);
```

`free()` deallocates memory pointed by `ptr`.

- if `ptr == nullptr`: fine

## `realloc()`

```cpp
void* realloc(void* ptr, size_t new_bytes);
```

`realloc()` deallocates memory pointed by `ptr` and reallocates `new_bytes` uninitialized memory.

- if `new_bytes == 0`: return `nullptr`
- if `ptr == nullptr`: fine

## Example

```cpp
#include "mtmalloc.h"

int main() {
    void* ptr = mtmalloc::malloc(16);
    mtmalloc::free(ptr);
}
```

# NOTE

mtmalloc does throw an `std::bad_alloc` exception when allocations fail, so please catch this exception to handle allocation failures gracefully.
