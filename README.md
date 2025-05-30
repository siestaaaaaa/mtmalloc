# mtmalloc : multi-threaded malloc

mtmalloc is a header-only, high-performance memory allocator designed for multi-threaded C++ applications. It currently supports Windows and Linux environments.

It's extremely easy to setup. Just include the **mtmalloc.h** file in your code!

> Please ensure that your compiler supports C++17 or later standards, and use O2 or higher optimization level.

# Benchmark

CPU: 12th Gen Intel i7-12700H (20) @ 2.688GHz 

Memory: 16 GB

OS: Ubuntu 24.04.2 LTS on Windows 10 x86_64

Compiler: g++ 13.3.0

|  size  | threads | malloc | mtmalloc | malloc/mtmalloc |
|:------:|:-------:|:------:|:--------:|:---------------:|
| 0 ~ 32K|    2    | 34.7ns |  23.8ns  |      1.46       |
| 0 ~ 32K|    4    | 34.7ns |  16.3ns  |      2.13       |
| 0 ~ 32K|    8    | 39.5ns |  19.1ns  |      2.07       |
| 0 ~ 32K|   16    | 51.2ns |  24.0ns  |      2.13       |
| 0 ~ 32K|   32    | 59.8ns |  25.2ns  |      2.37       |
| 0 ~ 32K|   64    | 60.8ns |  26.0ns  |      2.34       |
| 0 ~ 64K|    2    | 39.5ns |  14.9ns  |      2.65       |
| 0 ~ 64K|    4    | 34.7ns |  15.4ns  |      2.25       |
| 0 ~ 64K|    8    | 40.1ns |  17.7ns  |      2.27       |
| 0 ~ 64K|   16    | 56.0ns |  23.3ns  |      2.40       |
| 0 ~ 64K|   32    | 61.4ns |  24.4ns  |      2.52       |
| 0 ~ 64K|   64    | 63.4ns |  25.3ns  |      2.51       |
|0 ~ 128K|    2    | 35.8ns |  17.4ns  |      2.06       |
|0 ~ 128K|    4    | 36.8ns |  18.6ns  |      1.98       |
|0 ~ 128K|    8    | 42.4ns |  21.2ns  |      2.00       |
|0 ~ 128K|   16    | 55.5ns |  27.0ns  |      2.06       |
|0 ~ 128K|   32    | 61.5ns |  27.7ns  |      2.22       |
|0 ~ 128K|   64    | 62.9ns |  32.0ns  |      1.97       |
|0 ~ 256K|    2    | 34.4ns |  15.8ns  |      2.18       |
|0 ~ 256K|    4    | 33.9ns |  17.5ns  |      1.94       |
|0 ~ 256K|    8    | 42.3ns |  18.9ns  |      2.24       |
|0 ~ 256K|   16    | 58.5ns |  23.8ns  |      2.46       |
|0 ~ 256K|   32    | 61.2ns |  25.6ns  |      2.39       |
|0 ~ 256K|   64    | 65.3ns |  27.9ns  |      2.34       |

# Introduction

This project draws inspiration from TCMalloc and adopts a three-level cache structure, which effectively reduces lock contention and context switching during memory allocation in multi-threaded environments. Memory released by users is preferentially managed within the caches to minimize the frequency of system calls. Each level of the cache uses open hashing to manage memory blocks of varying sizes and employs an object pool to accelerate metadata allocation.

Core Modules:

- The Thread Cache leverages thread-local storage to provide a dedicated cache for each thread. This design allows for lock-free access, significantly enhancing concurrency efficiency. Each thread can allocate and deallocate memory from its own cache without contending with other threads, which reduces synchronization overhead and improves performance in multi-threaded applications.
- The Central Cache acts as an intermediary between the thread caches and the page heap. It is responsible for scheduling resources between these two levels. To ensure high concurrency performance and thread safety, the central cache employs bucket-based locking. This method minimizes contention by only locking the specific bucket that is being accessed, rather than locking the entire cache structure.
- The Page Heap manages memory at the page level, requesting memory from the OS in units of pages. It addresses external fragmentation issues through a buddy-system-like page merging techniques. When allocating memory, it splits larger blocks into smaller ones as needed, and when deallocating, it merges adjacent free blocks into larger chunks. This mechanism preserves large contiguous free memory blocks, thereby reducing fragmentation and improving memory usage.

In summary, this three-tiered caching architecture—comprising the Thread Cache, Central Cache, and Page Heap—is designed to optimize memory allocation and deallocation in multi-threaded environments. By minimizing lock contention, efficiently managing resources, and mitigating memory fragmentation, this system provides a robust solution for high-performance memory management in C++ applications.

For more information, you can refer to the source code.

# API

> This project currently only provides C-Style APIs, allowing users to encapsulate them as needed.

## `malloc()`

```cpp
void* malloc(size_t bytes);
```

`malloc()` allocates `bytes` of memory and returns the starting address of the allocated memory.

Specially, `malloc(0)` returns `nullptr`.

## `calloc()`

```cpp
void* calloc(size_t num, size_t bytes);
```

The differrence between `calloc()` and `malloc()` is that `calloc()` will zero-initialize all bytes in allocated storage.

Specially, `calloc(num, 0)` or `calloc(0, bytes)` returns `nullptr`.

## `realloc()`

```cpp
void* realloc(void *ptr, size_t new_bytes);
```

`realloc()` will deallocate the memory pointed by `ptr` and re-allocates `new_bytes` memory that does not perform any initialization.

Specially, `realloc(ptr, 0)` will deallocate the memory pointed by `ptr` and returns `nullptr`.

## `free()`

```cpp
void free(void* ptr);
```

`free()` can deallocates memory previously allocated by `malloc()` / `calloc()` / `realloc()`.

If you pass a null pointer, the function does nothing.

## Example

```cpp
#include "mtmalloc.h"

int main() {
    void* p = mtmalloc::malloc(16);
    mtmalloc::free(p);
}
```

# NOTE

mtmalloc does throw an `std::bad_alloc` exception when allocations fail, so please ensure you catch this exception to handle allocation failures gracefully.
