# mtmalloc : multi-threaded malloc

mtmalloc is a header-only, high-performance memory allocator designed specifically for multi-threaded C++ applications. It currently supports Windows and Linux environments.

It's extremely easy to setup. Just include the **mtmalloc.h** file in your code!

> Please ensure that your compiler supports C++17 or later standards, and use a compiler optimization level of O2 or higher.

# Benchmark

CPU: 12th Gen Intel(R) Core(TM) i7-12700H

Memory: 16 GB

OS: Ubuntu 22.04

Compiler: g++ 13.3.0

|  size  | threads | malloc | mtmalloc | malloc/mtmalloc |
|:------:|:-------:|:------:|:--------:|:---------------:|
| 0 ~ 32K|    1    | 17.5ns |  17.2ns  |      1.02       |
| 0 ~ 32K|    4    | 30.3ns |  11.0ns  |      2.75       |
| 0 ~ 32K|   16    | 46.7ns |  16.3ns  |      2.87       |
| 0 ~ 32K|   64    | 54.3ns |  19.5ns  |      2.78       |
| 0 ~ 64K|    1    | 34.5ns |  10.7ns  |      3.22       |
| 0 ~ 64K|    4    | 34.3ns |  11.6ns  |      2.96       |
| 0 ~ 64K|   16    | 50.5ns |  17.6ns  |      2.87       |
| 0 ~ 64K|   64    | 57.5ns |  19.7ns  |      2.92       |
|0 ~ 128K|    1    | 33.7ns |  14.2ns  |      2.37       |
|0 ~ 128K|    4    | 33.4ns |  15.7ns  |      2.13       |
|0 ~ 128K|   16    | 48.8ns |  21.4ns  |      2.28       |
|0 ~ 128K|   64    | 53.7ns |  23.8ns  |      2.26       |
|0 ~ 256K|    1    | 39.9ns |  12.1ns  |      3.30       |
|0 ~ 256K|    4    | 35.1ns |  13.4ns  |      2.62       |
|0 ~ 256K|   16    | 52.3ns |  19.1ns  |      2.74       |
|0 ~ 256K|   64    | 54.4ns |  21.2ns  |      2.57       |

# Introduction

This project draws inspiration from TCMalloc and adopts a three-level cache structure, which effectively reduces lock contention and context switching during memory allocation in multi-threaded environments. The memory management within the project does not rely on the standard library but instead obtains memory through system calls. Memory released by users is preferentially managed within the caches to minimize the frequency of system calls. Each level of the cache uses open hashing to manage memory blocks of varying sizes and employs an object pool to accelerate metadata allocation.

Core Modules:

- The Thread Cache leverages thread-local storage to provide a dedicated cache for each thread. This design allows for lock-free access, significantly enhancing concurrency efficiency. Each thread can allocate and deallocate memory from its own cache without contending with other threads, which reduces synchronization overhead and improves performance in multi-threaded applications.
- The Central Cache acts as an intermediary between the thread caches and the page heap. It is responsible for balancing resources by scheduling allocations and deallocations between these two levels. To ensure high concurrency performance and thread safety, the central cache employs bucket-based locking. This method minimizes contention by only locking the specific bucket that is being accessed, rather than locking the entire cache structure.
- The Page Heap manages memory at the page level, requesting memory from the operating system in units of pages. It addresses external fragmentation issues through the use of a buddy system and page merging techniques. When allocating memory, it splits larger blocks into smaller ones as needed, and when deallocating, it merges adjacent free blocks back into larger chunks. This approach helps maintain a contiguous block of free memory, reducing fragmentation and improving memory utilization.

In summary, this three-tiered caching architecture—comprising the Thread Cache, Central Cache, and Page Heap—is designed to optimize memory allocation and deallocation processes in multi-threaded environments. By minimizing lock contention, efficiently managing resources, and mitigating memory fragmentation, this system provides a robust solution for high-performance memory management in C++ applications.

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
