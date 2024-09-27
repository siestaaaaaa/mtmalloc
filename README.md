English | [中文](README-CN.md)

# mtmalloc : multi-threaded malloc

The mtmalloc is a high-performance, header-only C++ memory allocator, specifically designed for C++ multi-threaded applications.

It's extremely easy to setup. Just include the **mtmalloc.h** file in your code!

>Please make sure that your compiler supports C++17 or a newer standard and use compiler optimization level O2 or higher.

# Introduction

It is measured that after enabling O2 optimization on compilers such as GCC, Clang and MSVC, the performance of mtmalloc is significantly improved compared with the standard implementations, especially for multi-threaded applications.

This project draws on some of the design concepts from TCMalloc, employing a three-level cache structure aimed at reducing lock contention during memory allocation in a multi-threaded environment. Each level of the cache uses open hashing to manage memory chunks of different sizes and leverages object pooling techniques to accelerate metadata allocation. The project's memory management does not rely on the standard library but instead acquires memory directly through system calls. Memory released by the user is managed within the cache, thereby decreasing the frequency of system calls.

For more information, you can refer to the project's source code.

# API

>This project currently only provides C-Style APIs, and users can wrap them as needed.

## `malloc()`

```
void* malloc(size_t bytes);
```

`malloc()` allocates `bytes` of memory and returns a `void*` pointer to the start of that memory.

Specially, `malloc(0)` returns `nullptr`.

## `calloc()`

```
void* calloc(size_t num, size_t bytes);
```

The differrence between `calloc()` and `malloc()` is that `calloc()` will zero-initialize all bytes in allocated storage.

Specially, `calloc(num, 0)` or `calloc(0, bytes)` returns `nullptr`.

## `realloc()`

```
void* realloc(void *ptr, size_t new_bytes);
```

`realloc()` will deallocate the memory pointed by `ptr` and re-allocates `new_bytes` memory that does not perform any initialization.

Specially, `realloc(ptr, 0)` will deallocate the memory pointed by `ptr` and returns `nullptr`.

## `free()`

```
void free(void* ptr);
```

`free()` deallocates memory previously allocated by `malloc()`、`calloc()`、`realloc()`.

If `free()` is passed a null pointer, the function does nothing.

## Example

```cpp
#include "mtmalloc.h"

int main() {
    void* p = mtmalloc::malloc(16);
    mtmalloc::free(p);
}
```

# NOTE

mtmalloc does throw an `std::bad_alloc` exception when allocations fail, so please pay attention to catch exception.
