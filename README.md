English | [中文](README-CN.md)

# mtmalloc : multi-threaded malloc

The mtmalloc is a C++ header-only high performance memory allocator designed for multi-threaded application based on C++17.

It's extremely easy to setup. Just include the **mtmalloc.h** file in your code!

>Please make sure that your compiler supports C++17 or greater and use O2 or higher compiler optimization levels.

# Introduction

It is measured that after enabling O2 optimization on compilers such as gcc, clang and msvc, the performance of mtmalloc is significantly improved compared with the standard implementations, especially for multi-threaded applications.

This project refers to some ideas of tcmalloc that holding memory in caches to speed up access of commonly-used objects. These cache implementations allows mtmalloc to avoid requiring locks for most memory allocations and deallocations. Holding such caches even after deallocation also helps avoid costly system calls if such memory is later re-allocated.

More information can be referred in [mtmalloc design doc](design.md) and the source code.

# API

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

>to be continued...

# Example

```cpp
#include "mtmalloc.h"

int main() {
    auto p = mtmalloc::malloc(16);
    mtmalloc::free(p);
}
```

# NOTE

Unlike in the standard implementations, mtmalloc does not throw an exception or return a null pointer when allocations fail, but instead crashes directly.
