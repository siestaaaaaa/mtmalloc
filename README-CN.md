[English](README.md) | 中文

# mtmalloc : multi-threaded malloc

mtmalloc 是一个基于 C++17 实现的 C++ header-only 高性能内存分配器，专为多线程应用设计。

它非常容易使用，只需要在你的代码中包含 **mtmalloc.h** 文件即可！

>请确保您的编译器支持 C++17 或更新的标准，并使用 O2 或更高的编译器优化等级。

# 基本介绍

经测，在 GCC、Clang 和 MSVC 等编译器上启用 O2 优化后，mtmalloc 的性能相比标准库解决方案有显著提升，尤其是对于多线程应用程序。

本项目参考了 TCMalloc 的部分设计思路，利用缓存加快大部分场景下的内存分配速度。这些缓存的实现，使得 mtmalloc 在大多数内存分配中无需加锁。内存释放后，并不会直接归还给操作系统，而是保留在缓存中，供下一次的分配，从而避免每次分配都通过系统调用向操作系统申请内存。

更多信息可以参考 [mtmalloc design doc](design-CN.md) 和项目源码。

# API

## `malloc()`

```
void* malloc(size_t bytes);
```

`malloc()` 分配大小为 `bytes` 字节的内存，并返回一个 `void*` 类型的指向内存起始地址的指针。

特殊地，`malloc(0)` 将返回 `nullptr`。

## `calloc()`

```
void* calloc(size_t num, size_t bytes);
```

`calloc()` 和 `malloc()` 的不同在于，`calloc()` 会以零初始化分配的空间。

特殊地，`calloc(num, 0)` 或者 `calloc(0, bytes)` 将返回 `nullptr`。

## `realloc()`

```
void* realloc(void *ptr, size_t new_bytes);
```

`realloc()` 会释放 `ptr` 指向的内存，然后重新分配大小为 `new_bytes` 字节的内存（不会初始化）。

特殊地，`realloc(ptr, 0)` 会释放 `ptr` 指向的内存，并返回 `nullptr`。

## `free()`

```
void free(void* ptr);
```

`free()` 会释放 `malloc()` 或 `calloc()` 或 `realloc()` 分配的内存。

如果传递的是空指针，`free()` 什么事也不做。

>未完待续……

# 使用示例

```cpp
#include "mtmalloc.h"

int main() {
    auto p = mtmalloc::malloc(16);
    mtmalloc::free(p);
}
```

# 注意事项

当分配失败时，mtmalloc 会抛出异常，请注意捕获异常。
