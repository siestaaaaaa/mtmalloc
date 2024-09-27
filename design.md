English | [中文](design-CN.md)

# overview

The mtmalloc is divided into three levels of cache: thread cache, central cache, and page heap.

Each level of cache uses hash buckets to manage memory and each bucket is a free list.

# thread cache

The thread cache is specific for every thread and can be accessed without acquiring any locks.

The hash buckets of thread cache is to map the size of the allocated memory to the free list.

The free list of thread cache runs a slow start algorithm.

# central cache

The central cache is a singleton for balanced scheduling.

Similar to thread cache, the hash buckets of central cache is to map the size of the allocated memory to the free list too.

The difference is that the central cache uses a structure called span to manage the memory of contiguous pages and every free list of central cache has a lock.

# page heap

The page heap is a singleton that fetches memory from the OS and handles the external memory fragmentation.

Unlike the previous two levels, the hash buckets of page heap is to map the number of memory pages requested to the free list.

Also unlike the previous two levels, the page heap is protected by a lock as a whole.

# allocation

When a thread requests memory, memory no more than `thread_cache_max_bytes` (default size is 256KB) is allocated directly from the thread cache without acquiring any locks. And memory requests in excess of `thread_cache_max_bytes` will be allocated directly from the page heap.

In detail, when the thread cache gets the number of bytes to be allocated, it will find the corresponding free list through the hash buckets. If there is memory in the free list, it will be allocated directly, otherwise the memory will be obtained from the central cache, stored in the free list, and then allocated.
When the central cache allocates memory to the thread cache, it executes a slow-start algorithm to prevent wasting too much memory at once.

Similar to thread cache, when the central cache learns from the thread cache the number of bytes to be allocated, it will find the corresponding free list through the hash buckets. The difference is that when accessing a free list in the central cache, the free list needs to be locked to prevent data race. Another difference is that the free list of the central cache stores spans, and the memory managed by spans will be split into an appropriate size before being allocated to the thread cache. Of course, when the corresponding free list is empty, the span will be obtained from the page heap, stored in the free list, and then allocated.

As for the page heap, it is responsible for requesting memory from the OS with the smallest page unit and managing the memory pages to the span structure. Every span is an element of free list while every free list is mapped from the number of pages by the hash buckets of page heap. A lock is required when accessing the page heap.

# deallocation

When a thread frees memory, if the memory is directly allocated from page heap, it will be alos deallocated to page heap. Otherwise, it will be deallocated to thread cache's corresponding free list. When there is too much memory in the free list, the excess memory will go back to the central cache and be dispatched by the central cache.

When a span under certain free list in the central cache is no longer active, it will be returned to the page heap for collection.

In order to solve the external memory fragmentation, spans that go back to the page heap will be merged into one big span and managed. Only spans that are too large to manage will be released to the OS, so that mtmalloc can holding memory in caches for later re-allocation as much as possible.