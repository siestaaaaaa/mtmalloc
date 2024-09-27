//
//  mtmalloc.h
//
//  Copyright (c) 2024 siestaaaaaa. All rights reserved.
//  MIT License
//

#ifndef MTMALLOC_H
#define MTMALLOC_H

/*
 * Headers
 */

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <forward_list>
#include <mutex>

#if defined(_WIN32)

#include <windows.h>

#ifdef max
#pragma message("#undef marco max")
#undef max
#endif

#ifdef min
#pragma message("#undef marco min")
#undef min
#endif

#else

#include <sys/mman.h>
#include <unistd.h>

#endif

namespace mtmalloc {

namespace detail {

class System {
public:
    static void* allocate(size_t bytes) {
        size_t size = align(bytes, System::PAGE_SIZE);
#if defined(_WIN32)
        void* ptr = VirtualAlloc(nullptr, size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (ptr == nullptr) [[unlikely]] {
            throw std::bad_alloc{};
        }
#else
        void* ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (ptr == MAP_FAILED) [[unlikely]] {
            throw std::bad_alloc{};
        }
#endif
        return ptr;
    }

    static void free(void* ptr, [[maybe_unused]] size_t size) {
#if defined(_WIN32)
        VirtualFree(ptr, 0, MEM_RELEASE);
#else
        munmap(ptr, size);
#endif
    }

    static const constexpr size_t PAGE_SIZE = 4096;

    static size_t get_pageid(void* addr) {
        return reinterpret_cast<size_t>(addr) / System::PAGE_SIZE;
    }

    static size_t get_pageoff(void* addr) {
        return reinterpret_cast<size_t>(addr) % System::PAGE_SIZE;
    }

    static size_t align(size_t base, size_t align_num) {
        return (base + align_num - 1) & ~(align_num - 1);
    }

    static constexpr size_t MAX_SIZE = 256 * 1024;
    static constexpr size_t MAX_SLOTS = 4144;
    static constexpr size_t MAX_BUCKETS = MAX_SIZE / PAGE_SIZE + 1;

    static bool fast_path(size_t size) {
        return size <= MAX_SIZE;
    }
};

class SizeHandler {
public:
    SizeHandler(size_t bytes) {

        //////////////////////////////////////////
        /*             align rule               */
        /*  (0,1KB] - 16B - slots[0,63]         */
        /*  (1KB,256KB] - 64B - slots[64,4143]  */
        //////////////////////////////////////////

        assert(bytes > 0);
        if(bytes <= 1024) {
            size_ = System::align(bytes, 16);
        } else {
            size_ = System::align(bytes, 64);
        }
    }

    size_t get_size() { return size_; }

    size_t get_slot_idx() {
        assert(System::fast_path(size_));
        if(size_ <= 1024) {
            return (size_ - 1) / 16;
        } else {
            return (size_ - 1025) / 64 + 64;
        }
    }

    size_t get_bucket_idx() {
        assert(System::fast_path(size_));

        ////////////////////////////////////////////////
        /*                bucket idx                  */
        /* (size_-1)/System::PAGE_SIZE+1     @ [1,64] */
        /* (size_-1)/System::PAGE_SIZE+2     @ [2,65] */
        /* ((size_-1)/System::PAGE_SIZE+2)/2 @ [1,32] */
        ////////////////////////////////////////////////

        // DO NOT MODIFY THIS!!!
        return ((size_ - 1) / System::PAGE_SIZE + 2) / 2;
    }

private:
    size_t size_;
};

// Record next at the head of memblock
class MemBlock {
public:
    MemBlock(void* addr = nullptr) : addr_{addr} {}

    MemBlock get_next() {
        assert(addr_ != nullptr);
        return *static_cast<void**>(addr_);
    }

    void set_next(MemBlock next) {
        assert(addr_ != nullptr);
        *static_cast<void**>(addr_) = next.addr();
    }

    MemBlock& operator=(void* addr) {
        addr_ = addr;
        return *this;
    }

    void* addr() { return addr_; }

private:
    void* addr_;
};

class MemList {
public:
    void push_list(MemBlock head, MemBlock tail, size_t n) {
        assert(head.addr() != nullptr);
        assert(tail.addr() != nullptr);
        assert(n > 0);
        tail.set_next(head_);
        head_ = head;
        length_ += n;
    }

    auto pop_list(size_t n) -> std::pair<MemBlock, MemBlock> {
        assert(n > 0 && n <= length_);
        MemBlock head = head_, tail = head_;
        for (size_t i = 0; i < n - 1; ++i) {
            tail = tail.get_next();
        }
        head_ = tail.get_next();
        tail.set_next(nullptr);
        length_ -= n;
        return {head, tail};
    }

    void push_node(MemBlock node) {
        assert(node.addr() != nullptr);
        node.set_next(head_);
        head_ = node;
        ++length_;
    }

    auto pop_node() -> MemBlock {
        assert(!empty());
        MemBlock res = head_;
        head_ = head_.get_next();
        res.set_next(nullptr);
        --length_;
        return res;
    }

    bool empty() const { return length_ == 0; }

    size_t length() const { return length_; }

private:
    MemBlock head_;
    size_t length_ = 0;
};

// Contains enough paging memory for a specific size class
class Span {
public:
    Span(size_t first_pageid, size_t first_pageoff, size_t total_pages, size_t size)
        : first_pageid_{first_pageid},
          first_pageoff_{first_pageoff},
          total_pages_{total_pages},
          size_{size}
    {
        assert(size_ > 0);
    }

    void shrink_left_bound(size_t delta_pages) {
        assert(total_pages_ >= delta_pages);
        first_pageid_ += delta_pages;
        total_pages_ -= delta_pages;
    }

    char* get_begin_addr() const {
        return reinterpret_cast<char*>(first_pageid_ * System::PAGE_SIZE + first_pageoff_);
    }
    char* get_end_addr() const {
        return get_begin_addr() + total_pages_ * System::PAGE_SIZE;
    }

    size_t get_first_pageid() const { return first_pageid_; }
    size_t get_first_pageoff() const { return first_pageoff_; }
    size_t get_total_pages() const { return total_pages_; }
    size_t get_size() const { return size_; }

    // Called when span reused
    void reset_size(size_t size) {
        assert(size > 0);
        size_ = size;
    }

    // Called once by CentralCache
    void slice() {
        char* cur = get_begin_addr();
        char* end = get_end_addr();
        MemBlock tail;
        size_t n = 0;
        do {
            tail = cur;
            ++n;
            cur += size_;
            tail.set_next(cur);
        } while (cur + size_ <= end);
        tail.set_next(nullptr); // lost [cur, end) but ok coz it's in paging
        slice_list_.push_list(get_begin_addr(), tail, n);
    }

private:
    size_t first_pageid_;
    size_t first_pageoff_;
    size_t total_pages_;
    size_t size_;

public:
    MemList slice_list_;
    size_t active_slices_ = 0;
};

// Usage: inherit and declare friend
template <typename T>
class Singleton {
public:
    static T& get() { return instance; }

    Singleton(const Singleton&) = delete;
    Singleton& operator=(const Singleton&) = delete;

protected:
    Singleton() = default;

private:
    static T instance;
};

template <typename T>
inline T Singleton<T>::instance{};

// Should be accessed while holding PageHeap's lock
template <typename T>
class ObjectPool : public Singleton<ObjectPool<T>> {
private:
    friend class Singleton<ObjectPool<T>>;
    ObjectPool() = default;

public:
    void reserve(size_t n = 10) {
        if (n > memlist_.length()) [[likely]] {
            n -= memlist_.length();
            T* mem = static_cast<T*>(System::allocate(sizeof(T) * n));
            while (n--) {
                memlist_.push_node(mem);
                mem++;
            }
        }
    }

    // Acquire memory and construct object
    template <typename... Args>
    T* acquire(Args&&... args) {
        if (memlist_.empty()) {
            reserve();
        }
        T* res = static_cast<T*>(memlist_.pop_node().addr());
        new (res) T{std::forward<Args>(args)...};
        return res;
    }

    // Destruct object and release memory
    void release(T* ptr) {
        if (ptr == nullptr) [[unlikely]] {
            return;
        }
        ptr->~T();
        memlist_.push_node(ptr);
    }

private:
    MemList memlist_;
};

// Manage the mapping from pageid to span
class PageTable : public Singleton<PageTable> {
private:
    friend class Singleton<PageTable>;
    PageTable() = default;

    static constexpr size_t PAGEID_BITS = (sizeof(void*) == 8 ? 52 : 20);
    static constexpr size_t BITS3 = (PAGEID_BITS + 2) / 3;
    static constexpr size_t BITS2 = (PAGEID_BITS + 2) / 3;
    static constexpr size_t BITS1 = PAGEID_BITS - BITS2 - BITS3;

    static constexpr size_t MAX3 = 1 << BITS3;
    static constexpr size_t MAX2 = 1 << BITS2;
    static constexpr size_t MAX1 = 1 << BITS1;

    struct Node3 {
        Span* child_[MAX3]{};
    };
    struct Node2 {
        Node3* child_[MAX2]{};
    };
    struct Node1 {
        Node2* child_[MAX1]{};
    };

    // Only new the first level, the second and the third will be newed on demand
    Node1* root_ = new Node1;

public:
    Span* find(size_t pageid) {
        assert((pageid >> PAGEID_BITS) == 0);

        size_t i1 = pageid >> (BITS2 + BITS3);
        size_t i2 = (pageid >> BITS3) & (MAX2 - 1);
        size_t i3 = pageid & (MAX3 - 1);
        if (root_->child_[i1] == nullptr
            || root_->child_[i1]->child_[i2] == nullptr) [[unlikely]] {
            std::abort();
        }
        return root_->child_[i1]->child_[i2]->child_[i3];
    }

    void record_first_page(Span* span) {
        update(span->get_first_pageid(), span);
    }

    void record_every_page(Span* span) {
        for (size_t i = 0; i < span->get_total_pages(); ++i) {
            update(span->get_first_pageid() + i, span);
        }
    }

private:
    void update(size_t pageid, Span* span) {
        assert((pageid >> PAGEID_BITS) == 0);

        size_t i1 = pageid >> (BITS2 + BITS3);
        size_t i2 = (pageid >> BITS3) & (MAX2 - 1);
        size_t i3 = pageid & (MAX3 - 1);
        if (root_->child_[i1] == nullptr) {
            root_->child_[i1] = ObjectPool<Node2>::get().acquire();
        }
        if (root_->child_[i1]->child_[i2] == nullptr) {
            root_->child_[i1]->child_[i2] = ObjectPool<Node3>::get().acquire();
        }
        root_->child_[i1]->child_[i2]->child_[i3] = span;
    }
};

// Manage paged memory through span-based allocation
class PageHeap : public Singleton<PageHeap> {
private:
    friend class Singleton<PageHeap>;
    PageHeap() = default;

public:
    // Should be called while holding PageHeap's lock
    Span* acquire(SizeHandler& h) {
        const size_t bucket_idx = h.get_bucket_idx();
        const size_t size = h.get_size();

        if (!span_buckets_[bucket_idx].empty()) {
            Span* res = span_buckets_[bucket_idx].front();
            span_buckets_[bucket_idx].pop_front();
            res->reset_size(size);
            PageTable::get().record_every_page(res);
            return res;
        }

        // Find the first fit
        for (size_t i = bucket_idx + 1; i < System::MAX_BUCKETS; ++i) {
            if (!span_buckets_[i].empty()) {
                Span* first_fit = span_buckets_[i].front();
                span_buckets_[i].pop_front();
                Span* res = ObjectPool<Span>::get().acquire(
                    first_fit->get_first_pageid(),
                    first_fit->get_first_pageoff(),
                    bucket_idx,
                    size
                );
                first_fit->shrink_left_bound(bucket_idx);
                span_buckets_[first_fit->get_total_pages()].push_front(first_fit);
                PageTable::get().record_every_page(res);
                return res;
            }
        }

        // Not found fit span, new a biggest span and acquire again
        const size_t max_idx = System::MAX_BUCKETS - 1;
        void* addr = System::allocate(max_idx * System::PAGE_SIZE);
        const size_t pageid = System::get_pageid(addr);
        const size_t pageoff = System::get_pageoff(addr);
        Span* span = ObjectPool<Span>::get().acquire(
            pageid,
            pageoff,
            max_idx,
            size
        );
        span_buckets_[max_idx].push_front(span);
        return acquire(h);
    }

    // Should be called while holding PageHeap's lock
    void release(Span* span) {
        span_buckets_[span->get_total_pages()].push_front(span);
    }

    // Should be accessed while holding PageHeap's lock
    class SlowPath {
    public:
        static void* allocate(SizeHandler& h) {
            const size_t size = h.get_size();
            const size_t bucket_idx = h.get_bucket_idx();
            void* addr = System::allocate(size);
            Span* span = ObjectPool<Span>::get().acquire(
                System::get_pageid(addr),
                System::get_pageoff(addr),
                bucket_idx,
                size
            );
            PageTable::get().record_first_page(span);
            return addr;
        }

        static void free(Span* span) {
            System::free(span->get_begin_addr(), span->get_size());
            ObjectPool<Span>::get().release(span);
        }
    };

private:
    std::forward_list<Span*> span_buckets_[System::MAX_BUCKETS];

public:
    mutable std::mutex mtx_;
};

// Schedule resources between ThreadCache and PageHeap
class CentralCache : public Singleton<CentralCache> {
private:
    friend class Singleton<CentralCache>;
    CentralCache() = default;

public:
    // Acquire a list of memblocks from a span
    auto acquire(SizeHandler& h, size_t expected_num) {
        size_t slot_idx = h.get_slot_idx();
        auto&& slot = span_slots_[slot_idx];

        // Find a span which has slices
        Span* span{};
        std::unique_lock<std::mutex> slot_lock{slot_locks_[slot_idx]};
        auto it = std::find_if(slot.begin(), slot.end(), [](Span* _span) {
            return !_span->slice_list_.empty();
        });
        if (it != slot.end()) {
            span = *it;
        } else {
            slot_lock.unlock();
            {
                std::lock_guard<std::mutex> page_heap_lock{PageHeap::get().mtx_};
                span = PageHeap::get().acquire(h);
            }
            span->slice();
            slot_lock.lock();
            slot.push_front(span);
        }

        auto&& slice_list = span->slice_list_;
        size_t actual_num = std::min(slice_list.length(), expected_num);
        auto [head, tail] = slice_list.pop_list(actual_num);

        // mark these slices active
        span->active_slices_ += actual_num;
        return std::make_tuple(head, tail, actual_num);
    }

    // Release a list of memblocks to their spans
    void release(MemBlock head, size_t slot_idx) {
        auto&& slot = span_slots_[slot_idx];

        MemBlock cur = head;
        while (cur.addr()) {
            MemBlock next = cur.get_next();

            Span* span = PageTable::get().find(System::get_pageid(cur.addr()));
            {
                std::unique_lock<std::mutex> slot_lock{slot_locks_[slot_idx]};
                span->slice_list_.push_node(cur);

                // A span have no active slice should be released to PageHeap
                if (--span->active_slices_ == 0) {
                    slot.remove(span);
                    slot_lock.unlock();
                    {
                        std::lock_guard<std::mutex> page_heap_lock{PageHeap::get().mtx_};   
                        PageHeap::get().release(span);
                    }
                }
            }

            cur = next;
        }
    }

private:
    // Each slot should be accessed while holding its lock
    std::forward_list<Span*> span_slots_[System::MAX_SLOTS];
    std::mutex slot_locks_[System::MAX_SLOTS];
};

class DynMemList : public MemList {
public:
    size_t get_threshold() { return threshold_; }
    void inc_threshold() { ++threshold_; }
    void dec_threshold() { 
        if (threshold_ > MIN_THRESHOLD) {
            --threshold_;
        }
    }

private:
    static constexpr size_t MIN_THRESHOLD = 3;
    size_t threshold_ = MIN_THRESHOLD;
};

// Lock-free accessed through TLS
class ThreadCache {
public:
    MemBlock acquire(SizeHandler& h) {
        auto&& slot = mem_slots_[h.get_slot_idx()];
        if (!slot.empty()) {
            return slot.pop_node();
        } else {
            slot.inc_threshold();
            auto [head, tail, n] 
                = CentralCache::get().acquire(h, slot.get_threshold());
            if (n > 1) {
                slot.push_list(head.get_next(), tail, n - 1);
                head.set_next(nullptr);
            }
            return head;
        }
    }

    void release(void* ptr, size_t size) {
        SizeHandler h{size};
        size_t slot_idx = h.get_slot_idx();
        auto&& slot = mem_slots_[slot_idx];
        slot.push_node(ptr);

        // DO NOT MODIFY THIS!!!
        if (slot.length() > slot.get_threshold()) {    
            auto [head, tail] = slot.pop_list(slot.length());
            slot.dec_threshold();
            CentralCache::get().release(head, slot_idx);
        }
    }

private:
    DynMemList mem_slots_[System::MAX_SLOTS];
};

inline thread_local ThreadCache thread_cache;

}  // namespace detail

/*
 * C-Style API
 */

inline void* malloc(size_t bytes) {
    if (bytes == 0) [[unlikely]] {
        return nullptr;
    }

    using namespace detail;
    SizeHandler h{bytes};
    if (System::fast_path(h.get_size())) {
        return thread_cache.acquire(h).addr();
    } else {
        std::lock_guard<std::mutex> pageHeapLock{PageHeap::get().mtx_};
        return PageHeap::SlowPath::allocate(h);
    }
}

inline void* calloc(size_t num, size_t bytes) {
    size_t total = num * bytes;
    void* res = malloc(total);
    if (res) [[likely]] {
        memset(res, 0, total);
    }
    return res;
}

inline void free(void* ptr) {
    if (ptr == nullptr) [[unlikely]] {
        return;
    }

    using namespace detail;
    Span* span = PageTable::get().find(System::get_pageid(ptr));
    if (System::fast_path(span->get_size())) {
        thread_cache.release(ptr, span->get_size());
    } else {
        std::lock_guard<std::mutex> pageHeapLock{PageHeap::get().mtx_};
        PageHeap::SlowPath::free(span);
    }
}

inline void* realloc(void* ptr, size_t new_bytes) {
    free(ptr);
    return malloc(new_bytes);
}

}  // namespace mtmalloc

#endif
