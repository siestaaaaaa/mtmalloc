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
#include <cstdint>
#include <cstring>
#include <forward_list>
#include <memory>
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

// Encapsule system's API
class System {
public:
    static void* allocate(size_t bytes) {
#if defined(_WIN32)
        void* ptr = VirtualAlloc(nullptr, bytes, MEM_COMMIT | MEM_RESERVE,
                                 PAGE_READWRITE);
        if (ptr == nullptr) [[unlikely]] {
            throw std::bad_alloc{};
        }
#else
        void* ptr = mmap(nullptr, bytes, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (ptr == MAP_FAILED) [[unlikely]] {
            throw std::bad_alloc{};
        }
#endif
        return ptr;
    }

    static void free(void* ptr, [[maybe_unused]] size_t bytes) {
#if defined(_WIN32)
        VirtualFree(ptr, 0, MEM_RELEASE);
#else
        munmap(ptr, bytes);
#endif
    }

    static const inline size_t kPageSize = [] {
#if defined(_WIN32)
        SYSTEM_INFO info;
        GetSystemInfo(&info);
        return static_cast<size_t>(info.dwPageSize);
#else
        return static_cast<size_t>(sysconf(_SC_PAGESIZE));
#endif
    }();
};

// Record next memblock's addr at obj head
// Require memblock's size >= sizeof(void*)
class MemBlock {
public:
    MemBlock(void* addr = nullptr) : addr_{addr} {}

    MemBlock getNext() {
        assert(addr_ != nullptr);
        return *static_cast<void**>(addr_);
    }

    void setNext(MemBlock next) {
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

// Single linked list of memblock
class MemList {
public:
    // Push n linked nodes at front
    void pushList(MemBlock head, MemBlock tail, size_t n) {
        assert(head.addr() != nullptr);
        assert(tail.addr() != nullptr);
        assert(n > 0);
        tail.setNext(head_);
        head_ = head;
        length_ += n;
    }

    // Pop n linked nodes from front
    std::pair<MemBlock, MemBlock> popList(size_t n) {
        assert(n > 0 && n <= length_);
        MemBlock head = head_, tail = head_;
        for (size_t i = 0; i < n - 1; ++i) {
            tail = tail.getNext();
        }
        head_ = tail.getNext();
        tail.setNext(nullptr);
        length_ -= n;
        return {head, tail};
    }

    // Push one linked nodes at front
    void pushNode(MemBlock node) { pushList(node, node, 1); }

    // Pop one linked nodes at front
    MemBlock popNode() { return popList(1).first; }

    bool empty() { return length_ == 0; }

    size_t length() { return length_; }

private:
    MemBlock head_;
    size_t length_ = 0;
};

// Contains a range of pages
class Span {
public:
    Span(size_t firstPageID, size_t firstPageOffset, size_t totalPageNum)
        : firstPageID_{firstPageID},
          firstPageOffset_{firstPageOffset},
          totalPageNum_{totalPageNum} {}

    void expandLeftBound(size_t deltaPageNum) {
        assert(firstPageID_ >= deltaPageNum);
        firstPageID_ -= deltaPageNum;
        totalPageNum_ += deltaPageNum;
    }

    void expandRightBound(size_t deltaPageNum) {
        totalPageNum_ += deltaPageNum;
    }

    void shrinkLeftBound(size_t deltaPageNum) {
        assert(totalPageNum_ >= deltaPageNum);
        totalPageNum_ -= deltaPageNum;
        firstPageID_ += deltaPageNum;
    }

    size_t getFirstPageID() { return firstPageID_; }

    size_t getFirstPageOffset() { return firstPageOffset_; }

    size_t getTotalPageNum() { return totalPageNum_; }

    // Get the begin address of paged memory
    char* getBeginAddr() {
        return reinterpret_cast<char*>(firstPageID_ * System::kPageSize +
                                       firstPageOffset_);
    }

    // Get the end address of paged memory
    char* getEndAddr() {
        return getBeginAddr() + totalPageNum_ * System::kPageSize;
    }

    // Slice paged memory in sliceSize for CentralCache and ThreadCache
    void slice(size_t sliceSize) {
        inCache_ = true;
        sliceSize_ = sliceSize;

        char* cur = getBeginAddr();
        char* end = getEndAddr();
        MemBlock tail;
        size_t n = 0;
        do {
            tail = cur;
            ++n;
            cur += sliceSize;
            tail.setNext(cur);
        } while (cur + sliceSize <= end);
        tail.setNext(nullptr);  // lost [cur, end) but ok coz it's in paging

        sliceList_.pushList(getBeginAddr(), tail, n);
    }

private:
    // Paging begin
    size_t firstPageID_;
    size_t firstPageOffset_;
    size_t totalPageNum_;
    // Paging end

public:
    bool inCache_ = false;
    MemList sliceList_;        // for CentralCache and ThreadCache
    size_t activeSlices_ = 0;  // Num of slices in ThreadCache
    size_t sliceSize_ = 0;     // Size of a slice
};

// CRTP-style singleton pattern
// How to use: inherit from it and declare friend class
template <typename T>
class Singleton {
public:
    static T& getInstance() { return instance; }

    Singleton(const Singleton&) = delete;
    Singleton& operator=(const Singleton&) = delete;

protected:
    Singleton() = default;

private:
    static T instance;
};

// An obj-pool for Span, RadixTreeV3::Node2, RadixTreeV3::Node3
// Should be accessed while holding PageHeap's lock
template <typename T>
class ObjectPool : public Singleton<ObjectPool<T>> {
private:
    friend class Singleton<ObjectPool<T>>;
    ObjectPool() = default;

public:
    void reserve(size_t n = 10) {
        if (n > memPool_.length()) [[likely]] {
            n -= memPool_.length();
            T* mem = static_cast<T*>(System::allocate(sizeof(T) * n));
            while (n--) {
                memPool_.pushNode(mem);
                mem++;
            }
        }
    }

    // Acquire mem from pool and construct obj with args
    template <typename... Args>
    T* acquire(Args&&... args) {
        if (memPool_.empty()) {
            reserve();
        }
        T* res = static_cast<T*>(memPool_.popNode().addr());
        new (res) T{std::forward<Args>(args)...};
        return res;
    }

    // Destruct obj and release mem to pool
    void release(T* ptr) {
        if (ptr == nullptr) [[unlikely]] {
            return;
        }
        ptr->~T();
        memPool_.pushNode(ptr);
    }

private:
    MemList memPool_;
};

// A path-compressed Trie for integer key (here is pageID)
class RadixTreeV3 : public Singleton<RadixTreeV3> {
private:
    friend class Singleton<RadixTreeV3>;
    RadixTreeV3() = default;

private:
    // Here assume VA_BITS = 64/32, PAGE_SIZE >= 4KB
    // PageID_BITS = kBits1 + kBits2 + kBits3
    static constexpr int kPageID_Bits = (sizeof(void*) == 8 ? 52 : 20);
    static constexpr int kBits3 = (kPageID_Bits + 2) / 3;
    static constexpr int kBits2 = (kPageID_Bits + 2) / 3;
    static constexpr int kBits1 = kPageID_Bits - kBits2 - kBits3;

    static constexpr int kMax3 = 1 << kBits3;
    static constexpr int kMax2 = 1 << kBits2;
    static constexpr int kMax1 = 1 << kBits1;

    struct Node3 {
        Span* child_[kMax3]{};
    };
    struct Node2 {
        Node3* child_[kMax2]{};
    };
    struct Node1 {
        Node2* child_[kMax1]{};
    };

    Node1* root_ = new Node1;

public:
    // Find the span the page lies in, return nullptr if not found
    Span* search(size_t pageID) {
        assert((pageID >> kPageID_Bits) == 0);

        size_t i1 = pageID >> (kBits2 + kBits3);
        size_t i2 = (pageID >> kBits3) & (kMax2 - 1);
        size_t i3 = pageID & (kMax3 - 1);
        if (root_->child_[i1] == nullptr ||
            root_->child_[i1]->child_[i2] == nullptr) [[unlikely]] {
            return nullptr;
        }
        return root_->child_[i1]->child_[i2]->child_[i3];
    }

    // Insert a mapping from page to span
    void insert(size_t pageID, Span* span) {
        assert((pageID >> kPageID_Bits) == 0);

        ensure(pageID, 1);
        size_t i1 = pageID >> (kBits2 + kBits3);
        size_t i2 = (pageID >> kBits3) & (kMax2 - 1);
        size_t i3 = pageID & (kMax3 - 1);
        root_->child_[i1]->child_[i2]->child_[i3] = span;
    }

private:
    void ensure(size_t startPageID, size_t n) {
        size_t curPageID = startPageID;
        size_t endPageID = startPageID + n;
        assert((endPageID >> kPageID_Bits) == 0);
        while (curPageID < endPageID) {
            size_t i1 = curPageID >> (kBits2 + kBits3);
            size_t i2 = (curPageID >> kBits3) & (kMax2 - 1);
            if (root_->child_[i1] == nullptr) {
                root_->child_[i1] = ObjectPool<Node2>::getInstance().acquire();
            }
            if (root_->child_[i1]->child_[i2] == nullptr) [[likely]] {
                root_->child_[i1]->child_[i2] =
                    ObjectPool<Node3>::getInstance().acquire();
            }
            curPageID = ((curPageID >> kBits3) + 1) << kBits3;
        }
    }
};

// Handle byte alignment, hash rules and batch request
class SizeHandler {
public:
    SizeHandler(size_t bytes) : size_{align(bytes)} {}

    // Get aligned size
    size_t getSize() { return size_; }

    // Get the hash index of ThreadCache and CentralCache (1~207)
    size_t getCacheIndex() {
        if (cacheIndex_ != -1) [[likely]] {
            return cacheIndex_;
        }
        for (const auto& config : cacheIndexConfigs_) {
            if (size_ > config.minSize) {
                size_t delta = size_ - config.minSize;
                cacheIndex_ = static_cast<int>(
                    config.startIndex +
                    ((delta + config.alignNum - 1) / config.alignNum - 1));
                return cacheIndex_;
            }
        }
        std::abort();
    }

    // Get the hash index of PageHeap (1~inf)
    // If size > kTCMaxSize, returned index == (size / System::kPageSize)
    size_t getHeapIndex() {
        if (heapIndex_ != -1) {
            return heapIndex_;
        }
        heapIndex_ =
            static_cast<int>((getBatchNum() * size_) / System::kPageSize);
        heapIndex_ = std::max(heapIndex_, 1);
        return heapIndex_;
    }

    // Get the batch num for acquiring CentralCache or PageHeap (1~512)
    // If size > kTCMaxSize, return 1
    size_t getBatchNum() {
        if (batchNum_ != -1) {
            return batchNum_;
        }
        batchNum_ = static_cast<int>(kTCMaxSize / size_);
        batchNum_ = std::max(batchNum_, 1);
        batchNum_ = std::min(batchNum_, 512);
        return batchNum_;
    }

private:
    // Round up bytes to the nearest multiple of alignNum
    static size_t align(size_t bytes) {
        for (const auto& config : alignConfigs_) {
            if (bytes > config.minSize) {
                return (bytes + config.alignNum - 1) & ~(config.alignNum - 1);
            }
        }
        std::abort();
    }

public:
    // TODO: Change to platform-driven configure

    /*Configure Segment Begin*/

    // Configure the max size of an alloc request that ThreadCache can handle
    static constexpr size_t kTCMaxSize = 256 * 1024;

    static constexpr size_t kMaxCacheIndex = 208;

    static constexpr size_t kMaxHeapIndex = 129;

    // Configure align rules
    struct AlignConfig {
        const size_t minSize;
        const size_t alignNum;
    };
    static constexpr AlignConfig alignConfigs_[] = {
        // If minSize > kTCMaxSize, alignNum must be System::kPageSize
        {64 * 1024, 8 * 1024},
        {8 * 1024, 1024},
        {1024, 128},
        {128, 16},
        {0, 8}};

    // Configure cache hash rules
    struct CacheIndexConfig {
        const size_t minSize;
        const size_t alignNum;
        const size_t startIndex;
    };
    static constexpr CacheIndexConfig cacheIndexConfigs_[] = {
        {64 * 1024, 8 * 1024, 184},
        {8 * 1024, 1024, 128},
        {1024, 128, 72},
        {128, 16, 16},
        {0, 8, 0}};

    /*Configure Segment End*/

private:
    size_t size_;
    int cacheIndex_ = -1;
    int heapIndex_ = -1;
    int batchNum_ = -1;
};

// Manage paged memory through span-based allocation
class PageHeap : public Singleton<PageHeap> {
private:
    friend class Singleton<PageHeap>;
    PageHeap() = default;

public:
    // Acquire a span which contains sufficient memory
    // Should be called while holding PageHeap's lock
    Span* acquire(SizeHandler& sizeHandler) {
        const size_t bucketIndex = sizeHandler.getHeapIndex();

        // Special case, only called by ::mtmalloc::malloc
        if (bucketIndex >= kMaxBuckets) {
            return OutOfIndexAcquire(bucketIndex);
        }

        if (!spanBuckets_[bucketIndex].empty()) {
            Span* retSpan = spanBuckets_[bucketIndex].front();
            spanBuckets_[bucketIndex].pop_front();
            recordPopSpan(retSpan);
            return retSpan;
        }

        // Find first fit
        const size_t pagesToAcquire = bucketIndex;
        for (size_t i = bucketIndex + 1; i < kMaxBuckets; i++) {
            if (!spanBuckets_[i].empty()) {
                Span* firstFitSpan = spanBuckets_[i].front();
                spanBuckets_[i].pop_front();

                // Move pages from firstFitSpan to retSpan
                Span* retSpan = ObjectPool<Span>::getInstance().acquire(
                    firstFitSpan->getFirstPageID(),
                    firstFitSpan->getFirstPageOffset(), pagesToAcquire);
                recordPopSpan(retSpan);

                firstFitSpan->shrinkLeftBound(pagesToAcquire);
                spanBuckets_[firstFitSpan->getTotalPageNum()].push_front(
                    firstFitSpan);
                recordPushSpan(firstFitSpan);

                return retSpan;
            }
        }

        // Not found fit span, new a maxSpan and recursion to acquire
        const size_t pagesToAlloc = kMaxBuckets - 1;
        void* addr = System::allocate(pagesToAlloc * System::kPageSize);
        Span* maxSpan = ObjectPool<Span>::getInstance().acquire(
            getPageID(addr), getPageOffset(addr), pagesToAlloc);
        spanBuckets_[pagesToAlloc].push_front(maxSpan);
        return acquire(sizeHandler);
    }

    // Release a span to PageHeap, automatically merge into larger span
    // Should be called while holding PageHeap's lock
    void release(Span* span) {
        const size_t bucketIndex = span->getTotalPageNum();

        // Special case, only called by ::mtmalloc::free
        if (bucketIndex >= kMaxBuckets) {
            return OutOfIndexRelease(span);
        }

        // Merge adjacent free span
        while (true) {
            size_t prevPageID = span->getFirstPageID() - 1;
            Span* prevSpan = RadixTreeV3::getInstance().search(prevPageID);
            if (prevSpan == nullptr) {
                break;
            }
            if (prevSpan->inCache_) {
                break;
            }
            if (prevSpan->getFirstPageOffset() != span->getFirstPageOffset()) {
                break;
            }
            if (prevSpan->getTotalPageNum() + span->getTotalPageNum() >=
                kMaxBuckets) {
                break;
            }
            span->expandLeftBound(prevSpan->getTotalPageNum());
            spanBuckets_[prevSpan->getTotalPageNum()].remove(prevSpan);
            ObjectPool<Span>::getInstance().release(prevSpan);
        }
        while (true) {
            size_t nextPageID =
                span->getFirstPageID() + span->getTotalPageNum();
            Span* nextSpan = RadixTreeV3::getInstance().search(nextPageID);
            if (nextSpan == nullptr) {
                break;
            }
            if (nextSpan->inCache_) {
                break;
            }
            if (nextSpan->getFirstPageOffset() != span->getFirstPageOffset()) {
                break;
            }
            if (nextSpan->getTotalPageNum() + span->getTotalPageNum() >=
                kMaxBuckets) {
                break;
            }
            span->expandRightBound(nextSpan->getTotalPageNum());
            spanBuckets_[nextSpan->getTotalPageNum()].remove(nextSpan);
            ObjectPool<Span>::getInstance().release(nextSpan);
        }

        // Release to bucket
        span->inCache_ = false;
        spanBuckets_[span->getTotalPageNum()].push_front(span);
        recordPushSpan(span);
    }

    // Find addr's owner span, abort if not found
    static Span* findSpan(void* addr) {  // TEST: data race and overhead if lock
        // addr -> pageID -> span
        size_t pageID = getPageID(addr);
        Span* res = RadixTreeV3::getInstance().search(pageID);
        if (res == nullptr) [[unlikely]] {
            std::abort();
        }
        return res;
    }

private:
    // Record every page of this span
    static void recordPopSpan(Span* span) {
        size_t firstPageID = span->getFirstPageID();
        size_t pages = span->getTotalPageNum();
        for (size_t i = 0; i < pages; i++) {
            RadixTreeV3::getInstance().insert(firstPageID + i, span);
        }
    }

    // Record first and last page of this span
    static void recordPushSpan(Span* span) {
        size_t firstPageID = span->getFirstPageID();
        size_t pages = span->getTotalPageNum();
        RadixTreeV3::getInstance().insert(firstPageID, span);
        RadixTreeV3::getInstance().insert(firstPageID + pages - 1, span);
    }

    static size_t getPageID(void* addr) {
        return reinterpret_cast<size_t>(addr) / System::kPageSize;
    }
    static size_t getPageOffset(void* addr) {
        return reinterpret_cast<size_t>(addr) -
               (getPageID(addr) * System::kPageSize);
    }

    static Span* OutOfIndexAcquire(const size_t bucketIndex) {
        void* addr = System::allocate(bucketIndex * System::kPageSize);
        Span* res = ObjectPool<Span>::getInstance().acquire(
            getPageID(addr), getPageOffset(addr), bucketIndex);
        RadixTreeV3::getInstance().insert(getPageID(addr), res);
        return res;
    }

    static void OutOfIndexRelease(Span* span) {
        char* ptr = span->getBeginAddr();
        System::free(ptr, span->getTotalPageNum() * System::kPageSize);
        ObjectPool<Span>::getInstance().release(span);
    }

private:
    static constexpr size_t kMaxBuckets = SizeHandler::kMaxHeapIndex;
    std::forward_list<Span*> spanBuckets_[kMaxBuckets];

public:
    mutable std::mutex mtx_;
};

// Schedule resources between PageHeap and ThreadCache
class CentralCache : public Singleton<CentralCache> {
private:
    friend class Singleton<CentralCache>;
    CentralCache() = default;

public:
    // Try to acquire a batch of memblocks specifyed by fixedBatchNum
    auto acquire(SizeHandler& sizeHandler, size_t fixedBatchNum) {
        size_t index = sizeHandler.getCacheIndex();
        auto&& bucket = spanBuckets_[index];

        // Find a span which has slices
        Span* span{};
        std::unique_lock<std::mutex> bucketLock{bucketLocks_[index]};
        auto it = std::find_if(bucket.begin(), bucket.end(), [](Span* curSpan) {
            return !curSpan->sliceList_.empty();
        });
        if (it != bucket.end()) {
            span = *it;
        } else {
            bucketLock.unlock();
            span = fetchFromPageHeap(sizeHandler);
            bucketLock.lock();
            bucket.push_front(span);
        }

        // pop n slices from this span
        auto&& sliceList = span->sliceList_;
        size_t n = std::min(sliceList.length(), fixedBatchNum);
        auto [head, tail] = sliceList.popList(n);

        // mark these slices active
        span->activeSlices_ += n;
        return std::make_tuple(head, tail, n);
    }

    // Release a list of memblocks to their spans
    void release(MemBlock head, SizeHandler& sizeHandler) {
        size_t index = sizeHandler.getCacheIndex();
        auto&& bucket = spanBuckets_[index];

        MemBlock cur = head;
        while (cur.addr()) {
            MemBlock next = cur.getNext();

            Span* span = PageHeap::findSpan(cur.addr());
            {
                std::unique_lock<std::mutex> bucketLock{bucketLocks_[index]};
                span->sliceList_.pushNode(cur);

                // A span have no active slices will be released to PageHeap
                if (--span->activeSlices_ == 0) {
                    bucket.remove(span);
                    bucketLock.unlock();
                    {
                        std::lock_guard<std::mutex> pageHeapLock{
                            PageHeap::getInstance().mtx_};
                        PageHeap::getInstance().release(span);
                    }
                }
            }

            cur = next;
        }
    }

private:
    // Fetch one span from PageHeap, slice and return
    Span* fetchFromPageHeap(SizeHandler& sizeHandler) {
        assert(sizeHandler.getHeapIndex() < SizeHandler::kMaxHeapIndex);

        Span* span{};
        {
            std::lock_guard<std::mutex> pageHeapLock{
                PageHeap::getInstance().mtx_};
            span = PageHeap::getInstance().acquire(sizeHandler);
        }
        assert(span != nullptr);
        span->slice(sizeHandler.getSize());
        return span;
    }

private:
    static constexpr size_t kMaxBuckets = SizeHandler::kMaxCacheIndex;
    std::forward_list<Span*> spanBuckets_[kMaxBuckets];

    // Each bucket’s lock must be acquired ​​before accessing the bucket
    // and its span
    std::mutex bucketLocks_[kMaxBuckets];
};

// A special memlist for ThreadCache
class TCList : public MemList {
public:
    // Get slow-start threshold
    size_t threshold() { return threshold_; }

    // Increase slow-start threshold
    void slowStart() { ++threshold_; }

private:
    size_t threshold_ = 3;  // must > 0
};

// Lock-free accessed through TLS
class ThreadCache {
public:
    // Acquire one memblock from ThreadCache
    MemBlock acquire(SizeHandler& sizeHandler) {
        size_t index = sizeHandler.getCacheIndex();
        auto&& bucket = memBuckets_[index];
        if (!bucket.empty()) {
            return bucket.popNode();
        }
        return fetchFromCentralCache(sizeHandler);
    }

    // Release one memblock to ThreadCache
    void release(MemBlock memblock, SizeHandler sizeHandler) {
        size_t index = sizeHandler.getCacheIndex();
        auto&& bucket = memBuckets_[index];
        bucket.pushNode(memblock);

        // If bucket length > threshold, release a list of memblock to
        // CentralCache
        if (bucket.length() > bucket.threshold()) {
            auto [head, tail] = bucket.popList(bucket.threshold());
            CentralCache::getInstance().release(head, sizeHandler);
        }
    }

private:
    // Fetch a batch of memblocks from CentralCache and return one
    MemBlock fetchFromCentralCache(SizeHandler& sizeHandler) {
        size_t index = sizeHandler.getCacheIndex();
        auto&& bucket = memBuckets_[index];

        // slow-start strategy
        size_t fixedBatchNum = sizeHandler.getBatchNum();
        if (fixedBatchNum >= bucket.threshold()) {
            fixedBatchNum = bucket.threshold();
            bucket.slowStart();
        }

        auto [head, tail, n] =
            CentralCache::getInstance().acquire(sizeHandler, fixedBatchNum);
        if (n > 1) {
            bucket.pushList(head.getNext(), tail, n - 1);
            head.setNext(nullptr);
        }
        return head;
    }

private:
    static constexpr size_t kMaxBuckets = SizeHandler::kMaxCacheIndex;
    TCList memBuckets_[kMaxBuckets];
};

inline thread_local ThreadCache tls_ThreadCache;

template <typename T>
inline T Singleton<T>::instance{};

}  // namespace detail

/*
 * C-Style API
 */

inline void* malloc(size_t bytes) {
    if (bytes == 0) [[unlikely]] {
        return nullptr;
    }

    using namespace detail;
    SizeHandler sizeHandler{bytes};
    if (bytes <= SizeHandler::kTCMaxSize) {
        return tls_ThreadCache.acquire(sizeHandler).addr();
    } else {
        Span* span{};
        {
            std::lock_guard<std::mutex> pageHeapLock{
                PageHeap::getInstance().mtx_};
            span = PageHeap::getInstance().acquire(sizeHandler);
        }
        assert(span != nullptr);
        span->sliceSize_ = sizeHandler.getSize();
        return span->getBeginAddr();
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
    Span* span = PageHeap::findSpan(ptr);
    size_t size = span->sliceSize_;
    if (size <= SizeHandler::kTCMaxSize) {
        tls_ThreadCache.release(ptr, size);
    } else {
        std::lock_guard<std::mutex> pageHeapLock{PageHeap::getInstance().mtx_};
        PageHeap::getInstance().release(span);
    }
}

inline void* realloc(void* ptr, size_t new_bytes) {
    free(ptr);
    return malloc(new_bytes);
}

}  // namespace mtmalloc

#endif
