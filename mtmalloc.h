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

#elif defined(__linux__) || defined(linux)

#include <sys/mman.h>
#include <unistd.h>

#else
// TODO: support other platform
#endif

namespace mtmalloc {

namespace detail {

inline constexpr size_t TCMaxSize = 256 * 1024;

// for thread cache and central cache
inline constexpr size_t MaxBucketNum = 208;

// for page heap
inline constexpr size_t MaxPageNum = 129;

// assume page size >= 4KB
inline constexpr size_t PageShift = 12;

inline void* SysAlloc(size_t size) {
#if defined(_WIN32)
  void* ptr =
      VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (ptr == nullptr) {
    throw std::bad_alloc{};
  }
#elif defined(__linux__) || defined(linux)
  void* ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (ptr == MAP_FAILED) {
    throw std::bad_alloc{};
  }
#else
  // TODO: support other platform
#endif
  return ptr;
}

inline void SysFree(void* ptr, size_t size) {
#if defined(_WIN32)
  VirtualFree(ptr, size, MEM_RELEASE);
#elif defined(__linux__) || defined(linux)
  munmap(ptr, size);
#else
  // TODO: support other platform
#endif
}

// manage contiguous pages
struct Span {
  uintptr_t firstPageId_{};
  uintptr_t firstPageOffset_{};
  uintptr_t pageCount_{};

  void* freeList_{};
  size_t size_{};  // ensure mtmalloc::free no need to know size
  int useCount_{};

  bool isUsing_{};

  Span* next_{};
  Span* prev_{};
};

class Helper {
 public:
  static size_t bytesToSize(size_t bytes) {
    if (bytes <= 128) {
      return align(bytes, 8);
    } else if (bytes <= 1024) {
      return align(bytes, 16);
    } else if (bytes <= 8 * 1024) {
      return align(bytes, 128);
    } else if (bytes <= 64 * 1024) {
      return align(bytes, 1024);
    } else {
      return align(bytes, 8 * 1024);
    }
  }

  // for thread cache and central cache
  static size_t bytesToIndex(size_t bytes) {
    assert(bytes > 0 && bytes <= TCMaxSize);

    static int groups[4]{16, 56, 56, 56};
    if (bytes <= 128) {
      return indexInGroup(bytes, 3);
    } else if (bytes <= 1024) {
      return indexInGroup(bytes - 128, 4) + groups[0];
    } else if (bytes <= 8 * 1024) {
      return indexInGroup(bytes - 1024, 7) + groups[1] + groups[0];
    } else if (bytes <= 64 * 1024) {
      return indexInGroup(bytes - 8 * 1024, 10) + groups[2] + groups[1] +
             groups[0];
    } else if (bytes <= 256 * 1024) {
      return indexInGroup(bytes - 64 * 1024, 13) + groups[3] + groups[2] +
             groups[1] + groups[0];
    } else {
      return -1;
    }
  }

  static size_t sizeToBatch(size_t size) {
    assert(size > 0);

    auto res = TCMaxSize / size;
    res = std::max(res, size_t{2});
    res = std::min(res, size_t{512});
    return res;
  }

  static size_t sizeToPageNum(size_t size) {
    assert(size > 0);

    auto res = (sizeToBatch(size) * size) >> PageShift;
    res = std::max(res, size_t{1});
    return res;
  }

  // get the head of memblock to record the next memblock's address
  static void*& next(void* memblock) {
    assert(memblock != nullptr);
    return *static_cast<void**>(memblock);
  }

  static uintptr_t addressToPageId(void* ptr) {
    return reinterpret_cast<uintptr_t>(ptr) >> PageShift;
  }

  static uintptr_t addressToPageOffset(void* ptr) {
    return reinterpret_cast<uintptr_t>(ptr) -
           (addressToPageId(ptr) << PageShift);
  }

  static void* spanToBeginAddress(Span* span) {
    return reinterpret_cast<void*>((span->firstPageId_ << PageShift) +
                                   span->firstPageOffset_);
  }

  static void* spanToEndAddress(Span* span) {
    return static_cast<char*>(spanToBeginAddress(span)) +
           (span->pageCount_ << PageShift);
  }

 private:
  static size_t align(size_t bytes, size_t alignNum) {
    return (bytes + alignNum - 1) & ~(alignNum - 1);
  }

  static size_t indexInGroup(size_t bytes, size_t alignShift) {
    return ((bytes + (1 << alignShift) - 1) >> alignShift) - 1;
  }
};

template <typename T>
class Singleton {
 public:
  static T& getInstance() {
    // C++11 guarantee the thread-safety of static local variable's
    // initialization
    static T instance;
    return instance;
  }

  Singleton(const Singleton&) = delete;
  Singleton& operator=(const Singleton&) = delete;
  Singleton(Singleton&&) = delete;
  Singleton& operator=(Singleton&&) = delete;

 protected:
  Singleton() = default;
};

template <typename T>
class ObjectPool : public Singleton<ObjectPool<T>> {
  friend class Singleton<ObjectPool<T>>;
  ObjectPool() = default;

 public:
  T* new_() {
    T* res{};
    if (freeList_) {
      auto next = Helper::next(freeList_);
      res = static_cast<T*>(freeList_);
      freeList_ = next;
    } else {
      if (bytes_ < sizeof(T)) {
        bytes_ = 128 * 1024;
        mem_ = static_cast<char*>(SysAlloc(bytes_));
      }
      res = reinterpret_cast<T*>(mem_);
      auto stride = sizeof(T) < sizeof(void*) ? sizeof(void*) : sizeof(T);
      mem_ += stride;
      bytes_ -= stride;
    }
    new (res) T{};
    return res;
  }

  void delete_(T* ptr) {
    if (ptr == nullptr) {
      return;
    }
    ptr->~T();

    Helper::next(ptr) = freeList_;
    freeList_ = ptr;
  }

 private:
  char* mem_{};     // large continuous memory
  size_t bytes_{};

  void* freeList_{};
};

// PageMap contains a mapping from page to Span
// PageMap can be read without lock and written while holding PageHeap's lock
template <size_t Bits>
class PageMap : public Singleton<PageMap<Bits>> {
  friend class Singleton<PageMap<Bits>>;
  PageMap() = default;

 public:
  [[nodiscard]] Span* get(uintptr_t key) const {
    auto i1 = key >> (leafBits + nodeBits);
    auto i2 = (key >> leafBits) & (nodeLength - 1);
    auto i3 = key & (leafLength - 1);
    if ((key >> Bits) > 0 || root_[i1] == nullptr ||
        root_[i1]->leafs_[i2] == nullptr) {
      return nullptr;
    }
    return root_[i1]->leafs_[i2]->vals_[i3];
  }

  // pop span: must set every page
  // push span: set first and last page is ok
  void set(uintptr_t key, Span* val) {
    assert((key >> Bits) == 0);

    ensure(key, 1);
    auto i1 = key >> (leafBits + nodeBits);
    auto i2 = (key >> leafBits) & (nodeLength - 1);
    auto i3 = key & (leafLength - 1);
    root_[i1]->leafs_[i2]->vals_[i3] = val;
  }

  bool ensure(uintptr_t start, size_t n) {
    for (auto key = start; key < start + n;) {
      if ((key >> Bits) > 0) {
        return false;
      }
      auto i1 = key >> (leafBits + nodeBits);
      auto i2 = (key >> leafBits) & (nodeLength - 1);
      if (i1 >= rootLength) {
        return false;
      }
      if (root_[i1] == nullptr) {
        root_[i1] = ObjectPool<Node>::getInstance().new_();
      }
      if (root_[i1]->leafs_[i2] == nullptr) {
        root_[i1]->leafs_[i2] = ObjectPool<Leaf>::getInstance().new_();
      }
      key = ((key >> leafBits) + 1) << leafBits;
    }
    return true;
  }

 private:
  static constexpr int leafBits = (Bits + 2) / 3;  // round up
  static constexpr int leafLength = 1 << leafBits;
  static constexpr int nodeBits = (Bits + 2) / 3;  // round up
  static constexpr int nodeLength = 1 << nodeBits;
  static constexpr int rootBits = Bits - leafBits - nodeBits;
  static constexpr int rootLength = 1 << rootBits;

  struct Leaf {
    Span* vals_[leafLength]{};
  };

  struct Node {
    Leaf* leafs_[nodeLength]{};
  };

  Node* root_[rootLength]{};
};

// A double-list for Span without storing size
class SpanList {
 public:
  SpanList() {
    dummy_ = ObjectPool<Span>::getInstance().new_();
    dummy_->next_ = dummy_->prev_ = dummy_;
  }

  void push(Span* node) const {
    assert(node != nullptr);

    auto next = begin();
    node->prev_ = dummy_;
    node->next_ = next;
    dummy_->next_ = node;
    next->prev_ = node;
  }

  [[nodiscard]] Span* pop() const {
    assert(!empty());

    auto res = begin();
    erase(res);
    return res;
  }

  void erase(const Span* node) const {
    assert(node != nullptr);
    assert(node != dummy_);

    auto next = node->next_;
    auto prev = node->prev_;
    prev->next_ = next;
    next->prev_ = prev;
  }

  [[nodiscard]] Span* begin() const { return dummy_->next_; }

  [[nodiscard]] Span* end() const { return const_cast<Span*>(dummy_); }

  [[nodiscard]] bool empty() const { return begin() == end(); }

  SpanList(const SpanList&) = delete;
  SpanList& operator=(const SpanList&) = delete;
  SpanList(SpanList&&) = delete;
  SpanList& operator=(SpanList&&) = delete;

 private:
  Span* dummy_{};
};

class PageHeap : public Singleton<PageHeap> {
  friend class Singleton<PageHeap>;
  PageHeap() = default;

 public:
  // allocate Span
  Span* allocate(size_t pageNum) {
    assert(pageNum > 0);

    if (pageNum >= MaxPageNum) {
      auto ptr = SysAlloc(pageNum << PageShift);
      auto res = ObjectPool<Span>::getInstance().new_();
      res->firstPageId_ = Helper::addressToPageId(ptr);
      res->firstPageOffset_ = Helper::addressToPageOffset(ptr);
      res->pageCount_ = pageNum;
      for (size_t i = 0; i < res->pageCount_; i++) {
        PageMap<Bits>::getInstance().set(res->firstPageId_ + i, res);
      }
      return res;
    }

    if (!freeLists_[pageNum].empty()) {
      auto res = freeLists_[pageNum].pop();
      for (size_t i = 0; i < res->pageCount_; i++) {
        PageMap<Bits>::getInstance().set(res->firstPageId_ + i, res);
      }
      return res;
    }

    for (auto i = pageNum + 1; i < MaxPageNum; i++) {
      if (!freeLists_[i].empty()) {
        auto t = freeLists_[i].pop();

        auto res = ObjectPool<Span>::getInstance().new_();
        res->firstPageId_ = t->firstPageId_;
        res->firstPageOffset_ = t->firstPageOffset_;
        res->pageCount_ = pageNum;
        for (size_t j = 0; j < res->pageCount_; j++) {
          PageMap<Bits>::getInstance().set(res->firstPageId_ + j, res);
        }

        t->firstPageId_ += pageNum;
        t->pageCount_ -= pageNum;
        freeLists_[t->pageCount_].push(t);
        PageMap<Bits>::getInstance().set(t->firstPageId_, t);
        PageMap<Bits>::getInstance().set(t->firstPageId_ + t->pageCount_ - 1,
                                         t);
        return res;
      }
    }

    // new a big Span
    auto res = ObjectPool<Span>::getInstance().new_();
    auto ptr = SysAlloc((MaxPageNum - 1) << PageShift);
    res->firstPageId_ = Helper::addressToPageId(ptr);
    res->firstPageOffset_ = Helper::addressToPageOffset(ptr);
    res->pageCount_ = MaxPageNum - 1;
    freeLists_[res->pageCount_].push(res);
    return allocate(pageNum);
  }

  // deallocate Span
  void deallocate(Span* span) {
    assert(span != nullptr);

    if (span->pageCount_ >= MaxPageNum) {
      auto ptr = Helper::spanToBeginAddress(span);
      SysFree(ptr, span->pageCount_ << PageShift);
      ObjectPool<Span>::getInstance().delete_(span);
      return;
    }

    while (true) {
      auto prevPageId = span->firstPageId_ - 1;
      auto prevSpan = PageMap<Bits>::getInstance().get(prevPageId);
      if (prevSpan == nullptr) {
        break;
      }
      if (prevSpan->isUsing_) {
        break;
      }
      if (prevSpan->firstPageOffset_ != span->firstPageOffset_) {
        break;
      }
      if (prevSpan->pageCount_ + span->pageCount_ >= MaxPageNum) {
        break;
      }
      span->firstPageId_ = prevSpan->firstPageId_;
      span->pageCount_ += prevSpan->pageCount_;
      freeLists_[prevSpan->pageCount_].erase(prevSpan);
      ObjectPool<Span>::getInstance().delete_(prevSpan);
    }
    while (true) {
      auto nextPageId = span->firstPageId_ + span->pageCount_;
      auto nextSpan = PageMap<Bits>::getInstance().get(nextPageId);
      if (nextSpan == nullptr) {
        break;
      }
      if (nextSpan->isUsing_) {
        break;
      }
      if (nextSpan->firstPageOffset_ != span->firstPageOffset_) {
        break;
      }
      if (nextSpan->pageCount_ + span->pageCount_ >= MaxPageNum) {
        break;
      }
      span->pageCount_ += nextSpan->pageCount_;
      freeLists_[nextSpan->pageCount_].erase(nextSpan);
      ObjectPool<Span>::getInstance().delete_(nextSpan);
    }

    span->isUsing_ = false;
    freeLists_[span->pageCount_].push(span);
    PageMap<Bits>::getInstance().set(span->firstPageId_, span);
    PageMap<Bits>::getInstance().set(span->firstPageId_ + span->pageCount_ - 1,
                                     span);
  }

  Span* findSpan(void* ptr) const {
    auto pageId = Helper::addressToPageId(ptr);
    auto res = PageMap<Bits>::getInstance().get(pageId);
    assert(res != nullptr);
    return res;
  }

 private:
  SpanList freeLists_[MaxPageNum]; // index is pageNum
  static constexpr size_t Bits = (sizeof(void*) == 8 ? 48 : 32) - PageShift;

 public:
  mutable std::mutex mtx_;
};

class MutexSpanList final : public SpanList {
 public:
  using SpanList::SpanList;
  mutable std::mutex mtx_;
};

class CentralCache : public Singleton<CentralCache> {
  friend class Singleton<CentralCache>;
  CentralCache() = default;

 public:
  auto allocate(size_t index, size_t batch, size_t size) const {
    assert(index < MaxBucketNum);

    std::lock_guard<std::mutex> bucketLock{freeLists_[index].mtx_};

    auto span = freeLists_[index].begin();
    while (span != freeLists_[index].end()) {
      if (span->freeList_) {
        break;
      }
      span = span->next_;
    }
    if (span == freeLists_[index].end()) {
      span = fetchFromPageCache(index, size);
    }

    auto first = span->freeList_, last = first;
    size_t cnt = 1;
    while (cnt < batch && Helper::next(last)) {
      last = Helper::next(last);
      ++cnt;
    }
    span->freeList_ = Helper::next(last);
    Helper::next(last) = nullptr;

    span->useCount_ += cnt;
    return std::make_tuple(first, last, cnt);
  }

  void deallocate(void* ptr, size_t size) const {
    auto index = Helper::bytesToIndex(size);
    assert(index < MaxBucketNum);

    std::unique_lock<std::mutex> bucketLock{freeLists_[index].mtx_};
    while (ptr) {
      auto next = Helper::next(ptr);

      auto span = PageHeap::getInstance().findSpan(ptr);
      Helper::next(ptr) = span->freeList_;
      span->freeList_ = ptr;

      if (--span->useCount_ <= 0) {
        freeLists_[index].erase(span);
        span->freeList_ = nullptr;
        span->next_ = nullptr;
        span->prev_ = nullptr;

        bucketLock.unlock();
        {
          std::lock_guard<std::mutex> pageHeapLock{
              PageHeap::getInstance().mtx_};
          PageHeap::getInstance().deallocate(span);
        }
        bucketLock.lock();
      }

      ptr = next;
    }
  }

 private:
  Span* fetchFromPageCache(size_t index, size_t size) const {
    freeLists_[index].mtx_.unlock();

    assert(index < MaxBucketNum);

    auto pageNum = Helper::sizeToPageNum(size);
    std::unique_lock<std::mutex> pageHeapLock{PageHeap::getInstance().mtx_};
    auto span = PageHeap::getInstance().allocate(pageNum);
    pageHeapLock.unlock();

    assert(span != nullptr);
    auto begin = static_cast<char*>(Helper::spanToBeginAddress(span));
    auto end = static_cast<char*>(Helper::spanToEndAddress(span));
    assert(end - begin >= size);
    span->isUsing_ = true;
    span->size_ = size;

    span->freeList_ = begin;
    auto tail = begin;
    auto cur = begin;
    while (cur + size <= end) {
      tail = cur;
      cur += size;
      Helper::next(tail) = cur;
    }
    Helper::next(tail) =
        nullptr;  // lost [cur, end) but ok coz it's managed by span

    freeLists_[index].mtx_.lock();
    freeLists_[index].push(span);
    return span;
  }

 private:
  MutexSpanList freeLists_[MaxBucketNum]; // index is size
};

// A special double-list for memblock
class TCList {
 public:
  void push(void* node) {
    assert(node != nullptr);

    Helper::next(node) = dummy_;
    dummy_ = node;
    ++length_;
  }

  void push(void* first, void* last, size_t n) {
    assert(first != nullptr);
    assert(last != nullptr);

    Helper::next(last) = dummy_;
    dummy_ = first;
    length_ += n;
  }

  void* pop(size_t n = 1) {
    assert(!empty());
    if (n > length_) {
      n = length_;
    }

    auto first = dummy_, last = dummy_;
    for (size_t i = 0; i < n - 1; ++i) {
      last = Helper::next(last);
    }
    dummy_ = Helper::next(last);
    Helper::next(last) = nullptr;
    length_ -= n;
    return first;
  }

  [[nodiscard]] bool empty() const { return length_ == 0; }

  [[nodiscard]] size_t length() const { return length_; }

  [[nodiscard]] size_t maxLength() const { return maxLength_; }

  void increaseMaxLength() { ++maxLength_; }

 private:
  void* dummy_{};
  size_t length_{};

  size_t maxLength_{1}; // for slow-start
};

class ThreadCache {
 public:
  void* allocate(size_t bytes) {
    assert(bytes > 0 && bytes <= TCMaxSize);

    auto size = Helper::bytesToSize(bytes);
    auto index = Helper::bytesToIndex(bytes);
    if (!freeLists_[index].empty()) {
      return freeLists_[index].pop();
    }
    return fetchFromCentralCache(index, size);
  }

  void deallocate(void* ptr, size_t size) {
    assert(ptr != nullptr);
    assert(size > 0 && size <= TCMaxSize);

    auto index = Helper::bytesToIndex(size);
    freeLists_[index].push(ptr);

    if (freeLists_[index].length() >= freeLists_[index].maxLength()) {
      auto first = freeLists_[index].pop(freeLists_[index].maxLength());
      CentralCache::getInstance().deallocate(first, size);
    }
  }

 private:
  void* fetchFromCentralCache(size_t index, size_t size) {
    assert(index < MaxBucketNum);

    // slow-start
    auto batch = Helper::sizeToBatch(size);
    if (batch >= freeLists_[index].maxLength()) {
      batch = freeLists_[index].maxLength();
      freeLists_[index].increaseMaxLength();
    }

    auto [first, last, cnt] =
        CentralCache::getInstance().allocate(index, batch, size);
    if (cnt > 1) {
      freeLists_[index].push(Helper::next(first), last, cnt - 1);
    }
    return first;
  }

 private:
  TCList freeLists_[MaxBucketNum]; // index is size
};

inline std::mutex threadCachePoolMtx;

inline thread_local ThreadCache* tc{};

}  // namespace detail

/*
 * C-Style API
 */

inline void* malloc(size_t bytes) {
  if (bytes == 0) {
    return {};
  }

  using namespace detail;

  if (bytes > TCMaxSize) {
    // allocate from page heap
    auto size = Helper::bytesToSize(bytes);
    auto pageNum = Helper::sizeToPageNum(size);
    std::lock_guard<std::mutex> pageHeapLock{PageHeap::getInstance().mtx_};
    auto span = PageHeap::getInstance().allocate(pageNum);
    span->size_ = size;
    return Helper::spanToBeginAddress(span);
  }

  // allocate from thread cache
  if (tc == nullptr) {
    std::lock_guard<std::mutex> threadPoolLock{threadCachePoolMtx};
    tc = ObjectPool<ThreadCache>::getInstance().new_();
  }
  return tc->allocate(bytes);
}

inline void* calloc(size_t num, size_t bytes) {
  auto total = num * bytes;
  auto res = malloc(total);
  if (res) {
    memset(res, 0, total);
  }
  return res;
}

inline void free(void* ptr) {
  if (ptr == nullptr) {
    return;
  }

  using namespace detail;
  auto span = PageHeap::getInstance().findSpan(ptr);
  auto size = span->size_;

  if (size > TCMaxSize) {
    // deallocate to page heap
    std::lock_guard<std::mutex> pageHeapLock{PageHeap::getInstance().mtx_};
    PageHeap::getInstance().deallocate(span);
  } else {
    // deallocate to thread cache
    tc->deallocate(ptr, size);
  }
}

inline void* realloc(void* ptr, size_t new_bytes) {
  free(ptr);
  return malloc(new_bytes);
}

}  // namespace mtmalloc

#endif
