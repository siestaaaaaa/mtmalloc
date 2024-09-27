#pragma once

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <mutex>
#include <tuple>

#if defined(_WIN32)
#include <windows.h>
#undef max
#undef min
#elif defined(__linux__) || defined(linux)
#include <unistd.h>
#else
// to do: other platforms
#endif

//in this project, "bytes" means the number of bytes, "size" means the aligned bytes

namespace mtmalloc {

namespace mtmalloc_internal {

//designed
inline constexpr size_t thread_cache_max_bytes = 256 * 1024; //256KB
inline constexpr size_t N = 208; //num of the buckets of central_cache and thread_cache

//adjustable
inline constexpr size_t M = 129; //num of the buckets of page_heap
inline constexpr size_t page_shift = 13; //page_size: 8KB

//allocate memory from system
inline void* sys_alloc(size_t size) {
#if defined(_WIN32)
    void* ptr = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#elif defined(__linux__) || defined(linux)
    auto cur_brk = reinterpret_cast<intptr_t>(sbrk(0));
    auto new_brk = cur_brk + static_cast<intptr_t>(size);
    auto ptr = sbrk(new_brk - cur_brk);
    if(reinterpret_cast<intptr_t>(ptr) == -1) {
        ptr = nullptr;
    }
#else
    // to do: other platforms
#endif
    assert(ptr != nullptr);
    return ptr;
}

//free memory to system
inline void sys_free(void* ptr) {
#if defined(_WIN32)
    VirtualFree(ptr, 0, MEM_RELEASE);
#elif defined(__linux__) || defined(linux)
    auto cur_brk = reinterpret_cast<intptr_t>(sbrk(0));
    auto ptr_int = reinterpret_cast<intptr_t>(ptr);
    sbrk(ptr_int - cur_brk);
#else
    // to do: other platforms
#endif
}

class helper {
    static size_t align(size_t bytes, size_t align_num) {
        return (bytes + align_num - 1) & ~(align_num - 1);
    }

    static size_t index_in_group(size_t bytes, size_t align_shift) {
        return ((bytes + (1 << align_shift) - 1) >> align_shift) - 1;
    }

public:
    //align bytes to size
    static size_t get_size(size_t bytes) {
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

    //map the bytes to index
    static size_t get_index(size_t bytes) {
        static int group_size[4] = {16, 56, 56, 56};
        if (bytes <= 128) {
            return index_in_group(bytes, 3);
        } else if (bytes <= 1024) {
            return index_in_group(bytes - 128, 4) + group_size[0];
        } else if (bytes <= 8 * 1024) {
            return index_in_group(bytes - 1024, 7) + group_size[1] + group_size[0];
        } else if (bytes <= 64 * 1024) {
            return index_in_group(bytes - 8 * 1024, 10) + group_size[2] + group_size[1] +
                   group_size[0];
        } else if (bytes <= 256 * 1024) {
            return index_in_group(bytes - 64 * 1024, 13) + group_size[3] + group_size[2] +
                   group_size[1] + group_size[0];
        } else {
            assert(false);
            return -1;
        }
    }

    //the num of blocks to allocate
    static size_t get_nblock(size_t size) {
        assert(size > 0);

        auto res = thread_cache_max_bytes / size;
        res = std::max(res, size_t{2});
        res = std::min(res, size_t{512});
        return res;
    }

    //the num of pages to allocate
    static size_t get_npage(size_t size) {
        assert(size > 0);

        auto nblock = get_nblock(size);
        auto res = (nblock * size) >> page_shift;
        res = std::max(res, size_t{1});
        return res;
    }

    //get the head of memory block to memorize the addr of next block
    static void*& next(void* block) {
        assert(block != nullptr);
        return *static_cast<void**>(block);
    }
};

//object pool is to allocate memory of fixed length
template<typename T>
class object_pool {
    char* mem_{};           //large continuous memory
    size_t bytes_{};        //remain bytes
    void* freelist_{};      //manage free memory blocks

public:
    object_pool() = default;
    //not copyable and movable
    object_pool(const object_pool&) = delete;
    object_pool& operator=(const object_pool&) = delete;

    //new a object
    T* new_() {
        T* res{};
        if (freelist_) {
            //pop front to allocate memory
            auto next = helper::next(freelist_);
            res = static_cast<T*>(freelist_);
            freelist_ = next;
        } else {
            //allocate from a large continuous memory
            if (bytes_ < sizeof(T)) {
                bytes_ = 128 * 1024; //adjustable
                mem_ = static_cast<char*>(sys_alloc(bytes_));
            }
            assert(mem_ != nullptr);
            res = reinterpret_cast<T*>(mem_);
            auto stride = sizeof(T) < sizeof(void*) ? sizeof(void*) : sizeof(T);
            mem_ += stride;
            bytes_ -= stride;
        }
        new(res)T{};
        return res;
    }

    //delete a object
    void delete_(T* ptr) {
        if(ptr == nullptr) {
            return;
        }
        ptr->~T();
        //push front into freelist_ for re-allocation
        helper::next(ptr) = freelist_;
        freelist_ = ptr;
    }
};

//span is to manage the memory of contiguous pages
struct span {
    uintptr_t first_page{}; //<< page_shift to get the page's address
    size_t page_count_{};   //num of pages

    void* freelist_{};      //manage free memory blocks
    size_t size_{};         //size of memory blocks
    size_t use_count_{};    //num of memory blocks that are being used

    bool alive_{};          //whether the span is being used
    span* next_{};          //next span
    span* prev_{};          //prev span
};

inline object_pool<span> span_pool;

class span_list {
    span* head_{}; //dummy

public:
    span_list() {
        head_ = span_pool.new_();
        head_->next_ = head_->prev_ = head_;
    }
    //not copyable and movable
    span_list(const span_list&) = delete;
    span_list& operator=(const span_list&) = delete;

    void push(span* node) const {
        assert(node != nullptr);

        auto next = begin();
        node->prev_ = head_;
        node->next_ = next;
        head_->next_ = node;
        next->prev_ = node;
    }

    [[nodiscard]] span* pop() const {
        assert(!empty());

        auto res = begin();
        erase(res);
        return res;
    }

    void erase(const span* node) const {
        assert(node != nullptr);
        assert(node != head_);

        auto next = node->next_;
        auto prev = node->prev_;
        prev->next_ = next;
        next->prev_ = prev;
    }

    [[nodiscard]] span* begin() const {
        return head_->next_;
    }

    [[nodiscard]] span* end() const {
        return const_cast<span*>(head_);
    }

    [[nodiscard]] bool empty() const {
        return begin() == end();
    }
};

// page_map contains a mapping from page to span
// If span s occupies pages [p...q]
//      page_map[p] == s
//      page_map[q] == s
//      page_map[p+1...q-1] are undefined
//      page_map[p-1] and page_map[q+1] are defined:
//         nullptr if the corresponding page is not yet in the address space
//         otherwise it points to a span. This span may be free or allocated.
//         If free, it is in one of page_heap's freelist.
//
// page_map can be read without holding any locks
// and written while holding the page_heap's lock
template<size_t Bits>
class page_map {
    static constexpr int leaf_bits = (Bits + 2) / 3;        //round up
    static constexpr int leaf_length = 1 << leaf_bits;

    static constexpr int node_bits = (Bits + 2) / 3;        //round up
    static constexpr int node_length = 1 << node_bits;

    static constexpr int root_bits = Bits - leaf_bits - node_bits;
    static constexpr int root_length = 1 << root_bits;

    struct leaf {
        span* vals[leaf_length]{};
    };
    static inline object_pool<leaf> leaf_pool{};

    struct node {
        leaf* leafs[node_length]{};
    };
    static inline object_pool<node> node_pool{};

    node* root_[root_length]{};

public:
    page_map() = default;
    //not copyable and movable
    page_map(const page_map&) = delete;
    page_map& operator=(const page_map&) = delete;

    [[nodiscard]] span* get(uintptr_t key) const {
        auto i1 = key >> (leaf_bits + node_bits);
        auto i2 = (key >> leaf_bits) & (node_length - 1);
        auto i3 = key & (leaf_length - 1);
        if((key >> Bits) > 0 || root_[i1] == nullptr || root_[i1]->leafs[i2] == nullptr) {
            return nullptr;
        }
        return root_[i1]->leafs[i2]->vals[i3];
    }

    void set(uintptr_t key, span* val) {
        assert((key >> Bits) == 0);
        ensure(key, 1);
        auto i1 = key >> (leaf_bits + node_bits);
        auto i2 = (key >> leaf_bits) & (node_length - 1);
        auto i3 = key & (leaf_length - 1);
        root_[i1]->leafs[i2]->vals[i3] = val;
    }

    bool ensure(uintptr_t start, size_t n) {
        for(auto key = start; key < start + n;) {
            if((key >> Bits) > 0) {
                return false;
            }
            auto i1 = key >> (leaf_bits + node_bits);
            auto i2 = (key >> leaf_bits) & (node_length - 1);
            if (i1 >= root_length) {
                return false;
            }
            if (root_[i1] == nullptr) {
                root_[i1] = node_pool.new_();
            }
            if (root_[i1]->leafs[i2] == nullptr) {
                root_[i1]->leafs[i2] = leaf_pool.new_();
            }
            key = ((key >> leaf_bits) + 1) << leaf_bits;
        }
        return true;
    }
};

//page_heap is to allocate and deallocate span
class page_heap {
    span_list freelists_[M]; //map page_count to span_list

    static constexpr size_t Bits = (sizeof(void*) == 8 ? 48 : 32) - page_shift;
    page_map<Bits> page_to_span_{};

    page_heap() = default;

public:
    mutable std::mutex mtx_; //mutex for page_heap

    page_heap(const page_heap&) = delete;
    page_heap& operator=(const page_heap&) = delete;

    static page_heap& get_instance() {
        //C++11 guarantee the thread-safety of static local variable's initialization
        static page_heap instance;
        return instance;
    }

    span* allocate(size_t npage) {
        assert(npage > 0);

        if(npage >= M) {
            auto ptr = sys_alloc(npage << page_shift);
            auto res = span_pool.new_();
            res->first_page = reinterpret_cast<uintptr_t>(ptr) >> page_shift;
            res->page_count_ = npage;
            page_to_span_.set(res->first_page, res);
            page_to_span_.set(res->first_page + res->page_count_ - 1, res);
            return res;
        }

        if(!freelists_[npage].empty()) {
            auto res = freelists_[npage].pop();
            page_to_span_.set(res->first_page, res);
            page_to_span_.set(res->first_page + res->page_count_ - 1, res);
            return res;
        }

        for(auto i = npage + 1; i < M; i++) {
            if(!freelists_[i].empty()) {
                auto t = freelists_[i].pop();
                auto res = span_pool.new_();
                res->first_page = t->first_page;
                t->first_page += npage;
                res->page_count_ = npage;
                t->page_count_ -= npage;
                freelists_[t->page_count_].push(t);
                page_to_span_.set(t->first_page, t);
                page_to_span_.set(t->first_page + t->page_count_ - 1, t);
                page_to_span_.set(res->first_page, res);
                page_to_span_.set(res->first_page + res->page_count_ - 1, res);
                return res;
            }
        }

        //new a span with max num of pages and recurse to allocate the span of npage
        auto res = span_pool.new_();
        auto ptr = sys_alloc((M - 1) << page_shift);
        res->first_page = reinterpret_cast<uintptr_t>(ptr) >> page_shift;
        res->page_count_ = M - 1;
        freelists_[res->page_count_].push(res);
        return allocate(npage);
    }

    void deallocate(span* _span) {
        assert(_span != nullptr);

        if(_span->page_count_ >= M) {
            auto ptr = reinterpret_cast<void*>(_span->first_page << page_shift);
            sys_free(ptr);
            span_pool.delete_(_span);
            return;
        }

        //merge forward
        while(true) {
            auto prev_page = _span->first_page - 1; //the last page of prev_span
            auto prev_span = page_to_span_.get(prev_page);
            if(prev_span == nullptr) {
                break;
            }

            if(prev_span->alive_) {
                break;
            }
            if(prev_span->page_count_ + _span->page_count_ >= M) {
                break;
            }
            _span->first_page = prev_span->first_page; //the first page of prev_span
            _span->page_count_ += prev_span->page_count_;
            freelists_[prev_span->page_count_].erase(prev_span);
            span_pool.delete_(prev_span);
        }
        //merge backwards
        while(true) {
            auto next_page = _span->first_page + _span->page_count_; //the first page of next_span
            auto next_span = page_to_span_.get(next_page);
            if(next_span == nullptr) {
                break;
            }

            if(next_span->alive_) {
                break;
            }
            if(next_span->page_count_ + _span->page_count_ >= M) {
                break;
            }
            _span->page_count_ += next_span->page_count_;
            freelists_[next_span->page_count_].erase(next_span);
            span_pool.delete_(next_span);
        }
        freelists_[_span->page_count_].push(_span);
        _span->alive_ = false;
        page_to_span_.set(_span->first_page, _span);
        page_to_span_.set(_span->first_page + _span->page_count_ - 1, _span);
    }

    span* find_span(void* ptr) const {
        auto page = reinterpret_cast<uintptr_t>(ptr) >> page_shift;
        auto res = page_to_span_.get(page);
        assert(res != nullptr);
        return res;
    }
};

class mutex_span_list final : public span_list {
public:
    using span_list::span_list;
    mutable std::mutex mtx_; //mutex for every bucket
};

class central_cache {
    mutex_span_list freelists_[N]; //map size to mutex_span_list

    central_cache() = default;

    span* fetch_from_page_cache(size_t index, size_t size) const {
        assert(index < N);
        freelists_[index].mtx_.unlock();

        auto npage = helper::get_npage(size);
        page_heap::get_instance().mtx_.lock();
        auto _span = page_heap::get_instance().allocate(npage);
        assert(_span != nullptr);
        auto begin = reinterpret_cast<char*>(_span->first_page << page_shift);
        auto end = begin + (npage << page_shift);
        _span->alive_ = true;
        _span->size_ = size;
        page_heap::get_instance().mtx_.unlock();

        //push back
        _span->freelist_ = begin; //head
        auto tail = begin;   //tail
        begin += size;            //cur
        while(begin != end) {
            helper::next(tail) = begin;
            tail = begin;
            begin += size;
        }
        helper::next(tail) = nullptr;

        freelists_[index].mtx_.lock();
        freelists_[index].push(_span);
        return _span;
    }

public:
    central_cache(const central_cache&) = delete;
    central_cache& operator=(const central_cache&) = delete;

    static central_cache& get_instance() {
        //C++11 guarantee the thread-safety of static local variable's initialization
        static central_cache instance;
        return instance;
    }

    auto allocate(size_t index, size_t nblock, size_t size) const {
        assert(index < N);

        freelists_[index].mtx_.lock();
        auto _span = freelists_[index].begin();
        while(_span != freelists_[index].end()) {
            if(_span->freelist_) {
                break;
            }
            _span = _span->next_;
        }
        if(_span->freelist_ == nullptr) {
            _span = fetch_from_page_cache(index, size);
        }

        auto first = _span->freelist_, last = first;
        size_t cnt = 1;
        while(cnt < nblock && helper::next(last)) {
            last = helper::next(last);
            ++cnt;
        }
        _span->freelist_ = helper::next(last);
        helper::next(last) = nullptr;

        _span->use_count_ += cnt;
        freelists_[index].mtx_.unlock();
        return std::make_tuple(first, last, cnt);
    }

    void deallocate(void* ptr, size_t size) const {
        auto index = helper::get_index(size);
        assert(index < N);
        freelists_[index].mtx_.lock();
        while (ptr) {
            auto next = helper::next(ptr);
            auto _span = page_heap::get_instance().find_span(ptr);
            helper::next(ptr) = _span->freelist_;
            _span->freelist_ = ptr;
            if(--_span->use_count_ == 0) {
                freelists_[index].erase(_span);
                _span->freelist_ = nullptr;
                _span->next_ = nullptr;
                _span->prev_ = nullptr;

                freelists_[index].mtx_.unlock();
                page_heap::get_instance().mtx_.lock();
                page_heap::get_instance().deallocate(_span);
                page_heap::get_instance().mtx_.unlock();
                freelists_[index].mtx_.lock();
            }
            ptr = next;
        }
        freelists_[index].mtx_.unlock();
    }
};

class thread_cache {
    struct mem_list {
        void* head_{};
        size_t length_{};
        size_t max_length_{1}; //for slow start

        void push(void* block) {
            assert(block != nullptr);

            helper::next(block) = head_;
            head_ = block;
            ++length_;
        }

        void push(void* first, void* last, size_t n) {
            assert(first != nullptr);
            assert(last != nullptr);

            helper::next(last) = head_;
            head_ = first;
            length_ += n;
        }

        void* pop() {
            assert(!empty());

            auto res = head_;
            head_ = helper::next(head_);
            --length_;
            return res;
        }

        auto pop(size_t n) {
            assert(!empty());

            if(n > length_) {
                n = length_;
            }

            auto first = head_, last = head_;
            for(size_t i = 0; i < n - 1; ++i) {
                last = helper::next(last);
            }
            head_ = helper::next(last);
            helper::next(last) = nullptr;
            length_ -= n;
            return std::make_tuple(first, last, n);
        }

        [[nodiscard]] bool empty() const {
            return length_ == 0;
        }
    };

    mem_list freelists_[N]; //map size to mem_list

    void* fetch_from_central_cache(size_t index, size_t size) {
        assert(index < N);

        //slow start algorithm
        auto nblock = helper::get_nblock(size);
        if(nblock >= freelists_[index].max_length_) {
            nblock = freelists_[index].max_length_;
            freelists_->max_length_++;
        }

        auto [first, last, cnt] = central_cache::get_instance().allocate(index, nblock, size);
        if(cnt > 1) {
            freelists_[index].push(helper::next(first), last, cnt - 1);
        }
        return first;
    }

public:
    void* allocate(size_t bytes) {
        assert(bytes > 0 && bytes <= thread_cache_max_bytes);

        auto size = helper::get_size(bytes);
        auto index = helper::get_index(bytes);
        if(!freelists_[index].empty()) {
            return freelists_[index].pop();
        }
        return fetch_from_central_cache(index, size);
    }

    void deallocate(void* ptr, size_t size) {
        assert(ptr != nullptr);
        assert(size > 0 && size <= thread_cache_max_bytes);

        auto index = helper::get_index(size);
        freelists_[index].push(ptr);

        if(freelists_[index].length_ >= freelists_[index].max_length_) {
            auto [first, _1, _2] = freelists_[index].pop(freelists_[index].max_length_);
            central_cache::get_instance().deallocate(first, size);
        }
    }
};

inline thread_local thread_cache* tc{};

inline object_pool<thread_cache> thread_cache_pool;

inline std::mutex thread_cache_pool_mtx;

}

inline void* malloc(size_t bytes) {
    if(bytes == 0) {
        return {};
    }

    using namespace mtmalloc_internal;

    if(bytes > thread_cache_max_bytes) {
        auto size = helper::get_size(bytes);
        auto npage = helper::get_npage(size);
        std::lock_guard<std::mutex> lock{page_heap::get_instance().mtx_};
        auto _span = page_heap::get_instance().allocate(npage);
        _span->size_ = size;
        return reinterpret_cast<void*>(_span->first_page << page_shift);
    }

    if(tc == nullptr) {
        std::lock_guard<std::mutex> lock{thread_cache_pool_mtx};
        tc = thread_cache_pool.new_();
    }

    return tc->allocate(bytes);
}

inline void* calloc(size_t num, size_t bytes) {
    auto total = num * bytes;
    auto res = malloc(total);
    if(res) {
        memset(res, 0, total);
    }
    return res;
}

inline void free(void* ptr) {
    if(ptr == nullptr) {
        return;
    }

    using namespace mtmalloc_internal;

    auto _span = page_heap::get_instance().find_span(ptr);
    auto size = _span->size_;
    if(size > thread_cache_max_bytes) {
        std::lock_guard<std::mutex> lock{page_heap::get_instance().mtx_};
        page_heap::get_instance().deallocate(_span);
    } else {
        assert(tc != nullptr);
        tc->deallocate(ptr, size);
    }
}

inline void* realloc(void *ptr, size_t new_bytes) {
    free(ptr);
    return malloc(new_bytes);
}

}