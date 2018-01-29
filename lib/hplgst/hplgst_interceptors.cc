//=-- hplgst_interceptors.cc ------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of Heapologist.
// Stuart Byma, EPFL.
//
// Interceptors for Hplgst.
//
//===----------------------------------------------------------------------===//

#include "interception/interception.h"
#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_platform_interceptors.h"
#include "sanitizer_common/sanitizer_posix.h"
#include "sanitizer_common/sanitizer_tls_get_addr.h"
#include "hplgst.h"
#include "hplgst_flags.h"
#include "hplgst_allocator.h"
#include "hplgst_thread.h"
#include "hplgst_interceptors.h"
#include "hplgst_allocator.h"

#include <stddef.h>

using namespace __hplgst;

extern "C" {
int pthread_attr_init(void *attr);
int pthread_attr_destroy(void *attr);
//int pthread_attr_getdetachstate(void *attr, int *v);
int pthread_key_create(unsigned *key, void (*destructor)(void* v));
int pthread_setspecific(unsigned key, const void *v);
}

///// Malloc/free interceptors. /////

namespace std {
  struct nothrow_t;
}

#if !SANITIZER_MAC
INTERCEPTOR(void*, malloc, uptr size) {
  ENSURE_HPLGST_INITED();
  GET_STACK_TRACE_MALLOC;
  return hplgst_malloc(size, stack);
}

INTERCEPTOR(void, free, void *p) {
  ENSURE_HPLGST_INITED();
  hplgst_free(p);
}

INTERCEPTOR(void*, calloc, uptr nmemb, uptr size) {
  if (hplgst_init_is_running) {
    // Hack: dlsym calls calloc before REAL(calloc) is retrieved from dlsym.
    const uptr kCallocPoolSize = 1024;
    static uptr calloc_memory_for_dlsym[kCallocPoolSize];
    static uptr allocated;
    uptr size_in_words = ((nmemb * size) + kWordSize - 1) / kWordSize;
    void *mem = (void*)&calloc_memory_for_dlsym[allocated];
    allocated += size_in_words;
    CHECK(allocated < kCallocPoolSize);
    return mem;
  }
  if (CallocShouldReturnNullDueToOverflow(size, nmemb)) return nullptr;
  ENSURE_HPLGST_INITED();
  GET_STACK_TRACE_MALLOC;
  return hplgst_calloc(nmemb, size, stack);
}

INTERCEPTOR(void*, realloc, void *q, uptr size) {
  ENSURE_HPLGST_INITED();
  GET_STACK_TRACE_MALLOC;
  return hplgst_realloc(q, size, stack);
}

INTERCEPTOR(int, posix_memalign, void **memptr, uptr alignment, uptr size) {
  ENSURE_HPLGST_INITED();
  GET_STACK_TRACE_MALLOC;
  *memptr = hplgst_memalign(alignment, size, stack);
  // FIXME: Return ENOMEM if user requested more than max alloc size.
  return 0;
}

INTERCEPTOR(void*, valloc, uptr size) {
  ENSURE_HPLGST_INITED();
  GET_STACK_TRACE_MALLOC;
  return hplgst_valloc(size, stack);
}
#endif

#if SANITIZER_INTERCEPT_MEMALIGN
INTERCEPTOR(void*, memalign, uptr alignment, uptr size) {
  ENSURE_HPLGST_INITED();
  GET_STACK_TRACE_MALLOC;
  return hplgst_memalign(alignment, size, stack);
}
#define HPLGST_MAYBE_INTERCEPT_MEMALIGN INTERCEPT_FUNCTION(memalign)

INTERCEPTOR(void *, __libc_memalign, uptr alignment, uptr size) {
  ENSURE_HPLGST_INITED();
  GET_STACK_TRACE_MALLOC;
  void *res = hplgst_memalign(alignment, size, stack);
  DTLS_on_libc_memalign(res, size);
  return res;
}
#define HPLGST_MAYBE_INTERCEPT___LIBC_MEMALIGN INTERCEPT_FUNCTION(__libc_memalign)
#else
#define HPLGST_MAYBE_INTERCEPT_MEMALIGN
#define HPLGST_MAYBE_INTERCEPT___LIBC_MEMALIGN
#endif // SANITIZER_INTERCEPT_MEMALIGN

#if SANITIZER_INTERCEPT_ALIGNED_ALLOC
INTERCEPTOR(void*, aligned_alloc, uptr alignment, uptr size) {
  ENSURE_HPLGST_INITED();
  GET_STACK_TRACE_MALLOC;
  return hplgst_memalign(alignment, size, stack);
}
#define HPLGST_MAYBE_INTERCEPT_ALIGNED_ALLOC INTERCEPT_FUNCTION(aligned_alloc)
#else
#define HPLGST_MAYBE_INTERCEPT_ALIGNED_ALLOC
#endif

#if SANITIZER_INTERCEPT_MALLOC_USABLE_SIZE
INTERCEPTOR(uptr, malloc_usable_size, void *ptr) {
  ENSURE_HPLGST_INITED();
  return GetMallocUsableSize(ptr);
}
#define HPLGST_MAYBE_INTERCEPT_MALLOC_USABLE_SIZE \
        INTERCEPT_FUNCTION(malloc_usable_size)
#else
#define HPLGST_MAYBE_INTERCEPT_MALLOC_USABLE_SIZE
#endif

#if SANITIZER_INTERCEPT_MALLOPT_AND_MALLINFO
struct fake_mallinfo {
  int x[10];
};

INTERCEPTOR(struct fake_mallinfo, mallinfo, void) {
  struct fake_mallinfo res;
  internal_memset(&res, 0, sizeof(res));
  return res;
}
#define HPLGST_MAYBE_INTERCEPT_MALLINFO INTERCEPT_FUNCTION(mallinfo)

INTERCEPTOR(int, mallopt, int cmd, int value) {
  return -1;
}
#define HPLGST_MAYBE_INTERCEPT_MALLOPT INTERCEPT_FUNCTION(mallopt)
#else
#define HPLGST_MAYBE_INTERCEPT_MALLINFO
#define HPLGST_MAYBE_INTERCEPT_MALLOPT
#endif // SANITIZER_INTERCEPT_MALLOPT_AND_MALLINFO

#if SANITIZER_INTERCEPT_PVALLOC
INTERCEPTOR(void*, pvalloc, uptr size) {
  ENSURE_HPLGST_INITED();
  GET_STACK_TRACE_MALLOC;
  uptr PageSize = GetPageSizeCached();
  size = RoundUpTo(size, PageSize);
  if (size == 0) {
    // pvalloc(0) should allocate one page.
    size = PageSize;
  }
  return Allocate(stack, size, GetPageSizeCached(), kAlwaysClearMemory);
}
#define HPLGST_MAYBE_INTERCEPT_PVALLOC INTERCEPT_FUNCTION(pvalloc)
#else
#define HPLGST_MAYBE_INTERCEPT_PVALLOC
#endif // SANITIZER_INTERCEPT_PVALLOC

#if SANITIZER_INTERCEPT_CFREE
INTERCEPTOR(void, cfree, void *p) ALIAS(WRAPPER_NAME(free));
#define HPLGST_MAYBE_INTERCEPT_CFREE INTERCEPT_FUNCTION(cfree)
#else
#define HPLGST_MAYBE_INTERCEPT_CFREE
#endif // SANITIZER_INTERCEPT_CFREE

#if SANITIZER_INTERCEPT_MCHECK_MPROBE
INTERCEPTOR(int, mcheck, void (*abortfunc)(int mstatus)) {
  return 0;
}

INTERCEPTOR(int, mcheck_pedantic, void (*abortfunc)(int mstatus)) {
  return 0;
}

INTERCEPTOR(int, mprobe, void *ptr) {
  return 0;
}
#endif // SANITIZER_INTERCEPT_MCHECK_MPROBE

#define OPERATOR_NEW_BODY                              \
  ENSURE_HPLGST_INITED();                              \
  GET_STACK_TRACE_MALLOC;                              \
  return Allocate(stack, size, 1, kAlwaysClearMemory);

INTERCEPTOR_ATTRIBUTE
void *operator new(size_t size) { OPERATOR_NEW_BODY; }
INTERCEPTOR_ATTRIBUTE
void *operator new[](size_t size) { OPERATOR_NEW_BODY; }
INTERCEPTOR_ATTRIBUTE
void *operator new(size_t size, std::nothrow_t const&) { OPERATOR_NEW_BODY; }
INTERCEPTOR_ATTRIBUTE
void *operator new[](size_t size, std::nothrow_t const&) { OPERATOR_NEW_BODY; }

#define OPERATOR_DELETE_BODY \
  ENSURE_HPLGST_INITED();    \
  Deallocate(ptr);

INTERCEPTOR_ATTRIBUTE
void operator delete(void *ptr) NOEXCEPT { OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete[](void *ptr) NOEXCEPT { OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete(void *ptr, std::nothrow_t const&) { OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete[](void *ptr, std::nothrow_t const &) {
  OPERATOR_DELETE_BODY;
}


#define HPLGST_READ_RANGE(ctx, offset, size) \
  processRangeAccess(GET_CALLER_PC(), (uptr)offset, size, false)
#define HPLGST_WRITE_RANGE(ctx, offset, size) \
  processRangeAccess(GET_CALLER_PC(), (uptr)offset, size, true)

// Behavior of functions like "memcpy" or "strcpy" is undefined
// if memory intervals overlap. We report error in this case.
// Macro is used to avoid creation of new frames.
static inline bool RangesOverlap(const char *offset1, uptr length1,
                                 const char *offset2, uptr length2) {
  return !((offset1 + length1 <= offset2) || (offset2 + length2 <= offset1));
}
#define CHECK_RANGES_OVERLAP(name, _offset1, length1, _offset2, length2) do { \
  const char *offset1 = (const char*)_offset1; \
  const char *offset2 = (const char*)_offset2; \
  if (RangesOverlap(offset1, length1, offset2, length2)) { \
    GET_STACK_TRACE_FATAL; \
    Printf("Ranges overlap wtf\n"); \
  } \
} while (0)

#define HPLGST_MEMCPY_IMPL(ctx, to, from, size)                           \
  do {                                                                  \
    if (UNLIKELY(!hplgst_inited)) return internal_memcpy(to, from, size); \
    if (hplgst_init_is_running) {                                         \
      return REAL(memcpy)(to, from, size);                              \
    }                                                                   \
    ENSURE_HPLGST_INITED();                                               \
    if (getFlags()->replace_intrin) {                                      \
      if (to != from) {                                                 \
        CHECK_RANGES_OVERLAP("memcpy", to, size, from, size);           \
      }                                                                 \
      HPLGST_READ_RANGE(ctx, from, size);                                 \
      HPLGST_WRITE_RANGE(ctx, to, size);                                  \
    }                                                                   \
    return REAL(memcpy)(to, from, size);                                \
  } while (0)

// memset is called inside Printf.
#define HPLGST_MEMSET_IMPL(ctx, block, c, size)                           \
  do {                                                                  \
    if (UNLIKELY(!hplgst_inited)) return internal_memset(block, c, size); \
    if (hplgst_init_is_running) {                                         \
      return REAL(memset)(block, c, size);                              \
    }                                                                   \
    ENSURE_HPLGST_INITED();                                               \
    if (getFlags()->replace_intrin) {                                      \
      HPLGST_WRITE_RANGE(ctx, block, size);                               \
    }                                                                   \
    return REAL(memset)(block, c, size);                                \
  } while (0)

#define HPLGST_MEMMOVE_IMPL(ctx, to, from, size)                           \
  do {                                                                   \
    if (UNLIKELY(!hplgst_inited)) return internal_memmove(to, from, size); \
    ENSURE_HPLGST_INITED();                                                \
    if (getFlags()->replace_intrin) {                                       \
      HPLGST_READ_RANGE(ctx, from, size);                                  \
      HPLGST_WRITE_RANGE(ctx, to, size);                                   \
    }                                                                    \
    return internal_memmove(to, from, size);                             \
  } while (0)

void SetThreadName(const char *name) {
  u32 t = GetCurrentThread();
  if (t)
    hplgstThreadRegistry().SetThreadName(t, name);
}

int OnExit() {
  // FIXME: ask frontend whether we need to return failure.
  return 0;
}

struct HplgstInterceptorContext {
  const char *interceptor_name;
};



#define HPLGST_INTERCEPTOR_ENTER(ctx, func)                                      \
  HplgstInterceptorContext _ctx = {#func};                                       \
  ctx = (void *)&_ctx;                                                         \
  (void) ctx;                                                                  \

#define COMMON_INTERCEPT_FUNCTION(name) HPLGST_INTERCEPT_FUNC(name)
#define COMMON_INTERCEPT_FUNCTION_VER(name, ver)                          \
  HPLGST_INTERCEPT_FUNC_VER(name, ver)
#define COMMON_INTERCEPTOR_WRITE_RANGE(ctx, ptr, size) \
  HPLGST_WRITE_RANGE(ctx, ptr, size)
#define COMMON_INTERCEPTOR_READ_RANGE(ctx, ptr, size) \
  HPLGST_READ_RANGE(ctx, ptr, size)
#define COMMON_INTERCEPTOR_ENTER(ctx, func, ...)                               \
  HPLGST_INTERCEPTOR_ENTER(ctx, func);                                           \
  do {                                                                         \
    if (hplgst_init_is_running)                                                  \
      return REAL(func)(__VA_ARGS__);                                          \
    if (SANITIZER_MAC && UNLIKELY(!hplgst_inited))                               \
      return REAL(func)(__VA_ARGS__);                                          \
    ENSURE_HPLGST_INITED();                                                      \
  } while (false)
#define COMMON_INTERCEPTOR_DIR_ACQUIRE(ctx, path) \
  do {                                            \
  } while (false)
#define COMMON_INTERCEPTOR_FD_ACQUIRE(ctx, fd) \
  do {                                         \
  } while (false)
#define COMMON_INTERCEPTOR_FD_RELEASE(ctx, fd) \
  do {                                         \
  } while (false)
#define COMMON_INTERCEPTOR_FD_SOCKET_ACCEPT(ctx, fd, newfd) \
  do {                                                      \
  } while (false)
#define COMMON_INTERCEPTOR_SET_THREAD_NAME(ctx, name) SetThreadName(name)
// Should be hplgstThreadRegistry().SetThreadNameByUserId(thread, name)
// But hplgst does not remember UserId's for threads (pthread_t);
// and remembers all ever existed threads, so the linear search by UserId
// can be slow.
#define COMMON_INTERCEPTOR_SET_PTHREAD_NAME(ctx, thread, name) \
  do {                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_BLOCK_REAL(name) REAL(name)
// Strict init-order checking is dlopen-hostile:
// https://github.com/google/sanitizers/issues/178
#define COMMON_INTERCEPTOR_ON_DLOPEN(filename, flag) {}
#define COMMON_INTERCEPTOR_ON_EXIT(ctx) OnExit()
#define COMMON_INTERCEPTOR_LIBRARY_LOADED(filename, handle) {}
#define COMMON_INTERCEPTOR_LIBRARY_UNLOADED() {}
#define COMMON_INTERCEPTOR_NOTHING_IS_INITIALIZED (!hplgst_inited)
#define COMMON_INTERCEPTOR_GET_TLS_RANGE(begin, end)                           \
  if (ThreadContext *t = CurrentThreadContext()) {                                    \
    *begin = t->tls_begin();                                                   \
    *end = t->tls_end();                                                       \
  } else {                                                                     \
    *begin = *end = 0;                                                         \
  }

#define COMMON_INTERCEPTOR_MEMMOVE_IMPL(ctx, to, from, size) \
  do {                                                       \
    HPLGST_INTERCEPTOR_ENTER(ctx, memmove);                    \
    HPLGST_MEMMOVE_IMPL(ctx, to, from, size);                  \
  } while (false)

#define COMMON_INTERCEPTOR_MEMCPY_IMPL(ctx, to, from, size) \
  do {                                                      \
    HPLGST_INTERCEPTOR_ENTER(ctx, memcpy);                    \
    HPLGST_MEMCPY_IMPL(ctx, to, from, size);                  \
  } while (false)

#define COMMON_INTERCEPTOR_MEMSET_IMPL(ctx, block, c, size) \
  do {                                                      \
    HPLGST_INTERCEPTOR_ENTER(ctx, memset);                    \
    HPLGST_MEMSET_IMPL(ctx, block, c, size);                  \
  } while (false)

// realpath interceptor does something weird with wrapped malloc on mac OS
#undef SANITIZER_INTERCEPT_REALPATH
#include "sanitizer_common/sanitizer_common_interceptors.inc"

///// Thread initialization and finalization. /////

static unsigned g_thread_finalize_key;

static void thread_finalize(void *v) {
  uptr iter = (uptr)v;
  if (iter > 1) {
    if (pthread_setspecific(g_thread_finalize_key, (void*)(iter - 1))) {
      Report("LeakSanitizer: failed to set thread key.\n");
      Die();
    }
    return;
  }
  ThreadFinish();
}

struct ThreadParam {
  void *(*callback)(void *arg);
  void *param;
  atomic_uintptr_t tid;
};

extern "C" void *__hplgst_thread_start_func(void *arg) {
  ThreadParam *p = (ThreadParam*)arg;
  void* (*callback)(void *arg) = p->callback;
  void *param = p->param;
  // Wait until the last iteration to maximize the chance that we are the last
  // destructor to run.
  if (pthread_setspecific(g_thread_finalize_key,
                          (void*)GetPthreadDestructorIterations())) {
    Report("LeakSanitizer: failed to set thread key.\n");
    Die();
  }
  u32 tid = 0;
  while ((tid = (u32)atomic_load(&p->tid, memory_order_acquire)) == 0)
    internal_sched_yield();
  SetCurrentThread(tid);
  ThreadStart(tid, GetTid());
  atomic_store(&p->tid, 0, memory_order_release);
  return callback(param);
}

INTERCEPTOR(int, pthread_create, void *th, void *attr,
            void *(*callback)(void *), void *param) {
  ENSURE_HPLGST_INITED();
  EnsureMainThreadIDIsCorrect();
  __sanitizer_pthread_attr_t myattr;
  if (!attr) {
    pthread_attr_init(&myattr);
    attr = &myattr;
  }
  AdjustStackSize(attr);
  int detached = 0;
  pthread_attr_getdetachstate(attr, &detached);
  ThreadParam p;
  p.callback = callback;
  p.param = param;
  atomic_store(&p.tid, 0, memory_order_relaxed);
  int res;
  {
    // Ignore all allocations made by pthread_create: thread stack/TLS may be
    // stored by pthread for future reuse even after thread destruction, and
    // the linked list it's stored in doesn't even hold valid pointers to the
    // objects, the latter are calculated by obscure pointer arithmetic.
    ScopedInterceptorDisabler disabler;
    res = REAL(pthread_create)(th, attr, __hplgst_thread_start_func, &p);
  }
  if (res == 0) {
    // TODO fix this pthread crap
    int tid = ThreadCreate(GetCurrentThread(), *(uptr *)th,
            /*detached == PTHREAD_CREATE_DETACHED*/false);
    CHECK_NE(tid, 0);
    atomic_store(&p.tid, tid, memory_order_release);
    while (atomic_load(&p.tid, memory_order_acquire) != 0)
      internal_sched_yield();
  }
  if (attr == &myattr)
    pthread_attr_destroy(&myattr);
  return res;
}

INTERCEPTOR(int, pthread_join, void *th, void **ret) {
  ENSURE_HPLGST_INITED();
  u32 tid = ThreadTid((uptr)th);
  int res = REAL(pthread_join)(th, ret);
  if (res == 0)
    ThreadJoin(tid);
  return res;
}
#define HPLGST_READ_STRING_OF_LEN(ctx, s, len, n)                 \
  HPLGST_READ_RANGE((ctx), (s),                                   \
    common_flags()->strict_string_checks ? (len) + 1 : (n))

#define HPLGST_READ_STRING(ctx, s, n)                             \
  HPLGST_READ_STRING_OF_LEN((ctx), (s), REAL(strlen)(s), (n))


static inline uptr MaybeRealStrnlen(const char *s, uptr maxlen) {
#if SANITIZER_INTERCEPT_STRNLEN
  if (REAL(strnlen)) {
    return REAL(strnlen)(s, maxlen);
  }
#endif
  return internal_strnlen(s, maxlen);
}


INTERCEPTOR(uptr, fread, void *ptr, uptr size, uptr nmemb, void *f) {
  void *ctx;
  COMMON_INTERCEPTOR_ENTER(ctx, fread, ptr, size, nmemb, f);
  COMMON_INTERCEPTOR_WRITE_RANGE(ctx, ptr, size * nmemb);
  return REAL(fread)(ptr, size, nmemb, f);
}

INTERCEPTOR(uptr, fwrite, const void *p, uptr size, uptr nmemb, void *f) {
  void *ctx;
  COMMON_INTERCEPTOR_ENTER(ctx, fwrite, p, size, nmemb, f);
  COMMON_INTERCEPTOR_READ_RANGE(ctx, p, size * nmemb);
  return REAL(fwrite)(p, size, nmemb, f);
}

INTERCEPTOR(int, puts, const char *s) {
  void *ctx;
  COMMON_INTERCEPTOR_ENTER(ctx, puts, s);
  COMMON_INTERCEPTOR_READ_RANGE(ctx, s, internal_strlen(s));
  return REAL(puts)(s);
}

// For both strcat() and strncat() we need to check the validity of |to|
// argument irrespective of the |from| length.
INTERCEPTOR(char*, strcat, char *to, const char *from) {  // NOLINT
  void *ctx;
  HPLGST_INTERCEPTOR_ENTER(ctx, strcat);  // NOLINT
  ENSURE_HPLGST_INITED();
  if (getFlags()->replace_str) {
    uptr from_length = REAL(strlen)(from);
    HPLGST_READ_RANGE(ctx, from, from_length + 1);
    uptr to_length = REAL(strlen)(to);
    HPLGST_READ_STRING_OF_LEN(ctx, to, to_length, to_length);
    HPLGST_WRITE_RANGE(ctx, to + to_length, from_length + 1);
    // If the copying actually happens, the |from| string should not overlap
    // with the resulting string starting at |to|, which has a length of
    // to_length + from_length + 1.
    if (from_length > 0) {
      CHECK_RANGES_OVERLAP("strcat", to, from_length + to_length + 1,
                           from, from_length + 1);
    }
  }
  return REAL(strcat)(to, from);  // NOLINT
}

INTERCEPTOR(char*, strncat, char *to, const char *from, uptr size) {
  void *ctx;
  HPLGST_INTERCEPTOR_ENTER(ctx, strncat);
  ENSURE_HPLGST_INITED();
  if (getFlags()->replace_str) {
    uptr from_length = MaybeRealStrnlen(from, size);
    uptr copy_length = Min(size, from_length + 1);
    HPLGST_READ_RANGE(ctx, from, copy_length);
    uptr to_length = REAL(strlen)(to);
    HPLGST_READ_STRING_OF_LEN(ctx, to, to_length, to_length);
    HPLGST_WRITE_RANGE(ctx, to + to_length, from_length + 1);
    if (from_length > 0) {
      CHECK_RANGES_OVERLAP("strncat", to, to_length + copy_length + 1,
                           from, copy_length);
    }
  }
  return REAL(strncat)(to, from, size);
}

INTERCEPTOR(char*, strcpy, char *to, const char *from) {  // NOLINT
  void *ctx;
  HPLGST_INTERCEPTOR_ENTER(ctx, strcpy);  // NOLINT
#if SANITIZER_MAC
  if (UNLIKELY(!hplgst_inited)) return REAL(strcpy)(to, from);  // NOLINT
#endif
  // strcpy is called from malloc_default_purgeable_zone()
  // in __hplgst::ReplaceSystemAlloc() on Mac.
  if (hplgst_init_is_running) {
    return REAL(strcpy)(to, from);  // NOLINT
  }
  ENSURE_HPLGST_INITED();
  if (getFlags()->replace_str) {
    uptr from_size = REAL(strlen)(from) + 1;
    CHECK_RANGES_OVERLAP("strcpy", to, from_size, from, from_size);
    HPLGST_READ_RANGE(ctx, from, from_size);
    HPLGST_WRITE_RANGE(ctx, to, from_size);
  }
  return REAL(strcpy)(to, from);  // NOLINT
}

INTERCEPTOR(char*, strdup, const char *s) {
  void *ctx;
  HPLGST_INTERCEPTOR_ENTER(ctx, strdup);
  if (UNLIKELY(!hplgst_inited)) return internal_strdup(s);
  ENSURE_HPLGST_INITED();
  uptr length = REAL(strlen)(s);
  if (getFlags()->replace_str) {
    HPLGST_READ_RANGE(ctx, s, length + 1);
  }
  GET_STACK_TRACE_MALLOC;
  void *new_mem = hplgst_malloc(length + 1, stack);
  HPLGST_WRITE_RANGE(ctx, new_mem, length + 1);
  REAL(memcpy)(new_mem, s, length + 1);
  return reinterpret_cast<char*>(new_mem);
}

#if HPLGST_INTERCEPT___STRDUP
INTERCEPTOR(char*, __strdup, const char *s) {
  void *ctx;
  HPLGST_INTERCEPTOR_ENTER(ctx, strdup);
  if (UNLIKELY(!hplgst_inited)) return internal_strdup(s);
  ENSURE_HPLGST_INITED();
  uptr length = REAL(strlen)(s);
  if (getFlags()->replace_str) {
    HPLGST_READ_RANGE(ctx, s, length + 1);
  }
  GET_STACK_TRACE_MALLOC;
  void *new_mem = hplgst_malloc(length + 1, stack);
  REAL(memcpy)(new_mem, s, length + 1);
  return reinterpret_cast<char*>(new_mem);
}
#endif // HPLGST_INTERCEPT___STRDUP

INTERCEPTOR(SIZE_T, wcslen, const wchar_t *s) {
  void *ctx;
  HPLGST_INTERCEPTOR_ENTER(ctx, wcslen);
  SIZE_T length = internal_wcslen(s);
  if (!hplgst_init_is_running) {
    ENSURE_HPLGST_INITED();
    HPLGST_READ_RANGE(ctx, s, (length + 1) * sizeof(wchar_t));
  }
  return length;
}

INTERCEPTOR(char*, strncpy, char *to, const char *from, uptr size) {
  void *ctx;
  HPLGST_INTERCEPTOR_ENTER(ctx, strncpy);
  ENSURE_HPLGST_INITED();
  if (getFlags()->replace_str) {
    uptr from_size = Min(size, MaybeRealStrnlen(from, size) + 1);
    CHECK_RANGES_OVERLAP("strncpy", to, from_size, from, from_size);
    HPLGST_READ_RANGE(ctx, from, from_size);
    HPLGST_WRITE_RANGE(ctx, to, size);
  }
  return REAL(strncpy)(to, from, size);
}

INTERCEPTOR(long, strtol, const char *nptr,  // NOLINT
            char **endptr, int base) {
  void *ctx;
  HPLGST_INTERCEPTOR_ENTER(ctx, strtol);
  ENSURE_HPLGST_INITED();
  if (!getFlags()->replace_str) {
    return REAL(strtol)(nptr, endptr, base);
  }
  char *real_endptr;
  long result = REAL(strtol)(nptr, &real_endptr, base);  // NOLINT
  StrtolFixAndCheck(ctx, nptr, endptr, real_endptr, base);
  return result;
}

INTERCEPTOR(int, atoi, const char *nptr) {
  void *ctx;
  HPLGST_INTERCEPTOR_ENTER(ctx, atoi);
#if SANITIZER_MAC
  if (UNLIKELY(!hplgst_inited)) return REAL(atoi)(nptr);
#endif
  ENSURE_HPLGST_INITED();
  if (!getFlags()->replace_str) {
    return REAL(atoi)(nptr);
  }
  char *real_endptr;
  // "man atoi" tells that behavior of atoi(nptr) is the same as
  // strtol(nptr, 0, 10), i.e. it sets errno to ERANGE if the
  // parsed integer can't be stored in *long* type (even if it's
  // different from int). So, we just imitate this behavior.
  int result = REAL(strtol)(nptr, &real_endptr, 10);
  FixRealStrtolEndptr(nptr, &real_endptr);
  HPLGST_READ_STRING(ctx, nptr, (real_endptr - nptr) + 1);
  return result;
}

INTERCEPTOR(long, atol, const char *nptr) {  // NOLINT
  void *ctx;
  HPLGST_INTERCEPTOR_ENTER(ctx, atol);
#if SANITIZER_MAC
  if (UNLIKELY(!hplgst_inited)) return REAL(atol)(nptr);
#endif
  ENSURE_HPLGST_INITED();
  if (!getFlags()->replace_str) {
    return REAL(atol)(nptr);
  }
  char *real_endptr;
  long result = REAL(strtol)(nptr, &real_endptr, 10);  // NOLINT
  FixRealStrtolEndptr(nptr, &real_endptr);
  HPLGST_READ_STRING(ctx, nptr, (real_endptr - nptr) + 1);
  return result;
}

#if HPLGST_INTERCEPT_ATOLL_AND_STRTOLL
INTERCEPTOR(long long, strtoll, const char *nptr,  // NOLINT
            char **endptr, int base) {
  void *ctx;
  HPLGST_INTERCEPTOR_ENTER(ctx, strtoll);
  ENSURE_HPLGST_INITED();
  if (!getFlags()->replace_str) {
    return REAL(strtoll)(nptr, endptr, base);
  }
  char *real_endptr;
  long long result = REAL(strtoll)(nptr, &real_endptr, base);  // NOLINT
  StrtolFixAndCheck(ctx, nptr, endptr, real_endptr, base);
  return result;
}

INTERCEPTOR(long long, atoll, const char *nptr) {  // NOLINT
  void *ctx;
  HPLGST_INTERCEPTOR_ENTER(ctx, atoll);
  ENSURE_HPLGST_INITED();
  if (!getFlags()->replace_str) {
    return REAL(atoll)(nptr);
  }
  char *real_endptr;
  long long result = REAL(strtoll)(nptr, &real_endptr, 10);  // NOLINT
  FixRealStrtolEndptr(nptr, &real_endptr);
  HPLGST_READ_STRING(ctx, nptr, (real_endptr - nptr) + 1);
  return result;
}
#endif  // HPLGST_INTERCEPTA_ATOLL_AND_STRTOLL

namespace __hplgst {

void InitializeInterceptors() {

  static bool was_called_once;
  CHECK(!was_called_once);
  was_called_once = true;
  InitializeCommonInterceptors();
  // Intercept str* functions.
  HPLGST_INTERCEPT_FUNC(strcat);  // NOLINT
  HPLGST_INTERCEPT_FUNC(strcpy);  // NOLINT
  HPLGST_INTERCEPT_FUNC(wcslen);
  HPLGST_INTERCEPT_FUNC(strncat);
  HPLGST_INTERCEPT_FUNC(strncpy);
  HPLGST_INTERCEPT_FUNC(strdup);
#if HPLGST_INTERCEPT___STRDUP
  HPLGST_INTERCEPT_FUNC(__strdup);
#endif
#if HPLGST_INTERCEPT_INDEX && HPLGST_USE_ALIAS_ATTRIBUTE_FOR_INDEX
  HPLGST_INTERCEPT_FUNC(index);
#endif

  HPLGST_INTERCEPT_FUNC(atoi);
  HPLGST_INTERCEPT_FUNC(atol);
  HPLGST_INTERCEPT_FUNC(strtol);
#if HPLGST_INTERCEPT_ATOLL_AND_STRTOLL
  HPLGST_INTERCEPT_FUNC(atoll);
  HPLGST_INTERCEPT_FUNC(strtoll);
#endif
  // TODO add range access function interceptors (memset, etc. )
  INTERCEPT_FUNCTION(malloc);
  INTERCEPT_FUNCTION(free);
  HPLGST_MAYBE_INTERCEPT_CFREE;
  INTERCEPT_FUNCTION(calloc);
  INTERCEPT_FUNCTION(realloc);
  INTERCEPT_FUNCTION(puts);
  INTERCEPT_FUNCTION(fread);
  INTERCEPT_FUNCTION(fwrite);
  HPLGST_MAYBE_INTERCEPT_MEMALIGN;
  HPLGST_MAYBE_INTERCEPT___LIBC_MEMALIGN;
  HPLGST_MAYBE_INTERCEPT_ALIGNED_ALLOC;
  INTERCEPT_FUNCTION(posix_memalign);
  INTERCEPT_FUNCTION(valloc);
  HPLGST_MAYBE_INTERCEPT_PVALLOC;
  HPLGST_MAYBE_INTERCEPT_MALLOC_USABLE_SIZE;
  HPLGST_MAYBE_INTERCEPT_MALLINFO;
  HPLGST_MAYBE_INTERCEPT_MALLOPT;
  INTERCEPT_FUNCTION(pthread_create);
  INTERCEPT_FUNCTION(pthread_join);

  if (pthread_key_create(&g_thread_finalize_key, &thread_finalize)) {
    Report("Heapologist: failed to create thread key.\n");
    Die();
  }
}

} // namespace __hplgst
