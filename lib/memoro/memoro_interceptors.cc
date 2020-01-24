//=-- memoro_interceptors.cc ----------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of Memoro.
// Stuart Byma, EPFL.
//
// Interceptors for Memoro.
//
//===----------------------------------------------------------------------===//

#include "memoro_interceptors.h"
#include "interception/interception.h"
#include "memoro.h"
#include "memoro_allocator.h"
#include "memoro_flags.h"
#include "memoro_thread.h"
#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_allocator_checks.h"
#include "sanitizer_common/sanitizer_platform_interceptors.h"
#include "sanitizer_common/sanitizer_posix.h"
#include "sanitizer_common/sanitizer_tls_get_addr.h"

#include <stddef.h>
#include <alloca.h>

using namespace __memoro;

// Fake std::nothrow_t and std::align_val_t to avoid including <new>.
namespace std {
struct nothrow_t {};
enum class align_val_t: size_t {};
}  // namespace std

extern "C" {
int pthread_attr_init(void *attr);
int pthread_attr_destroy(void *attr);
// int pthread_attr_getdetachstate(void *attr, int *v);
int pthread_key_create(unsigned *key, void (*destructor)(void *v));
int pthread_setspecific(unsigned key, const void *v);
}

///// Malloc/free interceptors. /////

namespace std {
struct nothrow_t;
}

DECLARE_REAL_AND_INTERCEPTOR(void *, malloc, uptr)
DECLARE_REAL_AND_INTERCEPTOR(void, free, void *)

#if !SANITIZER_MAC

static uptr allocated_for_dlsym;
static const uptr kDlsymAllocPoolSize = 1024 * 1024;
static uptr alloc_memory_for_dlsym[kDlsymAllocPoolSize];

static bool IsInDlsymAllocPool(const void *ptr) {
  uptr off = (uptr)ptr - (uptr)alloc_memory_for_dlsym;
  return off < sizeof(alloc_memory_for_dlsym);
}

static void *AllocateFromLocalPool(uptr size_in_bytes) {
  uptr size_in_words = RoundUpTo(size_in_bytes, kWordSize) / kWordSize;
  void *mem = (void*)&alloc_memory_for_dlsym[allocated_for_dlsym];
  allocated_for_dlsym += size_in_words;
  CHECK_LT(allocated_for_dlsym, kDlsymAllocPoolSize);
  return mem;
}

INTERCEPTOR(void *, malloc, uptr size) {
  if (UNLIKELY(!memoro_inited))
    // Hack: dlsym calls malloc before REAL(malloc) is retrieved from dlsym.
    return AllocateFromLocalPool(size);
  ENSURE_MEMORO_INITED();
  GET_STACK_TRACE_MALLOC;
  return memoro_malloc(size, stack);
}

INTERCEPTOR(void, free, void *p) {
  if (UNLIKELY(IsInDlsymAllocPool(p)))
    return;
  ENSURE_MEMORO_INITED();
  memoro_free(p);
}

INTERCEPTOR(void *, calloc, uptr nmemb, uptr size) {
  if (UNLIKELY(!memoro_inited))
    // Hack: dlsym calls calloc before REAL(calloc) is retrieved from dlsym.
    return AllocateFromLocalPool(nmemb * size);
  ENSURE_MEMORO_INITED();
  GET_STACK_TRACE_MALLOC;
  return memoro_calloc(nmemb, size, stack);
}

INTERCEPTOR(void *, realloc, void *ptr, uptr size) {
  GET_STACK_TRACE_MALLOC;
  if (UNLIKELY(IsInDlsymAllocPool(ptr))) {
    uptr offset = (uptr)ptr - (uptr)alloc_memory_for_dlsym;
    uptr copy_size = Min(size, kDlsymAllocPoolSize - offset);
    void *new_ptr = memoro_malloc(size, stack);
    internal_memcpy(new_ptr, ptr, copy_size);
    return new_ptr;
  }
  ENSURE_MEMORO_INITED();
  return memoro_realloc(ptr, size, stack);
}

INTERCEPTOR(int, posix_memalign, void **memptr, uptr alignment, uptr size) {
  ENSURE_MEMORO_INITED();
  GET_STACK_TRACE_MALLOC;
  *memptr = memoro_memalign(alignment, size, stack);
  // FIXME: Return ENOMEM if user requested more than max alloc size.
  return 0;
}

INTERCEPTOR(void *, valloc, uptr size) {
  ENSURE_MEMORO_INITED();
  GET_STACK_TRACE_MALLOC;
  return memoro_valloc(size, stack);
}
#endif

#if SANITIZER_INTERCEPT_MEMALIGN
INTERCEPTOR(void *, memalign, uptr alignment, uptr size) {
  ENSURE_MEMORO_INITED();
  GET_STACK_TRACE_MALLOC;
  return memoro_memalign(alignment, size, stack);
}
#define MEMORO_MAYBE_INTERCEPT_MEMALIGN INTERCEPT_FUNCTION(memalign)

INTERCEPTOR(void *, __libc_memalign, uptr alignment, uptr size) {
  ENSURE_MEMORO_INITED();
  GET_STACK_TRACE_MALLOC;
  void *res = memoro_memalign(alignment, size, stack);
  DTLS_on_libc_memalign(res, size);
  return res;
}
#define MEMORO_MAYBE_INTERCEPT___LIBC_MEMALIGN                                 \
  INTERCEPT_FUNCTION(__libc_memalign)
#else
#define MEMORO_MAYBE_INTERCEPT_MEMALIGN
#define MEMORO_MAYBE_INTERCEPT___LIBC_MEMALIGN
#endif // SANITIZER_INTERCEPT_MEMALIGN

#if SANITIZER_INTERCEPT_ALIGNED_ALLOC
INTERCEPTOR(void *, aligned_alloc, uptr alignment, uptr size) {
  ENSURE_MEMORO_INITED();
  GET_STACK_TRACE_MALLOC;
  return memoro_memalign(alignment, size, stack);
}
#define MEMORO_MAYBE_INTERCEPT_ALIGNED_ALLOC INTERCEPT_FUNCTION(aligned_alloc)
#else
#define MEMORO_MAYBE_INTERCEPT_ALIGNED_ALLOC
#endif

#if SANITIZER_INTERCEPT_MALLOC_USABLE_SIZE
INTERCEPTOR(uptr, malloc_usable_size, void *ptr) {
  ENSURE_MEMORO_INITED();
  return GetMallocUsableSize(ptr);
}
#define MEMORO_MAYBE_INTERCEPT_MALLOC_USABLE_SIZE                              \
  INTERCEPT_FUNCTION(malloc_usable_size)
#else
#define MEMORO_MAYBE_INTERCEPT_MALLOC_USABLE_SIZE
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
#define MEMORO_MAYBE_INTERCEPT_MALLINFO INTERCEPT_FUNCTION(mallinfo)

INTERCEPTOR(int, mallopt, int cmd, int value) { return -1; }
#define MEMORO_MAYBE_INTERCEPT_MALLOPT INTERCEPT_FUNCTION(mallopt)
#else
#define MEMORO_MAYBE_INTERCEPT_MALLINFO
#define MEMORO_MAYBE_INTERCEPT_MALLOPT
#endif // SANITIZER_INTERCEPT_MALLOPT_AND_MALLINFO

#if SANITIZER_INTERCEPT_PVALLOC
INTERCEPTOR(void *, pvalloc, uptr size) {
  ENSURE_MEMORO_INITED();
  GET_STACK_TRACE_MALLOC;
  uptr PageSize = GetPageSizeCached();
  size = RoundUpTo(size, PageSize);
  if (size == 0) {
    // pvalloc(0) should allocate one page.
    size = PageSize;
  }
  return Allocate(stack, size, GetPageSizeCached(), kAlwaysClearMemory);
}
#define MEMORO_MAYBE_INTERCEPT_PVALLOC INTERCEPT_FUNCTION(pvalloc)
#else
#define MEMORO_MAYBE_INTERCEPT_PVALLOC
#endif // SANITIZER_INTERCEPT_PVALLOC

#if SANITIZER_INTERCEPT_CFREE
INTERCEPTOR(void, cfree, void *p) ALIAS(WRAPPER_NAME(free));
#define MEMORO_MAYBE_INTERCEPT_CFREE INTERCEPT_FUNCTION(cfree)
#else
#define MEMORO_MAYBE_INTERCEPT_CFREE
#endif // SANITIZER_INTERCEPT_CFREE

#define OPERATOR_NEW_BODY                                                      \
  ENSURE_MEMORO_INITED();                                                      \
  GET_STACK_TRACE_MALLOC;                                                      \
  return Allocate(stack, size, 1, kAlwaysClearMemory);

#define OPERATOR_NEW_BODY_ALIGN                                                \
  ENSURE_MEMORO_INITED();                                                      \
  GET_STACK_TRACE_MALLOC;                                                      \
  return Allocate(stack, size, (uptr)align, kAlwaysClearMemory);

INTERCEPTOR_ATTRIBUTE
void *operator new(size_t size) { OPERATOR_NEW_BODY; }
INTERCEPTOR_ATTRIBUTE
void *operator new[](size_t size) { OPERATOR_NEW_BODY; }
INTERCEPTOR_ATTRIBUTE
void *operator new(size_t size, std::nothrow_t const &) { OPERATOR_NEW_BODY; }
INTERCEPTOR_ATTRIBUTE
void *operator new[](size_t size, std::nothrow_t const &) { OPERATOR_NEW_BODY; }

INTERCEPTOR_ATTRIBUTE
void *operator new(size_t size, std::align_val_t align)
{ OPERATOR_NEW_BODY_ALIGN; }
INTERCEPTOR_ATTRIBUTE
void *operator new[](size_t size, std::align_val_t align)
{ OPERATOR_NEW_BODY_ALIGN; }
INTERCEPTOR_ATTRIBUTE
void *operator new(size_t size, std::align_val_t align, std::nothrow_t const&)
{ OPERATOR_NEW_BODY_ALIGN; }
INTERCEPTOR_ATTRIBUTE
void *operator new[](size_t size, std::align_val_t align, std::nothrow_t const&)
{ OPERATOR_NEW_BODY_ALIGN; }

#define OPERATOR_DELETE_BODY                                                   \
  ENSURE_MEMORO_INITED();                                                      \
  Deallocate(ptr);

INTERCEPTOR_ATTRIBUTE
void operator delete(void *ptr)NOEXCEPT { OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete[](void *ptr) NOEXCEPT { OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete(void *ptr, std::nothrow_t const &) {
  OPERATOR_DELETE_BODY;
}
INTERCEPTOR_ATTRIBUTE
void operator delete[](void *ptr, std::nothrow_t const &) {
  OPERATOR_DELETE_BODY;
}
INTERCEPTOR_ATTRIBUTE
void operator delete(void *ptr, size_t size) NOEXCEPT
{ OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete[](void *ptr, size_t size) NOEXCEPT
{ OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete(void *ptr, std::align_val_t align) NOEXCEPT
{ OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete[](void *ptr, std::align_val_t align) NOEXCEPT
{ OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete(void *ptr, std::align_val_t align, std::nothrow_t const&)
{ OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete[](void *ptr, std::align_val_t align, std::nothrow_t const&)
{ OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete(void *ptr, size_t size, std::align_val_t align) NOEXCEPT
{ OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete[](void *ptr, size_t size, std::align_val_t align) NOEXCEPT
{ OPERATOR_DELETE_BODY; }

#define MEMORO_READ_RANGE(ctx, offset, size)                                   \
  do {                                                                         \
    if (getFlags()->access_sampling_rate != 0) {                               \
      uptr rsp = (uptr)alloca(0);                                              \
      uptr uoffset = (uptr)offset;                                             \
      if (uoffset < rsp || GetCurrentStackEnd() <= uoffset)                    \
        processRangeAccess(GET_CALLER_PC(), (uptr)offset, size, false);        \
    }                                                                          \
  } while (false)

#define MEMORO_WRITE_RANGE(ctx, offset, size)                                  \
  do {                                                                         \
    if (getFlags()->access_sampling_rate != 0) {                               \
      uptr rsp = (uptr)alloca(0);                                              \
      uptr uoffset = (uptr)offset;                                             \
      if (uoffset < rsp || GetCurrentStackEnd() <= uoffset)                    \
        processRangeAccess(GET_CALLER_PC(), (uptr)offset, size, true);         \
    }                                                                          \
  } while (false)

// Behavior of functions like "memcpy" or "strcpy" is undefined
// if memory intervals overlap. We report error in this case.
// Macro is used to avoid creation of new frames.
static inline bool RangesOverlap(const char *offset1, uptr length1,
                                 const char *offset2, uptr length2) {
  return !((offset1 + length1 <= offset2) || (offset2 + length2 <= offset1));
}
#define CHECK_RANGES_OVERLAP(name, _offset1, length1, _offset2, length2)       \
  do {                                                                         \
    const char *offset1 = (const char *)_offset1;                              \
    const char *offset2 = (const char *)_offset2;                              \
    if (RangesOverlap(offset1, length1, offset2, length2)) {                   \
      GET_STACK_TRACE_FATAL;                                                   \
      Printf("Ranges overlap wtf\n");                                          \
    }                                                                          \
  } while (0)

#define MEMORO_MEMCPY_IMPL(ctx, to, from, size)                                \
  do {                                                                         \
    if (UNLIKELY(!memoro_inited))                                              \
      return internal_memcpy(to, from, size);                                  \
    if (memoro_init_is_running) {                                              \
      return REAL(memcpy)(to, from, size);                                     \
    }                                                                          \
    ENSURE_MEMORO_INITED();                                                    \
    if (getFlags()->replace_intrin) {                                          \
      if (to != from) {                                                        \
        CHECK_RANGES_OVERLAP("memcpy", to, size, from, size);                  \
      }                                                                        \
      MEMORO_READ_RANGE(ctx, from, size);                                      \
      MEMORO_WRITE_RANGE(ctx, to, size);                                       \
    }                                                                          \
    return REAL(memcpy)(to, from, size);                                       \
  } while (0)

// memset is called inside Printf.
#define MEMORO_MEMSET_IMPL(ctx, block, c, size)                                \
  do {                                                                         \
    if (UNLIKELY(!memoro_inited))                                              \
      return internal_memset(block, c, size);                                  \
    if (memoro_init_is_running) {                                              \
      return REAL(memset)(block, c, size);                                     \
    }                                                                          \
    ENSURE_MEMORO_INITED();                                                    \
    if (getFlags()->replace_intrin) {                                          \
      MEMORO_WRITE_RANGE(ctx, block, size);                                    \
    }                                                                          \
    return REAL(memset)(block, c, size);                                       \
  } while (0)

#define MEMORO_MEMMOVE_IMPL(ctx, to, from, size)                               \
  do {                                                                         \
    if (UNLIKELY(!memoro_inited))                                              \
      return internal_memmove(to, from, size);                                 \
    ENSURE_MEMORO_INITED();                                                    \
    if (getFlags()->replace_intrin) {                                          \
      MEMORO_READ_RANGE(ctx, from, size);                                      \
      MEMORO_WRITE_RANGE(ctx, to, size);                                       \
    }                                                                          \
    return internal_memmove(to, from, size);                                   \
  } while (0)

void SetThreadName(const char *name) {
  u32 t = GetCurrentThread();
  if (t)
    memoroThreadRegistry().SetThreadName(t, name);
}

// should this direct to the main OnExit in memoro_interface.cc?
int OnExit() { return 0; }

struct MemoroInterceptorContext {
  const char *interceptor_name;
};

#define MEMORO_INTERCEPTOR_ENTER(ctx, func)                                    \
  MemoroInterceptorContext _ctx = {#func};                                     \
  ctx = (void *)&_ctx;                                                         \
  (void)ctx;

#define COMMON_INTERCEPT_FUNCTION(name) MEMORO_INTERCEPT_FUNC(name)
#define COMMON_INTERCEPT_FUNCTION_VER(name, ver)                               \
  MEMORO_INTERCEPT_FUNC_VER(name, ver)
#define COMMON_INTERCEPTOR_WRITE_RANGE(ctx, ptr, size)                         \
  MEMORO_WRITE_RANGE(ctx, ptr, size)
#define COMMON_INTERCEPTOR_READ_RANGE(ctx, ptr, size)                          \
  MEMORO_READ_RANGE(ctx, ptr, size)
#define COMMON_INTERCEPTOR_ENTER(ctx, func, ...)                               \
  MEMORO_INTERCEPTOR_ENTER(ctx, func);                                         \
  do {                                                                         \
    if (memoro_init_is_running)                                                \
      return REAL(func)(__VA_ARGS__);                                          \
    if (SANITIZER_MAC && UNLIKELY(!memoro_inited))                             \
      return REAL(func)(__VA_ARGS__);                                          \
    ENSURE_MEMORO_INITED();                                                    \
  } while (false)
#define COMMON_INTERCEPTOR_DIR_ACQUIRE(ctx, path)                              \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_FD_ACQUIRE(ctx, fd)                                 \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_FD_RELEASE(ctx, fd)                                 \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_FD_SOCKET_ACCEPT(ctx, fd, newfd)                    \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_SET_THREAD_NAME(ctx, name) SetThreadName(name)
// Should be memoroThreadRegistry().SetThreadNameByUserId(thread, name)
// But memoro does not remember UserId's for threads (pthread_t);
// and remembers all ever existed threads, so the linear search by UserId
// can be slow.
#define COMMON_INTERCEPTOR_SET_PTHREAD_NAME(ctx, thread, name)                 \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_BLOCK_REAL(name) REAL(name)
// Strict init-order checking is dlopen-hostile:
// https://github.com/google/sanitizers/issues/178
#define COMMON_INTERCEPTOR_ON_DLOPEN(filename, flag)                           \
  {}
#define COMMON_INTERCEPTOR_ON_EXIT(ctx) OnExit()
#define COMMON_INTERCEPTOR_LIBRARY_LOADED(filename, handle)                    \
  {}
#define COMMON_INTERCEPTOR_LIBRARY_UNLOADED()                                  \
  {}
#define COMMON_INTERCEPTOR_NOTHING_IS_INITIALIZED (!memoro_inited)
#define COMMON_INTERCEPTOR_GET_TLS_RANGE(begin, end)                           \
  if (ThreadContext *t = CurrentThreadContext()) {                             \
    *begin = t->tls_begin();                                                   \
    *end = t->tls_end();                                                       \
  } else {                                                                     \
    *begin = *end = 0;                                                         \
  }

#define COMMON_INTERCEPTOR_MEMMOVE_IMPL(ctx, to, from, size)                   \
  do {                                                                         \
    MEMORO_INTERCEPTOR_ENTER(ctx, memmove);                                    \
    MEMORO_MEMMOVE_IMPL(ctx, to, from, size);                                  \
  } while (false)

#define COMMON_INTERCEPTOR_MEMCPY_IMPL(ctx, to, from, size)                    \
  do {                                                                         \
    MEMORO_INTERCEPTOR_ENTER(ctx, memcpy);                                     \
    MEMORO_MEMCPY_IMPL(ctx, to, from, size);                                   \
  } while (false)

#define COMMON_INTERCEPTOR_MEMSET_IMPL(ctx, block, c, size)                    \
  do {                                                                         \
    MEMORO_INTERCEPTOR_ENTER(ctx, memset);                                     \
    MEMORO_MEMSET_IMPL(ctx, block, c, size);                                   \
  } while (false)

// realpath interceptor does something weird with wrapped malloc on mac OS
#undef SANITIZER_INTERCEPT_REALPATH
#undef SANITIZER_INTERCEPT_TLS_GET_ADDR
#include "sanitizer_common/sanitizer_common_interceptors.inc"

///// Thread initialization and finalization. /////

static unsigned g_thread_finalize_key;

static void thread_finalize(void *v) {
  uptr iter = (uptr)v;
  if (iter > 1) {
    if (pthread_setspecific(g_thread_finalize_key, (void *)(iter - 1))) {
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

extern "C" void *__memoro_thread_start_func(void *arg) {
  ThreadParam *p = (ThreadParam *)arg;
  void *(*callback)(void *arg) = p->callback;
  void *param = p->param;
  // Wait until the last iteration to maximize the chance that we are the last
  // destructor to run.
  if (pthread_setspecific(g_thread_finalize_key,
                          (void *)GetPthreadDestructorIterations())) {
    Report("Memoro: failed to set thread key.\n");
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
  ENSURE_MEMORO_INITED();
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
    // stuart: for memoro this may be an unneeded relic
    ScopedInterceptorDisabler disabler;
    res = REAL(pthread_create)(th, attr, __memoro_thread_start_func, &p);
  }
  if (res == 0) {
    int tid = ThreadCreate(GetCurrentThread(), *(uptr *)th,
                           /*detached == PTHREAD_CREATE_DETACHED*/ false);
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
  ENSURE_MEMORO_INITED();
  u32 tid = ThreadTid((uptr)th);
  int res = REAL(pthread_join)(th, ret);
  if (res == 0)
    ThreadJoin(tid);
  return res;
}
#define MEMORO_READ_STRING_OF_LEN(ctx, s, len, n)                              \
  MEMORO_READ_RANGE((ctx), (s),                                                \
                    common_flags()->strict_string_checks ? (len) + 1 : (n))

#define MEMORO_READ_STRING(ctx, s, n)                                          \
  MEMORO_READ_STRING_OF_LEN((ctx), (s), REAL(strlen)(s), (n))

static inline uptr MaybeRealStrnlen(const char *s, uptr maxlen) {
#if SANITIZER_INTERCEPT_STRNLEN
  if (REAL(strnlen)) {
    return REAL(strnlen)(s, maxlen);
  }
#endif
  return internal_strnlen(s, maxlen);
}

// For both strcat() and strncat() we need to check the validity of |to|
// argument irrespective of the |from| length.
INTERCEPTOR(char *, strcat, char *to, const char *from) { // NOLINT
  void *ctx;
  MEMORO_INTERCEPTOR_ENTER(ctx, strcat); // NOLINT
  ENSURE_MEMORO_INITED();
  if (getFlags()->replace_str) {
    uptr from_length = REAL(strlen)(from);
    MEMORO_READ_RANGE(ctx, from, from_length + 1);
    uptr to_length = REAL(strlen)(to);
    MEMORO_READ_STRING_OF_LEN(ctx, to, to_length, to_length);
    MEMORO_WRITE_RANGE(ctx, to + to_length, from_length + 1);
    // If the copying actually happens, the |from| string should not overlap
    // with the resulting string starting at |to|, which has a length of
    // to_length + from_length + 1.
    if (from_length > 0) {
      CHECK_RANGES_OVERLAP("strcat", to, from_length + to_length + 1, from,
                           from_length + 1);
    }
  }
  return REAL(strcat)(to, from); // NOLINT
}

INTERCEPTOR(char *, strncat, char *to, const char *from, uptr size) {
  void *ctx;
  MEMORO_INTERCEPTOR_ENTER(ctx, strncat);
  ENSURE_MEMORO_INITED();
  if (getFlags()->replace_str) {
    uptr from_length = MaybeRealStrnlen(from, size);
    uptr copy_length = Min(size, from_length + 1);
    MEMORO_READ_RANGE(ctx, from, copy_length);
    uptr to_length = REAL(strlen)(to);
    MEMORO_READ_STRING_OF_LEN(ctx, to, to_length, to_length);
    MEMORO_WRITE_RANGE(ctx, to + to_length, from_length + 1);
    if (from_length > 0) {
      CHECK_RANGES_OVERLAP("strncat", to, to_length + copy_length + 1, from,
                           copy_length);
    }
  }
  return REAL(strncat)(to, from, size);
}

INTERCEPTOR(char *, strcpy, char *to, const char *from) { // NOLINT
  void *ctx;
  MEMORO_INTERCEPTOR_ENTER(ctx, strcpy); // NOLINT
#if SANITIZER_MAC
  if (UNLIKELY(!memoro_inited))
    return REAL(strcpy)(to, from); // NOLINT
#endif
  // strcpy is called from malloc_default_purgeable_zone()
  // in __memoro::ReplaceSystemAlloc() on Mac.
  if (memoro_init_is_running) {
    return REAL(strcpy)(to, from); // NOLINT
  }
  ENSURE_MEMORO_INITED();
  if (getFlags()->replace_str) {
    uptr from_size = REAL(strlen)(from) + 1;
    CHECK_RANGES_OVERLAP("strcpy", to, from_size, from, from_size);
    MEMORO_READ_RANGE(ctx, from, from_size);
    MEMORO_WRITE_RANGE(ctx, to, from_size);
  }
  return REAL(strcpy)(to, from); // NOLINT
}

INTERCEPTOR(char *, strdup, const char *s) {
  void *ctx;
  MEMORO_INTERCEPTOR_ENTER(ctx, strdup);
  if (UNLIKELY(!memoro_inited))
    return internal_strdup(s);
  ENSURE_MEMORO_INITED();
  uptr length = REAL(strlen)(s);
  if (getFlags()->replace_str) {
    MEMORO_READ_RANGE(ctx, s, length + 1);
  }
  GET_STACK_TRACE_MALLOC;
  void *new_mem = memoro_malloc(length + 1, stack);
  MEMORO_WRITE_RANGE(ctx, new_mem, length + 1);
  REAL(memcpy)(new_mem, s, length + 1);
  return reinterpret_cast<char *>(new_mem);
}

#if MEMORO_INTERCEPT___STRDUP
INTERCEPTOR(char *, __strdup, const char *s) {
  void *ctx;
  MEMORO_INTERCEPTOR_ENTER(ctx, strdup);
  if (UNLIKELY(!memoro_inited))
    return internal_strdup(s);
  ENSURE_MEMORO_INITED();
  uptr length = REAL(strlen)(s);
  if (getFlags()->replace_str) {
    MEMORO_READ_RANGE(ctx, s, length + 1);
  }
  GET_STACK_TRACE_MALLOC;
  void *new_mem = memoro_malloc(length + 1, stack);
  REAL(memcpy)(new_mem, s, length + 1);
  return reinterpret_cast<char *>(new_mem);
}
#endif // MEMORO_INTERCEPT___STRDUP

INTERCEPTOR(char *, strncpy, char *to, const char *from, uptr size) {
  void *ctx;
  MEMORO_INTERCEPTOR_ENTER(ctx, strncpy);
  ENSURE_MEMORO_INITED();
  if (getFlags()->replace_str) {
    uptr from_size = Min(size, MaybeRealStrnlen(from, size) + 1);
    CHECK_RANGES_OVERLAP("strncpy", to, from_size, from, from_size);
    MEMORO_READ_RANGE(ctx, from, from_size);
    MEMORO_WRITE_RANGE(ctx, to, size);
  }
  return REAL(strncpy)(to, from, size);
}

INTERCEPTOR(long, strtol, const char *nptr, // NOLINT
            char **endptr, int base) {
  void *ctx;
  MEMORO_INTERCEPTOR_ENTER(ctx, strtol);
  ENSURE_MEMORO_INITED();
  if (!getFlags()->replace_str) {
    return REAL(strtol)(nptr, endptr, base);
  }
  char *real_endptr;
  long result = REAL(strtol)(nptr, &real_endptr, base); // NOLINT
  StrtolFixAndCheck(ctx, nptr, endptr, real_endptr, base);
  return result;
}

INTERCEPTOR(int, atoi, const char *nptr) {
  void *ctx;
  MEMORO_INTERCEPTOR_ENTER(ctx, atoi);
#if SANITIZER_MAC
  if (UNLIKELY(!memoro_inited))
    return REAL(atoi)(nptr);
#endif
  ENSURE_MEMORO_INITED();
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
  MEMORO_READ_STRING(ctx, nptr, (real_endptr - nptr) + 1);
  return result;
}

INTERCEPTOR(long, atol, const char *nptr) { // NOLINT
  void *ctx;
  MEMORO_INTERCEPTOR_ENTER(ctx, atol);
#if SANITIZER_MAC
  if (UNLIKELY(!memoro_inited))
    return REAL(atol)(nptr);
#endif
  ENSURE_MEMORO_INITED();
  if (!getFlags()->replace_str) {
    return REAL(atol)(nptr);
  }
  char *real_endptr;
  long result = REAL(strtol)(nptr, &real_endptr, 10); // NOLINT
  FixRealStrtolEndptr(nptr, &real_endptr);
  MEMORO_READ_STRING(ctx, nptr, (real_endptr - nptr) + 1);
  return result;
}

#if MEMORO_INTERCEPT_ATOLL_AND_STRTOLL
INTERCEPTOR(long long, strtoll, const char *nptr, // NOLINT
            char **endptr, int base) {
  void *ctx;
  MEMORO_INTERCEPTOR_ENTER(ctx, strtoll);
  ENSURE_MEMORO_INITED();
  if (!getFlags()->replace_str) {
    return REAL(strtoll)(nptr, endptr, base);
  }
  char *real_endptr;
  long long result = REAL(strtoll)(nptr, &real_endptr, base); // NOLINT
  StrtolFixAndCheck(ctx, nptr, endptr, real_endptr, base);
  return result;
}

INTERCEPTOR(long long, atoll, const char *nptr) { // NOLINT
  void *ctx;
  MEMORO_INTERCEPTOR_ENTER(ctx, atoll);
  ENSURE_MEMORO_INITED();
  if (!getFlags()->replace_str) {
    return REAL(atoll)(nptr);
  }
  char *real_endptr;
  long long result = REAL(strtoll)(nptr, &real_endptr, 10); // NOLINT
  FixRealStrtolEndptr(nptr, &real_endptr);
  MEMORO_READ_STRING(ctx, nptr, (real_endptr - nptr) + 1);
  return result;
}
#endif // MEMORO_INTERCEPTA_ATOLL_AND_STRTOLL

namespace __memoro {

void InitializeInterceptors() {

  static bool was_called_once;
  CHECK(!was_called_once);
  was_called_once = true;
  InitializeCommonInterceptors();
  // Intercept str* functions.
  MEMORO_INTERCEPT_FUNC(strcat); // NOLINT
  MEMORO_INTERCEPT_FUNC(strcpy); // NOLINT
  MEMORO_INTERCEPT_FUNC(wcslen);
  MEMORO_INTERCEPT_FUNC(strncat);
  MEMORO_INTERCEPT_FUNC(strncpy);
  MEMORO_INTERCEPT_FUNC(strdup);
#if MEMORO_INTERCEPT___STRDUP
  MEMORO_INTERCEPT_FUNC(__strdup);
#endif
#if MEMORO_INTERCEPT_INDEX && MEMORO_USE_ALIAS_ATTRIBUTE_FOR_INDEX
  MEMORO_INTERCEPT_FUNC(index);
#endif

  MEMORO_INTERCEPT_FUNC(atoi);
  MEMORO_INTERCEPT_FUNC(atol);
  MEMORO_INTERCEPT_FUNC(strtol);
#if MEMORO_INTERCEPT_ATOLL_AND_STRTOLL
  MEMORO_INTERCEPT_FUNC(atoll);
  MEMORO_INTERCEPT_FUNC(strtoll);
#endif
  INTERCEPT_FUNCTION(malloc);
  INTERCEPT_FUNCTION(free);
  MEMORO_MAYBE_INTERCEPT_CFREE;
  INTERCEPT_FUNCTION(calloc);
  INTERCEPT_FUNCTION(realloc);
  INTERCEPT_FUNCTION(puts);
  INTERCEPT_FUNCTION(fread);
  INTERCEPT_FUNCTION(fwrite);
  MEMORO_MAYBE_INTERCEPT_MEMALIGN;
  MEMORO_MAYBE_INTERCEPT___LIBC_MEMALIGN;
  MEMORO_MAYBE_INTERCEPT_ALIGNED_ALLOC;
  INTERCEPT_FUNCTION(posix_memalign);
  INTERCEPT_FUNCTION(valloc);
  MEMORO_MAYBE_INTERCEPT_PVALLOC;
  MEMORO_MAYBE_INTERCEPT_MALLOC_USABLE_SIZE;
  MEMORO_MAYBE_INTERCEPT_MALLINFO;
  MEMORO_MAYBE_INTERCEPT_MALLOPT;
  INTERCEPT_FUNCTION(pthread_create);
  INTERCEPT_FUNCTION(pthread_join);

  if (pthread_key_create(&g_thread_finalize_key, &thread_finalize)) {
    Report("Memoro: failed to create thread key.\n");
    Die();
  }
}

} // namespace __memoro
