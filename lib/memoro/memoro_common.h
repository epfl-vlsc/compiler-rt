//=-- memoro_common.h -------------------------------------------------------===//
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
// Private Memoro header.
//
//===----------------------------------------------------------------------===//

#ifndef MEMORO_COMMON_H
#define MEMORO_COMMON_H

#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_platform.h"
#include "sanitizer_common/sanitizer_stoptheworld.h"
#include "sanitizer_common/sanitizer_symbolizer.h"

namespace __sanitizer {
class FlagParser;
struct DTLS;
}

namespace __memoro {

const u32 kInvalidTid = (u32) -1;

// Platform-specific functions.
void InitializePlatformSpecificModules();

struct RootRegion {
  uptr begin;
  uptr size;
};

enum IgnoreObjectResult {
  kIgnoreObjectSuccess,
  kIgnoreObjectAlreadyIgnored,
  kIgnoreObjectInvalid
};

// Functions called from the parent tool.
void InitCommonMemoro();
void DisableCounterUnderflow();
bool DisabledInThisThread();

// Used to implement __memoro::ScopedDisabler.
void DisableInThisThread();
void EnableInThisThread();
// Can be used to ignore memory allocated by an intercepted
// function.
struct ScopedInterceptorDisabler {
  ScopedInterceptorDisabler() { DisableInThisThread(); }
  ~ScopedInterceptorDisabler() { EnableInThisThread(); }
};

// According to Itanium C++ ABI array cookie is a one word containing
// size of allocated array.
static inline bool IsItaniumABIArrayCookie(uptr chunk_beg, uptr chunk_size,
                                           uptr addr) {
  return chunk_size == sizeof(uptr) && chunk_beg + chunk_size == addr &&
         *reinterpret_cast<uptr *>(chunk_beg) == 0;
}

// According to ARM C++ ABI array cookie consists of two words:
// struct array_cookie {
//   std::size_t element_size; // element_size != 0
//   std::size_t element_count;
// };
static inline bool IsARMABIArrayCookie(uptr chunk_beg, uptr chunk_size,
                                       uptr addr) {
  return chunk_size == 2 * sizeof(uptr) && chunk_beg + chunk_size == addr &&
         *reinterpret_cast<uptr *>(chunk_beg + sizeof(uptr)) == 0;
}

// Special case for "new T[0]" where T is a type with DTOR.
// new T[0] will allocate a cookie (one or two words) for the array size (0)
// and store a pointer to the end of allocated chunk. The actual cookie layout
// varies between platforms according to their C++ ABI implementation.
inline bool IsSpecialCaseOfOperatorNew0(uptr chunk_beg, uptr chunk_size,
                                        uptr addr) {
#if defined(__arm__)
  return IsARMABIArrayCookie(chunk_beg, chunk_size, addr);
#else
  return IsItaniumABIArrayCookie(chunk_beg, chunk_size, addr);
#endif
}

// The following must be implemented in the parent tool.

void ForEachChunk(ForEachChunkCallback callback, void *arg);
// Returns the address range occupied by the global allocator object.
void GetAllocatorGlobalRange(uptr *begin, uptr *end);
// Wrappers for allocator's ForceLock()/ForceUnlock().
void LockAllocator();
void UnlockAllocator();
// Returns true if [addr, addr + sizeof(void *)) is poisoned.
bool WordIsPoisoned(uptr addr);
// Wrappers for ThreadRegistry access.
void LockThreadRegistry();
void UnlockThreadRegistry();
  bool GetThreadRangesLocked(uptr os_id, uptr *stack_begin, uptr *stack_end,
                             uptr *tls_begin, uptr *tls_end, uptr *cache_begin,
                             uptr *cache_end, DTLS **dtls);
void ForEachExtraStackRange(uptr os_id, RangeIteratorCallback callback,
                            void *arg);
// If called from the main thread, updates the main thread's TID in the thread
// registry. We need this to handle processes that fork() without a subsequent
// exec(), which invalidates the recorded TID. To update it, we must call
// gettid() from the main thread. Our solution is to call this function before
// leak checking and also before every call to pthread_create() (to handle cases
// where leak checking is initiated from a non-main thread).
void EnsureMainThreadIDIsCorrect();
// If p points into a chunk that has been allocated to the user, returns its
// user-visible address. Otherwise, returns 0.
uptr PointsIntoChunk(void *p);
// Returns address of user-visible chunk contained in this allocator chunk.
uptr GetUserBegin(uptr chunk);
// Helper for __memoro_ignore_object().
IgnoreObjectResult IgnoreObjectLocked(const void *p);

// Return the linker module, if valid for the platform.
LoadedModule *GetLinker();

// Wrapper for chunk metadata operations.
class MemoroMetadata {
 public:
  // Constructor accepts address of user-visible chunk.
  explicit MemoroMetadata(uptr chunk);
  bool allocated() const;
  uptr requested_size() const;
  u8 num_reads() const;
  u8 num_writes() const;
  void incr_writes();
  void incr_reads();
  u32 stack_trace_id() const;
  u64 timestamp_start() const;
  void set_latest_timestamp(u64 ts);
  void set_first_timestamp(u64 ts);
  u64 first_timestamp();
  u64 latest_timestamp();
  u32 creating_thread();
  void set_multi_thread();
  u32 interval_low() const;
  u32 interval_high() const;
  u8 multi_thread() const;
  u64 alloc_call_time() const;
  void set_interval_low(u32 value);
  void set_interval_high(u32 value);
 //private:
  void *metadata_;
};

}  // namespace __memoro

extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE
int __memoro_is_turned_off();

SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE
const char *__memoro_default_suppressions();
}  // extern "C"

#endif  // MEMORO_COMMON_H
