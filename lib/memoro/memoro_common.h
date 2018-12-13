//=-- memoro_common.h -----------------------------------------------------===//
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
} // namespace __sanitizer

namespace __memoro {

const u32 kInvalidTid = (u32)-1;

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
void DisableCounterUnderflow();
bool DisabledInThisThread();

// Used to implement __memoro::ScopedDisabler.
// stuart: not sure if this is needed anymore
void DisableInThisThread();
void EnableInThisThread();
// Can be used to ignore memory allocated by an intercepted
// function.
struct ScopedInterceptorDisabler {
  ScopedInterceptorDisabler() { DisableInThisThread(); }
  ~ScopedInterceptorDisabler() { EnableInThisThread(); }
};

void ForEachChunk(ForEachChunkCallback callback, void *arg);
// Returns the address range occupied by the global allocator object.
void GetAllocatorGlobalRange(uptr *begin, uptr *end);
// Wrappers for allocator's ForceLock()/ForceUnlock().
void LockAllocator();
void UnlockAllocator();
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
// Returns address of user-visible chunk contained in this allocator chunk.
uptr GetUserBegin(uptr chunk);

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
  // private:
  void *metadata_;
};

} // namespace __memoro

// stuart: Not sure if these are needed
extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE int
__memoro_is_turned_off();

SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE const char *
__memoro_default_suppressions();
} // extern "C"

#endif // MEMORO_COMMON_H
