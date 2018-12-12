//===-- memoro_malloc_mac.cc ----------------------------------------------===//
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
// Mac-specific malloc interception.
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_platform.h"
#if SANITIZER_MAC

#include "memoro.h"
#include "memoro_allocator.h"
#include "memoro_thread.h"

using namespace __memoro;
#define COMMON_MALLOC_ZONE_NAME "memoro"
#define COMMON_MALLOC_ENTER() ENSURE_MEMORO_INITED()
#define COMMON_MALLOC_SANITIZER_INITIALIZED memoro_inited
#define COMMON_MALLOC_FORCE_LOCK()
#define COMMON_MALLOC_FORCE_UNLOCK()
#define COMMON_MALLOC_MEMALIGN(alignment, size)                                \
  GET_STACK_TRACE_MALLOC;                                                      \
  void *p = memoro_memalign(alignment, size, stack)
#define COMMON_MALLOC_MALLOC(size)                                             \
  GET_STACK_TRACE_MALLOC;                                                      \
  void *p = memoro_malloc(size, stack)
#define COMMON_MALLOC_REALLOC(ptr, size)                                       \
  GET_STACK_TRACE_MALLOC;                                                      \
  void *p = memoro_realloc(ptr, size, stack)
#define COMMON_MALLOC_CALLOC(count, size)                                      \
  GET_STACK_TRACE_MALLOC;                                                      \
  void *p = memoro_calloc(count, size, stack)
#define COMMON_MALLOC_POSIX_MEMALIGN(memptr, alignment, size) \
  GET_STACK_TRACE_MALLOC; \
  int res = memoro_posix_memalign(memptr, alignment, size, stack);
#define COMMON_MALLOC_VALLOC(size) \
  GET_STACK_TRACE_MALLOC; \
  void *p = memoro_memalign(GetPageSizeCached(), size, stack);
#define COMMON_MALLOC_FREE(ptr) memoro_free(ptr)
#define COMMON_MALLOC_SIZE(ptr) uptr size = memoro_mz_size(ptr)
#define COMMON_MALLOC_FILL_STATS(zone, stats)
#define COMMON_MALLOC_REPORT_UNKNOWN_REALLOC(ptr, zone_ptr, zone_name)         \
  (void)zone_name;                                                             \
  Report("mz_realloc(%p) -- attempting to realloc unallocated memory.\n", ptr);
#define COMMON_MALLOC_NAMESPACE __memoro

#include "sanitizer_common/sanitizer_malloc_mac.inc"

#endif // SANITIZER_MAC
