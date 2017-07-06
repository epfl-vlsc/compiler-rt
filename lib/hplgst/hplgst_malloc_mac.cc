//===-- hplgst_malloc_mac.cc ------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of LeakSanitizer (LSan), a memory leak detector.
//
// Mac-specific malloc interception.
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_platform.h"
#if SANITIZER_MAC

#include "hplgst.h"
#include "hplgst_allocator.h"
#include "hplgst_thread.h"

using namespace __hplgst;
#define COMMON_MALLOC_ZONE_NAME "hplgst"
#define COMMON_MALLOC_ENTER() ENSURE_HPLGST_INITED
#define COMMON_MALLOC_SANITIZER_INITIALIZED hplgst_inited
#define COMMON_MALLOC_FORCE_LOCK()
#define COMMON_MALLOC_FORCE_UNLOCK()
#define COMMON_MALLOC_MEMALIGN(alignment, size) \
  GET_STACK_TRACE_MALLOC; \
  void *p = hplgst_memalign(alignment, size, stack)
#define COMMON_MALLOC_MALLOC(size) \
  GET_STACK_TRACE_MALLOC; \
  void *p = hplgst_malloc(size, stack)
#define COMMON_MALLOC_REALLOC(ptr, size) \
  GET_STACK_TRACE_MALLOC; \
  void *p = hplgst_realloc(ptr, size, stack)
#define COMMON_MALLOC_CALLOC(count, size) \
  GET_STACK_TRACE_MALLOC; \
  void *p = hplgst_calloc(count, size, stack)
#define COMMON_MALLOC_VALLOC(size) \
  GET_STACK_TRACE_MALLOC; \
  void *p = hplgst_valloc(size, stack)
#define COMMON_MALLOC_FREE(ptr) \
  hplgst_free(ptr)
#define COMMON_MALLOC_SIZE(ptr) \
  uptr size = hplgst_mz_size(ptr)
#define COMMON_MALLOC_FILL_STATS(zone, stats)
#define COMMON_MALLOC_REPORT_UNKNOWN_REALLOC(ptr, zone_ptr, zone_name) \
  (void)zone_name; \
  Report("mz_realloc(%p) -- attempting to realloc unallocated memory.\n", ptr);
#define COMMON_MALLOC_NAMESPACE __hplgst

#include "sanitizer_common/sanitizer_malloc_mac.inc"

#endif // SANITIZER_MAC
