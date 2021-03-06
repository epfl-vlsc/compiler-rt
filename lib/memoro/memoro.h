//=-- memoro.h ------------------------------------------------------------===//
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
// Private header for Memoro RTL.
//
//===----------------------------------------------------------------------===//

#include "memoro_interface_internal.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_atomic.h"

#define GET_STACK_TRACE(max_size, fast)                                        \
  BufferedStackTrace stack;                                                    \
  {                                                                            \
    uptr stack_top = 0, stack_bottom = 0;                                      \
    ThreadContext *t;                                                          \
    if (fast && (t = CurrentThreadContext())) {                                \
      stack_top = t->stack_end();                                              \
      stack_bottom = t->stack_begin();                                         \
    }                                                                          \
    if (!SANITIZER_MIPS ||                                                     \
        IsValidFrame(GET_CURRENT_FRAME(), stack_top, stack_bottom)) {          \
      stack.Unwind(max_size, StackTrace::GetCurrentPc(), GET_CURRENT_FRAME(),  \
                   /* context */ 0, stack_top, stack_bottom, fast);            \
    }                                                                          \
  }

#define GET_STACK_TRACE_FATAL                                                  \
  GET_STACK_TRACE(kStackTraceMax, common_flags()->fast_unwind_on_fatal)

#define GET_STACK_TRACE_MALLOC                                                 \
  GET_STACK_TRACE(common_flags()->malloc_context_size,                         \
                  common_flags()->fast_unwind_on_malloc)

namespace __memoro {

void InitializeInterceptors();

void ReplaceSystemMalloc();

void processRangeAccess(uptr PC, uptr Addr, uptr Size, bool IsWrite);
void checkStackAccess(void *Addr);

#define ENSURE_MEMORO_INITED()                                                 \
  do {                                                                         \
    CHECK(!memoro_init_is_running);                                            \
    if (!memoro_inited)                                                        \
      __memoro_init();                                                         \
  } while (0)

extern atomic_uint64_t total_hits;
extern atomic_uint64_t stack_hits;
extern atomic_uint64_t sample_hits;
extern atomic_uint64_t primary_hits;
extern atomic_uint64_t allocators_hits;
extern atomic_uint64_t primary_time;
extern atomic_uint64_t allocators_time;
extern atomic_uint64_t update_time;
extern atomic_uint64_t filter_time;

/* #define MEMORO_METRICS */

#ifdef MEMORO_METRICS
#define MEMORO_METRIC_ADD(atomic_var, val) (atomic_fetch_add(&(atomic_var), (val), memory_order_relaxed))
#define MEMORO_METRIC_TIME() (get_timestamp())
#else
#define MEMORO_METRIC_ADD(atomic_var, val)
#define MEMORO_METRIC_TIME() (0)
#endif
} // namespace __memoro

extern bool memoro_inited;
extern bool memoro_init_is_running;
