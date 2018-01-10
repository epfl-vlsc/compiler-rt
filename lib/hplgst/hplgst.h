//=-- hplgst.h --------------------------------------------------------------===//
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
// Private header for Hplgst RTL.
//
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "hplgst_interface_internal.h"

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

#define GET_STACK_TRACE_FATAL \
  GET_STACK_TRACE(kStackTraceMax, common_flags()->fast_unwind_on_fatal)

#define GET_STACK_TRACE_MALLOC                                      \
  GET_STACK_TRACE(common_flags()->malloc_context_size, \
                  common_flags()->fast_unwind_on_malloc)

namespace __hplgst {

void InitializeInterceptors();

void ReplaceSystemMalloc();

void processRangeAccess(uptr PC, uptr Addr, uptr Size, bool IsWrite);

#define ENSURE_HPLGST_INITED() do {   \
  CHECK(!hplgst_init_is_running);   \
  if (!hplgst_inited)               \
    __hplgst_init((ToolType)0, nullptr);                \
} while (0)

  extern u64 total_hits;
  extern u64 heap_hits;
}  // namespace __hplgst

extern bool hplgst_inited;
extern bool hplgst_init_is_running;