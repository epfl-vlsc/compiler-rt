//=-- memoro_linux.cc -----------------------------------------------------===//
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
// Linux-specific malloc interception..
//
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_platform.h"

#if SANITIZER_LINUX

#include "memoro_allocator.h"

namespace __memoro {

static THREADLOCAL u32 current_thread_tid = kInvalidTid;
u32 GetCurrentThread() { return current_thread_tid; }
void SetCurrentThread(u32 tid) { current_thread_tid = tid; }

static THREADLOCAL AllocatorCache allocator_cache;
AllocatorCache *GetAllocatorCache() { return &allocator_cache; }

void ReplaceSystemMalloc() {}

} // namespace __memoro

#endif // SANITIZER_LINUX
