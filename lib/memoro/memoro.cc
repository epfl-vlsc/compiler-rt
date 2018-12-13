//=-- memoro.cc -----------------------------------------------------------===//
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
// Memoro RTL.
//
//===----------------------------------------------------------------------===//

#include "memoro.h"
#include "memoro_allocator.h"
#include "memoro_thread.h"
#include "memoro_timer.h"
#include "sanitizer_common/sanitizer_flag_parser.h"

namespace __memoro {

u64 total_hits = 0;
u64 heap_hits = 0;

// Detect if the memory (Addr) being accessed is on the heap by asking
// the allocator. If it is, get the metadata for that heap chunk
// and update access statistics
void processRangeAccess(uptr PC, uptr Addr, uptr Size, bool IsWrite) {
  /*  VPrintf(3, "in memoro::%s %p: %c %p %d\n", __FUNCTION__, PC,
            IsWrite ? 'w' : 'r', Addr, Size);*/

  total_hits++;
  void *p = (void *)Addr;
  if (PointerIsAllocator(p)) {
    heap_hits++;
    MemoroMetadata m(Addr);
    u64 ts = get_timestamp();
    if (m.first_timestamp() == 0)
      m.set_first_timestamp(ts);

    m.set_latest_timestamp(ts);
    if (IsWrite) {
      m.incr_writes();
    } else {
      m.incr_reads();
    }

    // TODO make optional
    // use uptr for arithmetic
    uptr begin = (uptr)GetBlockBegin(p);
    if (Addr - begin < m.interval_low())
      m.set_interval_low(Addr - begin);
    if (Addr - begin + Size > m.interval_high())
      m.set_interval_high((u32)Addr - begin + Size);

    // this is prob expensive because GetCurrentThread locks
    // TODO make optional
    if (GetCurrentThread() != m.creating_thread()) {
      m.set_multi_thread();
    }
  }
}

} // namespace __memoro
