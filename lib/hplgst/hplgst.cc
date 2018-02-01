//=-- hplgst.cc -------------------------------------------------------------===//
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
// Hplgst RTL.
//
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_flag_parser.h"
#include "hplgst.h"
#include "hplgst_timer.h"
#include "hplgst_allocator.h"
#include "hplgst_thread.h"

namespace __hplgst {

u64 total_hits = 0;
u64 heap_hits = 0;

void processRangeAccess(uptr PC, uptr Addr, uptr Size, bool IsWrite) {
/*  VPrintf(3, "in hplgst::%s %p: %c %p %d\n", __FUNCTION__, PC,
          IsWrite ? 'w' : 'r', Addr, Size);*/

  total_hits++;
  void *p = (void*)Addr;
  if (PointerIsAllocator(p) ) {
    heap_hits++;
    HplgstMetadata m(Addr);
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
      m.set_interval_low(Addr-begin);
    if (Addr-begin+Size > m.interval_high())
      m.set_interval_high((u32)Addr-begin+Size);

    // this is prob too expensive
    // TODO make optional
    /*if (GetCurrentThread() != m.creating_thread()) {
      m.set_multi_thread();
    }*/
  }
}

}  // namespace __hplgst



