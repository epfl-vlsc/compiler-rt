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

namespace __hplgst {

void processRangeAccess(uptr PC, uptr Addr, uptr Size, bool IsWrite) {
  /*VPrintf(3, "in hplgst::%s %p: %c %p %d\n", __FUNCTION__, PC,
          IsWrite ? 'w' : 'r', Addr, Size);*/

  void *p = (void*)Addr;
  if (PointerIsAllocator(p) ) {
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
  }
}

}  // namespace __hplgst



