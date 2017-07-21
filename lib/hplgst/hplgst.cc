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
// Standalone Hplgst RTL.
//
//===----------------------------------------------------------------------===//



#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "hplgst.h"
#include "hplgst_flags.h"
#include "hplgst_allocator.h"



namespace __hplgst {

void processRangeAccess(uptr PC, uptr Addr, int Size, bool IsWrite) {
  Printf("in hplgst::%s %p: %c %p %d\n", __FUNCTION__, PC,
          IsWrite ? 'w' : 'r', Addr, Size);

  void *p = (void*)Addr;
  // test if pointer owned by allocator and then process
  if (PointerIsAllocator(p) ) {
    HplgstMetadata m(Addr);
    if (IsWrite) {
      m.incr_writes();
    } else {
      m.incr_reads();
    }

  }
}


}  // namespace __hplgst



