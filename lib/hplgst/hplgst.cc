//=-- hplgst.cc -------------------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of LeakSanitizer.
// Standalone LSan RTL.
//
//===----------------------------------------------------------------------===//



#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "hplgst.h"



namespace __hplgst {

  using namespace __sanitizer;

void processRangeAccess(uptr PC, uptr Addr, int Size, bool IsWrite) {
  VPrintf(3, "in hplgst::%s %p: %c %p %d\n", __FUNCTION__, PC,
          IsWrite ? 'w' : 'r', Addr, Size);

  // test if pointer owned by allocator and then process
}

}  // namespace __hplgst



