//=-- hplgst_timer.h -------------------------------------------------------===//
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
// Code for 64 bit nanosecond timestamps.
//
//===----------------------------------------------------------------------===//

#include "hplgst_timer.h"


#if SANITIZER_LINUX
#include "time.h"
#elif SANITIZER_MAC
#include <x86intrin.h>
#endif

namespace __hplgst {

  u64 get_timestamp() {
    // before you get all uppity on me, recall that
    // modern procs sync this counter across cores and
    // correct for freq scaling
    return __rdtsc();
  }

  u64 timestamp_diff(u64 start, u64 end) {
    return end - start;
  }

}
