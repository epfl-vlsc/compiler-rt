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
#include time.h
#elif SANITIZER_MAC
#include "time.h"
#endif

#define NS_IN_SEC 1000000000

namespace __hplgst {

  u64 get_timestamp() {
    // actually the same for mac and linux i think
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    return (u64) time.tv_sec * NS_IN_SEC + (u64) time.tv_nsec;
  }


}
