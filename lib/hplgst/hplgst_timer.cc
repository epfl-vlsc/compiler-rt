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
#include <x86intrin.h>
#elif SANITIZER_MAC
#include <mach/mach_time.h>
#include <x86intrin.h>

#endif

#define NS_IN_SEC 1000000000

namespace __hplgst {

  u64 get_timestamp() {
    return __rdtsc();
/*#if SANITIZER_LINUX
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    return (u64) time.tv_sec * NS_IN_SEC + (u64) time.tv_nsec;
#elif SANITIZER_MAC
    return mach_absolute_time();
#else
    return 0;
#endif*/

  }

  u64 timestamp_diff(u64 start, u64 end) {
/*#if SANITIZER_MAC
    static mach_timebase_info_data_t sTimebaseInfo;
    if ( sTimebaseInfo.denom == 0 ) {
      (void) mach_timebase_info(&sTimebaseInfo);
    }
    u64 elapsed = end - start;
    return elapsed * sTimebaseInfo.numer / sTimebaseInfo.denom;
#elif SANITIZER_LINUX
    return end - start;
#else
    return 0;
#endif*/
    return end - start;
  }

}
