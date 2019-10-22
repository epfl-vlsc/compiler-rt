//=-- memoro_timer.h ------------------------------------------------------===//
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
// Code for 64 bit nanosecond timestamps.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_MEMORO_TIMER_H
#define LLVM_MEMORO_TIMER_H

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"

#if SANITIZER_LINUX
#include <x86intrin.h>
#elif SANITIZER_MAC
#include <x86intrin.h>
#endif

namespace __memoro {

inline u64 get_timestamp() { return __rdtsc(); }
inline u64 timestamp_diff(u64 start, u64 end) {
  return end - start;
}

} // namespace __memoro

#endif // LLVM_MEMORO_TIMER_H
