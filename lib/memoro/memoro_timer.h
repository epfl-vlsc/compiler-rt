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

namespace __memoro {

u64 get_timestamp();
u64 timestamp_diff(u64 start, u64 end);

} // namespace __memoro

#endif // LLVM_MEMORO_TIMER_H
