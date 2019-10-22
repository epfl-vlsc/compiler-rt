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
#include "memoro_flags.h"

#include <alloca.h>

namespace __memoro {

atomic_uint64_t total_hits;

atomic_uint64_t stack_hits;
atomic_uint64_t sample_hits;

atomic_uint64_t primary_hits;
atomic_uint64_t allocators_hits;

atomic_uint64_t primary_time;
atomic_uint64_t allocators_time;
atomic_uint64_t update_time;
atomic_uint64_t filter_time;

// THREADLOCAL is not portable on macOS
/* THREADLOCAL uptr sample_hits_noatomic; */
uptr sample_hits_noatomic;

// Detect if the memory (Addr) being accessed is on the heap by asking
// the allocator. If it is, get the metadata for that heap chunk
// and update access statistics
void processRangeAccess(uptr PC, uptr Addr, uptr Size, bool IsWrite) {
  /*  VPrintf(3, "in memoro::%s %p: %c %p %d\n", __FUNCTION__, PC,
            IsWrite ? 'w' : 'r', Addr, Size);*/

  const int sampling_rate = getFlags()->access_sampling_rate;
  if (UNLIKELY(sampling_rate == 0))
    return;

  MEMORO_METRIC_ADD(total_hits, 1);

  u64 start_filter /* = get_timestamp() */;
  uptr rsp = (uptr)alloca(0);
  if (rsp <= Addr && Addr < GetCurrentStackEnd()) {
    MEMORO_METRIC_ADD(filter_time, get_timestamp() - start_filter);
    MEMORO_METRIC_ADD(stack_hits, 1);
    return;
  }
  MEMORO_METRIC_ADD(filter_time, get_timestamp() - start_filter);

  MEMORO_METRIC_ADD(sample_hits, 1);

  // Sample accesses
  if (LIKELY(sample_hits_noatomic++ % sampling_rate != 0))
    return;

  bool is_primary = true;
  u64 start /* = get_timestamp() */;
  uptr p = (uptr)GetBlockBegin((void*)Addr, &is_primary);
  if (LIKELY(p)) {
    MemoroMetadata m(p);
    u64 ts = get_timestamp();

    MEMORO_METRIC_ADD(allocators_hits, 1);
    MEMORO_METRIC_ADD(allocators_time, ts - start);
    if (LIKELY(is_primary)) {
      MEMORO_METRIC_ADD(primary_hits, 1);
      MEMORO_METRIC_ADD(primary_time, ts - start);
    }

    if (UNLIKELY(m.first_timestamp() == 0))
      m.set_first_timestamp(ts);

    m.set_latest_timestamp(ts);
    if (IsWrite) {
      m.incr_writes();
    } else {
      m.incr_reads();
    }

    // TODO make optional
    // use uptr for arithmetic
    uptr begin = (uptr)p;
    if (Addr - begin < m.interval_low())
      m.set_interval_low(Addr - begin);
    if (Addr - begin + Size > m.interval_high())
      m.set_interval_high((u32)Addr - begin + Size);

    // this is prob expensive because GetCurrentThread locks
    // TODO make optional
    if (UNLIKELY(getFlags()->register_multi_thread && GetCurrentThread() != m.creating_thread())) {
      m.set_multi_thread();
    }

    return;
  }
  MEMORO_METRIC_ADD(update_time, get_timestamp() - start);
}

void checkStackAccess(void* Addr) {
  if (getFlags()->check_stack_accesses)
    CHECK(GetBlockBegin(Addr, nullptr) == nullptr);
}

} // namespace __memoro
