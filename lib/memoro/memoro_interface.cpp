//===-- memoro_interface.cpp ----------------------------------------------===//
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
//===----------------------------------------------------------------------===//

#include "memoro.h"
#include "memoro_allocator.h"
#include "memoro_common.h"
#include "memoro_flags.h"
#include "memoro_interface_internal.h"
#include "memoro_stackdepot.h"
#include "memoro_thread.h"
#include "memoro_timer.h"
#include "memoro_tracewriter.h"

bool memoro_inited = false;
bool memoro_init_is_running = false;

using namespace __memoro; // NOLINT

// a ForEachChunk callback
void AddStillAllocatedCb(__sanitizer::uptr chunk, void *arg) {

  __sanitizer::u64 end_ts = *(__sanitizer::u64 *)arg;
  MemoroMetadata m(chunk);
  // at the end, we only care about chunks that are still allocated
  if (m.allocated()) {
    MemoroStackAndChunks sl = MemoroStackDepotGet(m.stack_trace_id());
    MemoroMemoryChunk newchunk;
    newchunk.allocated = 1;
    newchunk.timestamp_start = m.timestamp_start();
    newchunk.timestamp_end = end_ts;
    newchunk.size = m.requested_size();
    newchunk.num_writes = m.num_writes();
    newchunk.num_reads = m.num_reads();
    newchunk.timestamp_first_access = m.first_timestamp();
    newchunk.timestamp_last_access = m.latest_timestamp();
    newchunk.alloc_call_time = m.alloc_call_time();
    newchunk.multi_thread = m.multi_thread();
    newchunk.access_interval_low = m.interval_low();
    newchunk.access_interval_high = m.interval_high();
    /* sl.chunks->push_back(newchunk); */
    sl.PushChunk(newchunk);
  }
}

void TallyAllocationPoint(const MemoroStackAndChunks &sc, void *arg) {
  auto vec = (InternalMmapVector<MemoroStackAndChunks> *)arg;
  vec->push_back(sc);
}

// start timestamp to get relative chunk lifetimes
static __sanitizer::u64 memoro_start;
extern "C" { void __memoro_report(); }
static void OnExit() {
  Flags *flags = getFlags();
  if (flags->no_output)
    return;

  // Make sure we don't collect data anymore as
  // the symbolizer can be compiled with Memoro
  flags->register_allocs = false;
  flags->access_sampling_rate = 0;

  // add remaining still-allocated chunks to the stack depot
  // structure, use program end as the end timestamp
  __sanitizer::u64 end_ts = get_timestamp();
  ForEachChunk(AddStillAllocatedCb, &end_ts);

  // sorting may not be necessary, considering removing
  MemoroStackDepot_SortAllChunkVectors();

  // making a copy of stack trace handles, pointed-to data
  // is not duplicated
  InternalMmapVector<MemoroStackAndChunks> all_alloc_points;
  MemoroStackDepot_ForEachStackTrace(TallyAllocationPoint, &all_alloc_points);

  __sanitizer::u64 trace_count = all_alloc_points.size();
  __sanitizer::u64 chunk_count = 0;
  for (const auto& alloc_point : all_alloc_points)
    chunk_count += alloc_point.chunks->size();

  if (trace_count == 0 || chunk_count == 0) {
    Printf("Memoro: no profile collected!\n");
    return;
  }

  // write all alloc points and chunks to file
  const __sanitizer::uptr buflen = 2 * 1024 * 1024; // 2MiB because i dont care
  char *buf = new char[buflen];
  TraceWriter writer(trace_count, chunk_count);

  for (uptr i = 0; i < all_alloc_points.size(); i++) {
    const MemoroStackAndChunks &alloc_point = all_alloc_points[i];
    alloc_point.st.SPrint(buf, buflen, "#%n %p %F %L|");

    writer.WriteTrace(buf);

    for (auto &chunk : *alloc_point.chunks) {
      chunk.stack_index = i;
      chunk.timestamp_start = chunk.timestamp_start - memoro_start;
      chunk.timestamp_end = chunk.timestamp_end - memoro_start;
      chunk.timestamp_first_access = chunk.timestamp_first_access > 0
          ? chunk.timestamp_first_access - memoro_start : 0;
      chunk.timestamp_last_access = chunk.timestamp_last_access > 0
          ? chunk.timestamp_last_access - memoro_start : 0;
      if (chunk.access_interval_high != 0 &&
          chunk.access_interval_high - chunk.access_interval_low > chunk.size)
        Printf("WARNING: chunk had access interval larger than size\n");
      // Clear 0xffffffff from chunk.access_interval_low if there was no read
      if (chunk.num_reads == 0 && chunk.num_writes == 0)
        chunk.access_interval_low = chunk.access_interval_high = 0;

      writer.WriteChunk(chunk);
    }
  }

  delete[] buf;

  if (!writer.OutputFiles())
    Printf("Error writing trace or chunk files!\n");
}

extern "C" void __memoro_init() {
  CHECK(!memoro_init_is_running);
  if (memoro_inited)
    return;
  memoro_init_is_running = true;
  SanitizerToolName = "Memoro";
  CacheBinaryName();
  AvoidCVE_2016_2143();
  InitializeFlags();
  InitializeAllocator();
  InitializeDepotLock();
  ReplaceSystemMalloc();
  InitTlsSize();
  InitializeInterceptors();
  InitializeThreadRegistry();
  __sanitizer::u32 tid = ThreadCreate(0, 0, true);
  CHECK_EQ(tid, 0);
  ThreadStart(tid, GetTid());
  SetCurrentThread(tid);
  Atexit(OnExit);
  memoro_start = get_timestamp();

  memoro_inited = true;
  memoro_init_is_running = false;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __sanitizer_print_stack_trace() {
  GET_STACK_TRACE_FATAL;
  stack.Print();
}

void __memoro_exit() {}

void __memoro_aligned_load1(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 1, false);
}

void __memoro_aligned_load2(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 2, false);
}

void __memoro_aligned_load4(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 4, false);
}

void __memoro_aligned_load8(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 8, false);
}

void __memoro_aligned_load16(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 16, false);
}

void __memoro_aligned_store1(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 1, true);
}

void __memoro_aligned_store2(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 2, true);
}

void __memoro_aligned_store4(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 4, true);
}

void __memoro_aligned_store8(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 8, true);
}

void __memoro_aligned_store16(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 16, true);
}

void __memoro_unaligned_load2(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 2, false);
}

void __memoro_unaligned_load4(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 4, false);
}

void __memoro_unaligned_load8(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 8, false);
}

void __memoro_unaligned_load16(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 16, false);
}

void __memoro_unaligned_store2(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 2, true);
}

void __memoro_unaligned_store4(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 4, true);
}

void __memoro_unaligned_store8(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 8, true);
}

void __memoro_unaligned_store16(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, 16, true);
}

void __memoro_unaligned_loadN(void *Addr, __sanitizer::uptr Size) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, Size, false);
}

void __memoro_unaligned_storeN(void *Addr, __sanitizer::uptr Size) {
  processRangeAccess(GET_CALLER_PC(), (__sanitizer::uptr)Addr, Size, true);
}

void __memoro_check_stack(void *Addr) {
  checkStackAccess(Addr);
}

// Public interface:
// stuart: these can probably be removed
extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE void __memoro_report() {
  Printf("=== MEMORO REPORT ===\n");
  Printf("Total hits: %zd\n", atomic_load_relaxed(&total_hits));
  Printf("Stack/Sample hits: %zd/%zd\n", atomic_load_relaxed(&stack_hits), atomic_load_relaxed(&sample_hits));
  Printf("Primary/Allocators hits: %zd/%zd\n", atomic_load_relaxed(&primary_hits), atomic_load_relaxed(&allocators_hits));
  Printf("Primary/Allocators time: %zd/%zd\n", atomic_load_relaxed(&primary_time), atomic_load_relaxed(&allocators_time));
  Printf("Total update time: %zd\n", atomic_load_relaxed(&update_time));
  Printf("Filter time: %zd\n", atomic_load_relaxed(&filter_time));
  PrintStats();
}

SANITIZER_INTERFACE_ATTRIBUTE unsigned int __memoro_get_sample_count() {
  return 0;
}

SANITIZER_INTERFACE_ATTRIBUTE Flags* __memoro_get_flags() { return getFlags(); }
} // extern "C"
