//===-- hplgst_interface.cpp ------------------------------------------------===//
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
//===----------------------------------------------------------------------===//

#include "hplgst_interface_internal.h"
#include "hplgst_stackdepot.h"
#include "hplgst_common.h"
#include "hplgst.h"
#include "hplgst_flags.h"
#include "hplgst_allocator.h"
#include "hplgst_thread.h"
#include "hplgst_timer.h"

bool hplgst_inited;
bool hplgst_init_is_running;

using namespace __hplgst; // NOLINT

// a ForEachChunk callback
void AddStillAllocatedCb(uptr chunk, void *arg) {

  u64 end_ts = *(u64*)arg;
  chunk = GetUserBegin(chunk);
  HplgstMetadata m(chunk); // in the end calls allocator.getMetadata(chunk)
  // at the end, we only care about chunks that are still allocated
  if (m.allocated()) {
    //Printf("ptr %llx, meta %llx, allocated %llu, req size %x, trace id %x \n", chunk, m.metadata_, m.allocated(), m.requested_size(), m.stack_trace_id());
    HplgstStackDepotHandle handle = HplgstStackDepotGetHandle(m.stack_trace_id());
    HplgstMemoryChunk& chunk = handle.new_chunk();
    chunk.allocated = 1;
    chunk.timestamp_start = m.timestamp_start();
    chunk.timestamp_end = end_ts;
    chunk.size = m.requested_size();
    chunk.num_writes = m.num_writes();
    chunk.num_reads = m.num_reads();
    chunk.timestamp_first_access = m.first_timestamp();
    chunk.timestamp_last_access = m.latest_timestamp();
  }
}

// TODO make editable from cmd line
#define REALLOC_INCREASE_RUN_MIN 3

struct FindReallocsMeta {
  u64 last_size = 0;
  u32 current_run = 0;
  u32 longest_run = 0;
};

// a ForEachStackTrace callback
void FindBadReallocsCb(HplgstStackDepotHandle& handle, void* arg) {

  // find instances where chunk size from the same allocation point
  // continually increase --> implying an up front, large allocation
  // would be better
  // we allow for multiple "runs" because the allocation point could be
  // in a loop

  // don't include stack traces that don't originate from main()
  if (!handle.TraceHasMain()) {
    return;
  }

  FindReallocsMeta meta;
  handle.ForEachChunk([](HplgstMemoryChunk& chunk, void* arg){
    FindReallocsMeta* cur = (FindReallocsMeta*) arg;
    if (cur->last_size == 0) {
      cur->last_size = chunk.size;
      cur->current_run++;
      return;
    }
    if (chunk.size > cur->last_size) {
      cur->last_size = chunk.size;
      cur->current_run++;
    } else {
      cur->longest_run = cur->current_run > cur->longest_run ? cur->current_run : cur->longest_run;
      cur->current_run = 0;
      cur->last_size = chunk.size;
    }
  }, &meta);

  if (meta.longest_run >= REALLOC_INCREASE_RUN_MIN) {
    handle.add_inefficiency(Inefficiency::IncreasingReallocs);
  }
}
// a ForEachStackTrace callback
void FindEarlyAllocLateFreeCb(HplgstStackDepotHandle& handle, void* arg) {

  // find instances where the first access is over half the lifetime
  // of the chunk

  // don't include stack traces that don't originate from main()
  if (!handle.TraceHasMain()) {
    return;
  }

  bool has_early_alloc = false;
  handle.ForEachChunk([](HplgstMemoryChunk& chunk, void* arg){
    if (chunk.timestamp_first_access - chunk.timestamp_start >
            (chunk.timestamp_end - chunk.timestamp_start) / 2) {
      bool* has_early = (bool*) arg;
      *has_early = true;
    }
  }, &has_early_alloc);

  bool has_late_free = false;
  handle.ForEachChunk([](HplgstMemoryChunk& chunk, void* arg){
    if (chunk.timestamp_end - chunk.timestamp_last_access >
        (chunk.timestamp_end - chunk.timestamp_start) / 2) {
      bool* has_late = (bool*) arg;
      *has_late = true;
    }
  }, &has_late_free);

  if (has_early_alloc) {
    handle.add_inefficiency(Inefficiency::EarlyAlloc);
  }
  if (has_late_free) {
    handle.add_inefficiency(Inefficiency::LateFree);
  }
}

// a ForEachStackTrace callback
void FindUnusedAllocsCb(HplgstStackDepotHandle& handle, void* arg) {

  // tally total reads and writes to chunks produced by this alloc point
  // we try to find points that produce basically unused allocs

  // don't include stack traces that don't originate from main()
  if (!handle.TraceHasMain()) {
    return;
  }

  int total_reads = 0, total_writes = 0;
  handle.ForEachChunk([](HplgstMemoryChunk& chunk, void* arg){
    int* r = (int*)arg;
    *r += (int) chunk.num_reads;
  }, &total_reads);
  handle.ForEachChunk([](HplgstMemoryChunk& chunk, void* arg){
    int* w = (int*)arg;
    *w += (int) chunk.num_writes;
  }, &total_writes);

  if (total_reads == 0 || total_writes == 0) {
    if (total_writes > 0) {
      handle.add_inefficiency(Inefficiency::WriteOnly);
    } else if (total_reads > 0) {
      handle.add_inefficiency(Inefficiency::ReadOnly);
    } else {
      handle.add_inefficiency(Inefficiency::Unused);
    }
  }

}

// TODO could make this relative to actual program lifetime?
#define BAD_LIFETIME_MIN 1000000  // 1 millisecond

// a ForEachStackTrace callback
void FindShortLifetimeAllocs(HplgstStackDepotHandle& handle, void* arg) {

  // Currently flags an allocation point that produces *any* short
  // lived chunks

  // don't include stack traces that don't originate from main()
  // TODO do this once and filter them up front
  if (!handle.TraceHasMain()) {
    return;
  }

  u64 min_lifetime = UINT64_MAX;
  handle.ForEachChunk([](HplgstMemoryChunk& chunk, void* arg){
    u64* cur_min = (u64*)arg;
    u64 lifetime = timestamp_diff(chunk.timestamp_start, chunk.timestamp_end);
    if (lifetime < *cur_min)
      *cur_min = lifetime;
  }, &min_lifetime);

  if (min_lifetime < BAD_LIFETIME_MIN) {
    handle.add_inefficiency(Inefficiency::ShortLifetime);
  }

}

// a ForEachStackTrace callback
void PrintCollectedStats(HplgstStackDepotHandle& handle, void* arg) {
  if (handle.has_inefficiencies()) {
    Printf("---------- Allocation Point: ----------\n");
    handle.trace().Print();
    if (handle.has_inefficiency(Inefficiency::Unused))
      Printf("--> Produces totally unused chunks (but may be from un-instrumented code)\n");
    if (handle.has_inefficiency(Inefficiency::ReadOnly))
      Printf("--> Produces read-only chunks\n");
    if (handle.has_inefficiency(Inefficiency::WriteOnly))
      Printf("--> Produces write-only chunks\n");
    if (handle.has_inefficiency(Inefficiency::ShortLifetime))
      Printf("--> Allocates chunks with very short lifetimes ( < %lld ms )\n", BAD_LIFETIME_MIN/1000000);
    if (handle.has_inefficiency(Inefficiency::EarlyAlloc))
      Printf("--> Allocates chunks early (first access after half of lifetime)\n");
    if (handle.has_inefficiency(Inefficiency::LateFree))
      Printf("--> Free chunks late (last access less than half of lifetime)\n");
    if (handle.has_inefficiency(Inefficiency::IncreasingReallocs))
      Printf("--> Has increasing allocation size patterns (did you put an alloc in a loop?)\n");

    // TODO if some verbose level output the individual chunks
    handle.ForEachChunk([](HplgstMemoryChunk& chunk, void* arg){
      Printf("Chunk: Size: %d, Reads: %d, Writes: %d, Lifetime: %lld, WasAllocated: %d\n",
             chunk.size, chunk.num_reads, chunk.num_writes,
             timestamp_diff(chunk.timestamp_start, chunk.timestamp_end), chunk.allocated);
    }, arg);
    Printf("---------------------------------------\n");

  }
}


extern "C" void __hplgst_init(ToolType Tool, void *Ptr) {
  CHECK(!hplgst_init_is_running);
  if (hplgst_inited)
    return;
  hplgst_init_is_running = true;
  SanitizerToolName = "Heapologist";
  CacheBinaryName();
  AvoidCVE_2016_2143();
  InitializeFlags();
  InitCommonHplgst();
  InitializeAllocator();
  ReplaceSystemMalloc();
  InitTlsSize();
  InitializeInterceptors();
  InitializeThreadRegistry();
  u32 tid = ThreadCreate(0, 0, true);
  CHECK_EQ(tid, 0);
  ThreadStart(tid, GetTid());
  SetCurrentThread(tid);

  //InitializeCoverage(common_flags()->coverage, common_flags()->coverage_dir);

  hplgst_inited = true;
  hplgst_init_is_running = false;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_print_stack_trace() {
  GET_STACK_TRACE_FATAL;
  stack.Print();
}

void __hplgst_exit(void *Ptr) {
  LockThreadRegistry();
  LockAllocator();

  // add remaining still-allocated chunks to the stack depot
  // structure, use program end as the end timestamp
  u64 end_ts = get_timestamp();
  ForEachChunk(AddStillAllocatedCb, &end_ts);

  // run all the different analyses across the different allocation
  // point stack traces
  // TODO add args to enable / disable individual analyses
  HplgstStackDepot_SortAllChunkVectors();
  HplgstStackDepot_ForEachStackTrace(FindUnusedAllocsCb, nullptr);
  HplgstStackDepot_ForEachStackTrace(FindShortLifetimeAllocs, nullptr);
  HplgstStackDepot_ForEachStackTrace(FindEarlyAllocLateFreeCb, nullptr);
  HplgstStackDepot_ForEachStackTrace(FindBadReallocsCb, nullptr);
  HplgstStackDepot_ForEachStackTrace(PrintCollectedStats, nullptr);

  UnlockAllocator();
  UnlockThreadRegistry();
}

void __hplgst_aligned_load1(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 1, false);
}

void __hplgst_aligned_load2(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 2, false);
}

void __hplgst_aligned_load4(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 4, false);
}

void __hplgst_aligned_load8(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 8, false);
}

void __hplgst_aligned_load16(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 16, false);
}

void __hplgst_aligned_store1(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 1, true);
}

void __hplgst_aligned_store2(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 2, true);
}

void __hplgst_aligned_store4(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 4, true);
}

void __hplgst_aligned_store8(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 8, true);
}

void __hplgst_aligned_store16(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 16, true);
}

void __hplgst_unaligned_load2(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 2, false);
}

void __hplgst_unaligned_load4(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 4, false);
}

void __hplgst_unaligned_load8(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 8, false);
}

void __hplgst_unaligned_load16(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 16, false);
}

void __hplgst_unaligned_store2(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 2, true);
}

void __hplgst_unaligned_store4(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 4, true);
}

void __hplgst_unaligned_store8(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 8, true);
}

void __hplgst_unaligned_store16(void *Addr) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, 16, true);
}

void __hplgst_unaligned_loadN(void *Addr, uptr Size) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, Size, false);
}

void __hplgst_unaligned_storeN(void *Addr, uptr Size) {
  processRangeAccess(GET_CALLER_PC(), (uptr)Addr, Size, true);
}

// Public interface:
extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_report() {

  //reportResults();
}

SANITIZER_INTERFACE_ATTRIBUTE unsigned int __hplgst_get_sample_count() {
  return 0;
}
} // extern "C"
