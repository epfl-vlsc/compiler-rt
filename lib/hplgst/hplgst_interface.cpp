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
  }
}

// a ForEachStackTrace callback
void FindUnusedAllocsCb(HplgstStackDepotHandle& handle, void* arg) {

  // tally total reads and writes to chunks produced by this alloc point
  // we try to find points that produce basically unused allocs

  // don't include stack traces that don't originate from main()
  if (!handle.TraceHasMain()) {
    //Printf("Trace does not have main()\n");
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

    Printf("---------- Allocation Point: ----------\n");
    handle.trace().Print();
    if (total_writes > 0)
      Printf("Produces write-only chunks:\n");
    else if (total_reads > 0)
      Printf("Produces read-only chunks:\n");
    else
      Printf("Produces totally unused chunks (but may be from un-instrumented code):\n");
    Printf("Total chunks from this allocation point: %d\n", handle.total_chunks());
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
  //Printf("INIT meta size is %d\n", sizeof(ChunkMetadata));
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
  /*Printf("about to lock T\n");
  LockThreadRegistry();
  Printf("about to lock A\n");
  LockAllocator();
  Printf("getting allocator\n");
  uptr s = get_allocator()->TotalMemoryUsed();
  Printf("total memory: %d\n", s);

  int chunkcount = 0;
  ForEachChunk(TestCb, &chunkcount);
  Printf("num chunks %d\n", chunkcount);

  UnlockAllocator();
  UnlockThreadRegistry();*/

  hplgst_inited = true;
  hplgst_init_is_running = false;
  /*u64 t = get_timestamp();
  Printf("init ts %lld\n", t);*/
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_print_stack_trace() {
  GET_STACK_TRACE_FATAL;
  stack.Print();
}

void __hplgst_exit(void *Ptr) {
  // TODO anything to do here?
  //Printf("Exiting!\n");
  LockThreadRegistry();
  LockAllocator();

  // add remaining still-allocated chunks to the stack depot
  // structure, use program end as the end timestamp
  u64 end_ts = get_timestamp();
  ForEachChunk(AddStillAllocatedCb, &end_ts);

  HplgstStackDepot_ForEachStackTrace(FindUnusedAllocsCb, nullptr);

  UnlockAllocator();
  UnlockThreadRegistry();

  // TODO
  // update stacktrace mappings with info from still-allocated chunks

  //processCompilationUnitExit(Ptr);
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
