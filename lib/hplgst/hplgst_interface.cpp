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
#include "hplgst_tracewriter.h"

bool hplgst_inited;
bool hplgst_init_is_running;

using namespace __hplgst; // NOLINT

// a ForEachChunk callback
void AddStillAllocatedCb(uptr chunk, void *arg) {

  u64 end_ts = *(u64*)arg;
  chunk = GetUserBegin(chunk);
  HplgstMetadata m(chunk); // in the end calls allocator.getMetadata(chunk)
  // at the end, we only care about chunks that are still allocated
  //Printf("lifetime: %lld \n", m.latest_timestamp() - m.timestamp_start());
  if (m.allocated()) {
    //Printf("ptr %llx, meta %llx, allocated %llu, req size %x, trace id %x \n", chunk, m.metadata_, m.allocated(), m.requested_size(), m.stack_trace_id());
    HplgstStackDepotHandle handle = HplgstStackDepotGetHandle(m.stack_trace_id());
    HplgstMemoryChunk newchunk;
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
    handle.new_chunk(newchunk);
  }
}

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
  /*if (!handle.TraceHasMain()) {
    return;
  }*/

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

  if (meta.longest_run >= getFlags()->realloc_min_run) {
    handle.add_inefficiency(Inefficiency::IncreasingReallocs);
  }
}
// a ForEachStackTrace callback
void FindEarlyAllocLateFreeCb(HplgstStackDepotHandle& handle, void* arg) {

  // find instances where the first access is over half the lifetime
  // of the chunk

  // don't include stack traces that don't originate from main()
  /*if (!handle.TraceHasMain()) {
    return;
  }*/

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
  /*if (!handle.TraceHasMain()) {
    return;
  }*/

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

// a ForEachStackTrace callback
void FindShortLifetimeAllocs(HplgstStackDepotHandle& handle, void* arg) {

  // Currently flags an allocation point that produces *any* short
  // lived chunks
  //handle.trace().Print();
  // don't include stack traces that don't originate from main()
  // TODO do this once and filter them up front
  /*if (!handle.TraceHasMain()) {
    Printf("no main\n");
    return;
  }*/

  u64 min_lifetime = UINT64_MAX;
  handle.ForEachChunk([](HplgstMemoryChunk& chunk, void* arg){
    u64* cur_min = (u64*)arg;
    u64 lifetime = timestamp_diff(chunk.timestamp_start, chunk.timestamp_end);
    if (lifetime < *cur_min)
      *cur_min = lifetime;
  }, &min_lifetime);

  if (min_lifetime < getFlags()->short_lifetime) {
    handle.add_inefficiency(Inefficiency::ShortLifetime);
  }

}

// a ForEachStackTrace callback
void TallyAllocationPoint(HplgstStackDepotHandle& handle, void* arg) {

  // Currently flags an allocation point that produces *any* short
  // lived chunks

  // don't include stack traces that don't originate from main()
  // TODO do this once and filter them up front
  /*if (handle.TraceHasUnknown()) {
    return;
  }*/

  auto vec = (InternalMmapVector<HplgstStackDepotHandle>*) arg;
  vec->push_back(handle);

}

static u64 hplgst_start;

// a ForEachStackTrace callback
void PrintCollectedStats(HplgstStackDepotHandle& handle, void* arg) {
  if (handle.has_inefficiencies()) {
    if (!handle.has_inefficiency(Inefficiency::Unused)) {
      Printf("---------- Allocation Point: ----------\n");
      handle.trace().Print();
      if (handle.has_inefficiency(Inefficiency::Unused))
        Printf("--> Produces totally unused chunks (but may be from un-instrumented code)\n");
      if (handle.has_inefficiency(Inefficiency::ReadOnly))
        Printf("--> Produces read-only chunks (may be from un-instrumented code)\n");
      if (handle.has_inefficiency(Inefficiency::WriteOnly))
        Printf("--> Produces write-only chunks\n");
      if (handle.has_inefficiency(Inefficiency::ShortLifetime))
        Printf("--> Allocates chunks with very short lifetimes ( < %lld ms )\n", getFlags()->short_lifetime / 1000000);
      if (!handle.has_inefficiency(Inefficiency::ShortLifetime)) {
        // these really only make sense if chunks don't have short lifetimes
        if (handle.has_inefficiency(Inefficiency::EarlyAlloc))
          Printf("--> Allocates chunks early (first access after half of lifetime)\n");
        if (handle.has_inefficiency(Inefficiency::LateFree))
          Printf("--> Free chunks late (last access less than half of lifetime)\n");
      }
      if (handle.has_inefficiency(Inefficiency::IncreasingReallocs))
        Printf("--> Has increasing allocation size patterns (did you put an alloc in a loop?)\n");
      if (handle.has_inefficiency(Inefficiency::TopPercentile))
        Printf("--> Is in the top %d-th percentile of chunks allocated\n", getFlags()->percentile);

      if (getFlags()->verbose_chunks) {
        handle.ForEachChunk([](HplgstMemoryChunk &chunk, void *arg) {
          Printf("Chunk: Size: %d, Reads: %d, Writes: %d, Lifetime: %lld, WasAllocated: %d\n",
                 chunk.size, chunk.num_reads, chunk.num_writes,
                 timestamp_diff(chunk.timestamp_start, chunk.timestamp_end), chunk.allocated);
        }, arg);

      } else {
        int count = 0;
        handle.ForEachChunk([](HplgstMemoryChunk &chunk, void *arg) {
          int * c = (int*) arg;
          (*c)++;
        }, &count);
        Printf("%d chunks allocated at this point\n", count);

      }
      Printf("---------------------------------------\n");
    }

  }
}

struct WriterArgs {
  TraceWriter* writer = nullptr;
  u32 stack_id = 0;
};

static void OnExit () {

  if (getFlags()->no_output)
    return;
  // add remaining still-allocated chunks to the stack depot
  // structure, use program end as the end timestamp
  //Printf("Heapologist pre-processing still allocated chunks ...\n");
  u64 end_ts = get_timestamp();
  ForEachChunk(AddStillAllocatedCb, &end_ts);

  //Printf("total hits: %lld, heap hits: %lld\n", total_hits, heap_hits);

  // run all the different analyses across the different allocation
  // point stack traces
  // TODO add args to enable / disable individual analyses
  //Printf("Heapologist sorting chunks ...\n");
  HplgstStackDepot_SortAllChunkVectors();

/*  Printf("Heapologist processing ...\n");
  HplgstStackDepot_ForEachStackTrace(FindUnusedAllocsCb, nullptr);
  Printf("Heapologist processing short lt ...\n");
  HplgstStackDepot_ForEachStackTrace(FindShortLifetimeAllocs, nullptr);
  Printf("Heapologist processing early allocs ...\n");
  HplgstStackDepot_ForEachStackTrace(FindEarlyAllocLateFreeCb, nullptr);
  Printf("Heapologist processing bad realloc ...\n");
  HplgstStackDepot_ForEachStackTrace(FindBadReallocsCb, nullptr);*/

  // making a copy of stack trace handles, pointed-to data
  // is not duplicated
  InternalMmapVector<HplgstStackDepotHandle> all_alloc_points(128);
  HplgstStackDepot_ForEachStackTrace(TallyAllocationPoint, &all_alloc_points);
  //Printf("Program has %d active allocation points this run\n", all_alloc_points.size());
  // sort to calculate percentile
  InternalSort(&all_alloc_points, all_alloc_points.size(), HplgstStackDepotHandle::ChunkNumComparator);
  float percentile = (float) getFlags()->percentile / 100.0f;
  int index = int(percentile * all_alloc_points.size());
  for (int i = index; i < all_alloc_points.size(); i++) {
    all_alloc_points[i].add_inefficiency(Inefficiency::TopPercentile);
  }


  // write all alloc points and chunks to file
  // this could be pretty big ...
  const uptr buflen = 1024*1024;
  char buf[buflen];  // 1MB because i dont care
  TraceWriter writer(1024, 1024*1024);
  WriterArgs args;
  args.writer = &writer;

  for (int i = 0; i < all_alloc_points.size(); i++) {
    auto& alloc_point = all_alloc_points[i];
    alloc_point.trace().SPrint(buf, buflen, "#%n %p %F %L|");

    writer.WriteTrace(buf);
    //writer.WriteTrace(alloc_point.trace().trace, alloc_point.trace().size);
    args.stack_id = (u32)i;

    alloc_point.ForEachChunk([](HplgstMemoryChunk& chunk, void * arg){
      chunk.timestamp_start = chunk.timestamp_start - hplgst_start;
      chunk.timestamp_end = chunk.timestamp_end - hplgst_start;
      chunk.timestamp_first_access = chunk.timestamp_first_access > 0 ?
                                     chunk.timestamp_first_access - hplgst_start : 0;
      chunk.timestamp_last_access = chunk.timestamp_last_access > 0 ?
                                     chunk.timestamp_last_access - hplgst_start : 0;
      if (chunk.access_interval_high != 0 && (chunk.access_interval_high - chunk.access_interval_low > chunk.size))
        Printf("WARNING: chunk had access interval larger than size\n");
      WriterArgs* args = (WriterArgs*)arg;
      args->writer->WriteChunk(chunk, args->stack_id);

    }, &args);

  }

  if (!writer.OutputFiles())
    Printf("Error writing trace or chunk files!\n");

/*
  fd_t hplgst_outfile = OpenFile("hplgst.json", FileAccessMode::WrOnly);
  const uptr buflen = 1024*1024;
  char buf[buflen];  // 1MB because i dont care
  uptr bytes_written;

  const char * begin_str = "[\n";
  const char * trace_str = "{\n\"trace\":\"";
  const char * chunks_str = "\",\n\"chunks\": [\n";
  const char * end_chunks_str = "{}\n]\n},\n";
  const char * end_chunks_str_no_comma = "{}\n]\n}\n";
  const char * end_str = "\n]}\n";

  char name_buf[kMaxPathLength];
  ReadBinaryName(name_buf, kMaxPathLength);
  internal_snprintf(buf, buflen, "{\n\"binary\":\"%s\", \n\"data\": [\n", name_buf);
  WriteToFile(hplgst_outfile, buf, internal_strlen(buf), &bytes_written);
  for (int i = 0; i < all_alloc_points.size(); i++) {
    auto& alloc_point = all_alloc_points[i];
    WriteToFile(hplgst_outfile, trace_str, internal_strlen(trace_str), &bytes_written);
    alloc_point.trace().SPrint(buf, buflen, "#%n %p %F %L|");

    WriteToFile(hplgst_outfile, buf, internal_strlen(buf), &bytes_written);
    WriteToFile(hplgst_outfile, chunks_str, internal_strlen(chunks_str), &bytes_written);

    alloc_point.ForEachChunk([](HplgstMemoryChunk& chunk, void * arg){
      char buf[2048];
      // reads writes allocated size ts_start ts_end ts_first ts_last
      internal_snprintf(buf, 2048, "{\"reads\":%d, \"writes\":%d, \"allocated\":%d, \"size\":%lld, \"ts_start\":%llu, \"ts_end\":%llu, \"ts_first\":%llu, \"ts_last\":%llu},\n", chunk.num_reads, chunk.num_writes,
                        chunk.allocated, chunk.size, chunk.timestamp_start - hplgst_start, chunk.timestamp_end - hplgst_start,
                        chunk.timestamp_first_access > 0 ? chunk.timestamp_first_access - hplgst_start : 0,
                        chunk.timestamp_last_access > 0 ? chunk.timestamp_last_access - hplgst_start : 0);
      fd_t outfile = *(fd_t*)arg;
      uptr bytes_written;
      WriteToFile(outfile, buf, internal_strlen(buf), &bytes_written);

    }, &hplgst_outfile);

    if (i == all_alloc_points.size() - 1)
      WriteToFile(hplgst_outfile, end_chunks_str_no_comma, internal_strlen(end_chunks_str_no_comma), &bytes_written);
    else
      WriteToFile(hplgst_outfile, end_chunks_str, internal_strlen(end_chunks_str), &bytes_written);

  }
  WriteToFile(hplgst_outfile, end_str, internal_strlen(end_str), &bytes_written);

  CloseFile(hplgst_outfile);
*/

  //HplgstStackDepot_ForEachStackTrace(PrintCollectedStats, nullptr);

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
  Atexit(OnExit);
  hplgst_start = get_timestamp();

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
