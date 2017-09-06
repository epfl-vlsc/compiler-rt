//===-- hplgst_stackdepot.h ----------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Custom stack depot for heapologist.
//
//===----------------------------------------------------------------------===//

#ifndef HPLGST_STACKDEPOT_H
#define HPLGST_STACKDEPOT_H

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_stacktrace.h"

namespace __hplgst {

struct __attribute__((packed)) HplgstMemoryChunk {
  HplgstMemoryChunk(u8 n_reads, u8 n_writes, u8 allocd,
                    u64 sz, u64 ts_start, u64 ts_end) : num_reads(n_reads), num_writes(n_writes),
                                      allocated(allocd), size(sz),
                                      timestamp_start(ts_start), timestamp_end(ts_end) {}
  HplgstMemoryChunk() {}
  u8 num_reads = 0;
  u8 num_writes = 0;
  u8 allocated = 0;
  u8 pad;
  u32 stack_index = 0; // used for file writer
  u64 size = 0;
  u64 timestamp_start = 0;
  u64 timestamp_end = 0;
  u64 timestamp_first_access = 0;
  u64 timestamp_last_access = 0;
  static bool ChunkComparator(const HplgstMemoryChunk &a, const HplgstMemoryChunk &b);
};


typedef void (*ForEachMemChunkCb) (HplgstMemoryChunk& chunk, void* arg);

enum Inefficiency : u64 {
  Unused = 0x1,
  WriteOnly = 1 << 1,
  ReadOnly = 1 << 2,
  ShortLifetime = 1 << 3,
  LateFree = 1 << 4,
  EarlyAlloc =  1 << 5,
  IncreasingReallocs = 1 << 6,
  TopPercentile = 1 << 7
};

// StackDepot efficiently stores huge amounts of stack traces.
struct HplgstStackDepotNode;
struct HplgstStackDepotHandle {
  HplgstStackDepotNode *node_;
  HplgstStackDepotHandle() : node_(nullptr) {}
  explicit HplgstStackDepotHandle(HplgstStackDepotNode *node) : node_(node) {}
  bool valid() { return node_; }
  u32 id();
  int use_count();
  void inc_use_count_unsafe();
  StackTrace trace();
  HplgstMemoryChunk& new_chunk();
  void ForEachChunk(ForEachMemChunkCb func, void* arg);
  bool TraceHasMain();
  bool TraceHasUnknown();
  uptr total_chunks() const;
  void add_inefficiency(Inefficiency i);
  bool has_inefficiency(Inefficiency i);
  bool has_inefficiencies();
  static bool ChunkNumComparator(const HplgstStackDepotHandle &a,
                                 const HplgstStackDepotHandle &b);
};


typedef void (*ForEachStackTraceCb) (HplgstStackDepotHandle& handle, void* arg);
const int kStackDepotMaxUseCount = 1U << 20;

StackDepotStats *StackDepotGetStats();
HplgstStackDepotHandle HplgstStackDepotPut_WithHandle(StackTrace stack);
HplgstStackDepotHandle HplgstStackDepotGetHandle(u32 id);
void HplgstStackDepot_ForEachStackTrace(ForEachStackTraceCb func, void* arg);
void HplgstStackDepot_SortAllChunkVectors();

// Retrieves a stored stack trace by the id.
//StackAndChunks StackDepotGet(u32 id);

void HplgstStackDepotLockAll();
void HplgstStackDepotUnlockAll();


} // namespace __hplgst

#endif // HPLGST_STACKDEPOT_H
