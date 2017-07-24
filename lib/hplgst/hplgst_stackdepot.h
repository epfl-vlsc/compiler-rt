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

  struct HplgstMemoryChunk {
    HplgstMemoryChunk(u8 n_reads, u8 n_writes, u8 allocd,
                      u64 sz, u64 ts_start, u64 ts_end) : num_reads(n_reads), num_writes(n_writes),
                                        allocated(allocd), size(sz),
                                        timestamp_start(ts_start), timestamp_end(ts_end) {}
    HplgstMemoryChunk() : num_reads(0), num_writes(0), allocated(0), size(0),
                          timestamp_start(0), timestamp_end(0) {}
    u8 num_reads;
    u8 num_writes;
    u8 allocated;
    u8 pad;
    u64 size;
    u64 timestamp_start;
    u64 timestamp_end;
  };

  typedef void (*ForEachMemChunkCb) (HplgstMemoryChunk& chunk, void* arg);

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
};


typedef void (*ForEachStackTraceCb) (HplgstStackDepotHandle& handle, void* arg);
const int kStackDepotMaxUseCount = 1U << 20;

StackDepotStats *StackDepotGetStats();
HplgstStackDepotHandle HplgstStackDepotPut_WithHandle(StackTrace stack);
HplgstStackDepotHandle HplgstStackDepotGetHandle(u32 id);
void HplgstStackDepot_ForEachStackTrace(ForEachStackTraceCb func, void* arg);

// Retrieves a stored stack trace by the id.
//StackAndChunks StackDepotGet(u32 id);

void HplgstStackDepotLockAll();
void HplgstStackDepotUnlockAll();


} // namespace __hplgst

#endif // HPLGST_STACKDEPOT_H
