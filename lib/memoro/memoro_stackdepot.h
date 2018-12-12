//===-- memoro_stackdepot.h ----------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Custom stack depot for Memoro.
//
//===----------------------------------------------------------------------===//

#ifndef MEMORO_STACKDEPOT_H
#define MEMORO_STACKDEPOT_H

#include <utility>

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_stacktrace.h"

namespace __memoro {

// this structure must be kept consistent with the Chunk struct in
// the visualizer C++ library, because it is written in binary form to disk
struct __attribute__((packed)) MemoroMemoryChunk {
  MemoroMemoryChunk(u8 n_reads, u8 n_writes, u8 allocd, u64 sz, u64 ts_start,
                    u64 ts_end)
      : num_reads(n_reads), num_writes(n_writes), allocated(allocd), size(sz),
        timestamp_start(ts_start), timestamp_end(ts_end) {}
  MemoroMemoryChunk() {}
  u8 num_reads = 0;
  u8 num_writes = 0;
  u8 allocated = 0;
  u8 multi_thread = 0;
  u32 stack_index = 0; // used for file writer
  u64 size = 0;
  u64 timestamp_start = 0;
  u64 timestamp_end = 0;
  u64 timestamp_first_access = 0;
  u64 timestamp_last_access = 0;
  u64 alloc_call_time = 0;
  // these are essentially byte indexes representing the interval that all
  // accesses fell into
  u32 access_interval_low = 0;
  u32 access_interval_high = 0;
  static bool ChunkComparator(const MemoroMemoryChunk &a,
                              const MemoroMemoryChunk &b);
};

typedef InternalMmapVectorNoCtor<MemoroMemoryChunk> ChunkVec;
struct MemoroStackAndChunks {
  StackTrace st;
  ChunkVec *chunks;

  MemoroStackAndChunks() : chunks(nullptr) {}
  MemoroStackAndChunks(const StackTrace &_st) : st(_st), chunks(nullptr) {}
  MemoroStackAndChunks(const StackTrace &_st, ChunkVec *_chunks)
      : st(_st), chunks(_chunks) {}
};

// StackDepot efficiently stores huge amounts of stack traces.
struct MemoroStackDepotNode;
struct MemoroStackDepotHandle {
  MemoroStackDepotNode *node_;
  MemoroStackDepotHandle() : node_(nullptr) {}
  explicit MemoroStackDepotHandle(MemoroStackDepotNode *node) : node_(node) {}
  bool valid() { return node_; }
  u32 id();
  int use_count();
  void inc_use_count_unsafe();
};

typedef void (*ForEachStackTraceCb)(const MemoroStackAndChunks &handle,
                                    void *arg);
const int kStackDepotMaxUseCount = 1U << 20;

MemoroStackDepotHandle MemoroStackDepotPut_WithHandle(StackTrace stack);
MemoroStackAndChunks MemoroStackDepotGet(u32 id);
void MemoroStackDepot_ForEachStackTrace(ForEachStackTraceCb func, void *arg);
void MemoroStackDepot_SortAllChunkVectors();

void MemoroStackDepotLockAll();
void MemoroStackDepotUnlockAll();

} // namespace __memoro

#endif // MEMORO_STACKDEPOT_H
