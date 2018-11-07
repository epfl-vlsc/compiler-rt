//===-- sanitizer_stackdepot.cc -------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is shared between AddressSanitizer and ThreadSanitizer
// run-time libraries.
//===----------------------------------------------------------------------===//

#include "memoro_stackdepot.h"

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_stackdepotbase.h"
#include "sanitizer_common/sanitizer_symbolizer.h"

namespace __memoro {

typedef InternalMmapVectorNoCtor<MemoroMemoryChunk> ChunkVec;

struct MemoroStackDepotNode {
  MemoroStackDepotNode *link;
  u32 id;
  atomic_uint32_t hash_and_use_count; // hash_bits : 12; use_count : 20;
  u32 size;
  u32 tag;
  // memoro stats
  ChunkVec* chunk_vec = nullptr;
  u64 inefficiencies = 0; // bit vector of Inefficiency enum
  uptr stack[1];  // [size]


  static const u32 kTabSizeLog = 20;
  // Lower kTabSizeLog bits are equal for all items in one bucket.
  // We use these bits to store the per-stack use counter.
  static const u32 kUseCountBits = kTabSizeLog;
  static const u32 kMaxUseCount = 1 << kUseCountBits;
  static const u32 kUseCountMask = (1 << kUseCountBits) - 1;
  static const u32 kHashMask = ~kUseCountMask;

  typedef StackTrace args_type;
  bool eq(u32 hash, const args_type &args) const {
    u32 hash_bits =
        atomic_load(&hash_and_use_count, memory_order_relaxed) & kHashMask;
    if ((hash & kHashMask) != hash_bits || args.size != size || args.tag != tag)
      return false;
    uptr i = 0;
    for (; i < size; i++) {
      if (stack[i] != args.trace[i]) return false;
    }
    return true;
  }
  static uptr storage_size(const args_type &args) {
    return sizeof(MemoroStackDepotNode) + (args.size - 1) * sizeof(uptr);
  }
  static u32 hash(const args_type &args) {
    // murmur2
    const u32 m = 0x5bd1e995;
    const u32 seed = 0x9747b28c;
    const u32 r = 24;
    u32 h = seed ^ (args.size * sizeof(uptr));
    for (uptr i = 0; i < args.size; i++) {
      u32 k = args.trace[i];
      k *= m;
      k ^= k >> r;
      k *= m;
      h *= m;
      h ^= k;
    }
    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;
    return h;
  }
  static bool is_valid(const args_type &args) {
    return args.size > 0 && args.trace;
  }
  void store(const args_type &args, u32 hash) {
    // afaict this only gets called a new entry is created so alloc is safe here
    atomic_store(&hash_and_use_count, hash & kHashMask, memory_order_relaxed);
    size = args.size;
    tag = args.tag;
    CHECK_EQ(chunk_vec, nullptr);
    chunk_vec = reinterpret_cast<decltype(chunk_vec)>(PersistentAlloc(sizeof(ChunkVec)));
    chunk_vec->Initialize(128); // hopefully not too big? or too small?
    internal_memcpy(stack, args.trace, size * sizeof(uptr));
  }
  args_type load() const {
    return args_type(&stack[0], size, tag);
  }
  MemoroStackDepotHandle get_handle() { return MemoroStackDepotHandle(this); }

  typedef MemoroStackDepotHandle handle_type;
};

COMPILER_CHECK(MemoroStackDepotNode::kMaxUseCount == (u32)kStackDepotMaxUseCount);

u32 MemoroStackDepotHandle::id() { return node_->id; }

int MemoroStackDepotHandle::use_count() {
  return atomic_load(&node_->hash_and_use_count, memory_order_relaxed) &
         MemoroStackDepotNode::kUseCountMask;
}

void MemoroStackDepotHandle::inc_use_count_unsafe() {
  u32 prev =
      atomic_fetch_add(&node_->hash_and_use_count, 1, memory_order_relaxed) &
      MemoroStackDepotNode::kUseCountMask;
  CHECK_LT(prev + 1, MemoroStackDepotNode::kMaxUseCount);
}

StackTrace MemoroStackDepotHandle::trace() {
  return StackTrace(&node_->stack[0], node_->size, node_->tag);
}

void MemoroStackDepotHandle::new_chunk(MemoroMemoryChunk& newChunk) {
  ChunkVec* vec = node_->chunk_vec;
  //SpinMutexLock l(&mu_); // multiple threads can free chunks at the same time, we need to sync
  vec->push_back(newChunk);
}

uptr MemoroStackDepotHandle::total_chunks() const {
  return node_->chunk_vec->size();
}

void MemoroStackDepotHandle::ForEachChunk(ForEachMemChunkCb func, void* arg) {
  auto vec = node_->chunk_vec;
  //Printf("handle has %d chunks\n", vec->size());
  for (uptr i = 0; i < vec->size(); i++) {
    func((*vec)[i], arg);
  }
}

void MemoroStackDepotHandle::add_inefficiency(Inefficiency i) {
  node_->inefficiencies |= i;
}

bool MemoroStackDepotHandle::has_inefficiency(Inefficiency i) {
  return node_->inefficiencies & i;
}

bool MemoroStackDepotHandle::has_inefficiencies() {
  return node_->inefficiencies != 0;
}

bool MemoroStackDepotHandle::ChunkNumComparator(const MemoroStackDepotHandle &a, const MemoroStackDepotHandle &b) {
  return a.total_chunks() < b.total_chunks();
}


// FIXME(dvyukov): this single reserved bit is used in TSan.
typedef InternalMmapVectorNoCtor<MemoroStackDepotHandle> MemoroStackDepotHandleVec;
typedef StackDepotBase<MemoroStackDepotNode, 1, MemoroStackDepotNode::kTabSizeLog>
    MemoroStackDepot;
static MemoroStackDepot theDepot;
static MemoroStackDepotHandleVec theDepotHandles;

StackDepotStats *StackDepotGetStats() {
  return theDepot.GetStats();
}

MemoroStackDepotHandle MemoroStackDepotPut_WithHandle(StackTrace stack) {
  bool inserted = false;
  MemoroStackDepotHandle theHandle = theDepot.Put(stack, &inserted);
  if (inserted) theDepotHandles.push_back(theHandle);
  return theHandle;
}

MemoroStackDepotHandle MemoroStackDepotGetHandle(u32 id) {
  // FIXME: This is very wrong!
  return theDepot.Put(theDepot.Get(id));
}

void MemoroStackDepotLockAll() {
  theDepot.LockAll();
}

void MemoroStackDepotUnlockAll() {
  theDepot.UnlockAll();
}

void MemoroStackDepot_ForEachStackTrace(ForEachStackTraceCb func, void* arg) {
  for (MemoroStackDepotHandle handle : theDepotHandles)
    func(handle, arg);
}


bool MemoroMemoryChunk::ChunkComparator(const MemoroMemoryChunk& a, const MemoroMemoryChunk& b) {
  return a.timestamp_start < b.timestamp_start;
}

void SortCb(MemoroStackDepotHandle& handle, void* arg) {
  Sort(handle.node_->chunk_vec->data(), handle.node_->chunk_vec->size(),
  MemoroMemoryChunk::ChunkComparator);
}

void MemoroStackDepot_SortAllChunkVectors() {
  MemoroStackDepot_ForEachStackTrace(SortCb, nullptr);
}

} // namespace __memoro
