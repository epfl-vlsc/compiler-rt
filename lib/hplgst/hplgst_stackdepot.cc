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

#include "hplgst_stackdepot.h"

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_stackdepotbase.h"
#include "sanitizer_common/sanitizer_symbolizer.h"

namespace __hplgst {

typedef InternalMmapVectorNoCtor<HplgstMemoryChunk> ChunkVec;

struct HplgstStackDepotNode {
  HplgstStackDepotNode *link;
  u32 id;
  atomic_uint32_t hash_and_use_count; // hash_bits : 12; use_count : 20;
  u32 size;
  u32 tag;
  // hplgst stats
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
    return sizeof(HplgstStackDepotNode) + (args.size - 1) * sizeof(uptr);
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
  HplgstStackDepotHandle get_handle() { return HplgstStackDepotHandle(this); }

  typedef HplgstStackDepotHandle handle_type;
};

COMPILER_CHECK(HplgstStackDepotNode::kMaxUseCount == (u32)kStackDepotMaxUseCount);

u32 HplgstStackDepotHandle::id() { return node_->id; }

int HplgstStackDepotHandle::use_count() {
  return atomic_load(&node_->hash_and_use_count, memory_order_relaxed) &
         HplgstStackDepotNode::kUseCountMask;
}

void HplgstStackDepotHandle::inc_use_count_unsafe() {
  u32 prev =
      atomic_fetch_add(&node_->hash_and_use_count, 1, memory_order_relaxed) &
      HplgstStackDepotNode::kUseCountMask;
  CHECK_LT(prev + 1, HplgstStackDepotNode::kMaxUseCount);
}

StackTrace HplgstStackDepotHandle::trace() {
  return StackTrace(&node_->stack[0], node_->size, node_->tag);
}

void HplgstStackDepotHandle::new_chunk(HplgstMemoryChunk& newChunk) {
  ChunkVec* vec = node_->chunk_vec;
  //SpinMutexLock l(&mu_); // multiple threads can free chunks at the same time, we need to sync
  vec->push_back(newChunk);
}

uptr HplgstStackDepotHandle::total_chunks() const {
  return node_->chunk_vec->size();
}

void HplgstStackDepotHandle::ForEachChunk(ForEachMemChunkCb func, void* arg) {
  auto vec = node_->chunk_vec;
  //Printf("handle has %d chunks\n", vec->size());
  for (uptr i = 0; i < vec->size(); i++) {
    func((*vec)[i], arg);
  }
}

void HplgstStackDepotHandle::add_inefficiency(Inefficiency i) {
  node_->inefficiencies |= i;
}

bool HplgstStackDepotHandle::has_inefficiency(Inefficiency i) {
  return node_->inefficiencies & i;
}

bool HplgstStackDepotHandle::has_inefficiencies() {
  return node_->inefficiencies != 0;
}

bool HplgstStackDepotHandle::ChunkNumComparator(const HplgstStackDepotHandle &a, const HplgstStackDepotHandle &b) {
  return a.total_chunks() < b.total_chunks();
}


// FIXME(dvyukov): this single reserved bit is used in TSan.
typedef StackDepotBase<HplgstStackDepotNode, 1, HplgstStackDepotNode::kTabSizeLog>
    HplgstStackDepot;
static HplgstStackDepot theDepot;

StackDepotStats *StackDepotGetStats() {
  return theDepot.GetStats();
}

HplgstStackDepotHandle HplgstStackDepotPut_WithHandle(StackTrace stack) {
  return theDepot.Put(stack);
}

HplgstStackDepotHandle HplgstStackDepotGetHandle(u32 id) {
  return theDepot.GetHandle(id);
}

void HplgstStackDepotLockAll() {
  theDepot.LockAll();
}

void HplgstStackDepotUnlockAll() {
  theDepot.UnlockAll();
}

void HplgstStackDepot_ForEachStackTrace(ForEachStackTraceCb func, void* arg) {
  theDepot.ForEach(func, arg);
}


bool HplgstMemoryChunk::ChunkComparator(const HplgstMemoryChunk& a, const HplgstMemoryChunk& b) {
  return a.timestamp_start < b.timestamp_start;
}

void SortCb(HplgstStackDepotHandle& handle, void* arg) {
  InternalSort(handle.node_->chunk_vec, handle.node_->chunk_vec->size(),
  HplgstMemoryChunk::ChunkComparator);
}

void HplgstStackDepot_SortAllChunkVectors() {
  HplgstStackDepot_ForEachStackTrace(SortCb, nullptr);
}

} // namespace __hplgst
