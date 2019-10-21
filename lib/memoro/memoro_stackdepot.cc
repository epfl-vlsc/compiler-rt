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
#include "sanitizer_common/sanitizer_mutex.h"

namespace __memoro {

struct MemoroStackDepotNode {
  MemoroStackDepotNode *link;
  u32 id;
  atomic_uint32_t hash_and_use_count; // hash_bits : 12; use_count : 20;
  u32 size;
  u32 tag;
  SpinMutex lock;
  // memoro stats
  ChunkVec *chunk_vec = nullptr;
  uptr stack[1]; // [size]

  static const u32 kTabSizeLog = 20;
  // Lower kTabSizeLog bits are equal for all items in one bucket.
  // We use these bits to store the per-stack use counter.
  static const u32 kUseCountBits = kTabSizeLog;
  static const u32 kMaxUseCount = 1 << kUseCountBits;
  static const u32 kUseCountMask = (1 << kUseCountBits) - 1;
  static const u32 kHashMask = ~kUseCountMask;

  typedef MemoroStackAndChunks args_type;
  bool eq(u32 hash, const args_type &args) const {
    const StackTrace &st = args.st;
    u32 hash_bits =
        atomic_load(&hash_and_use_count, memory_order_relaxed) & kHashMask;
    if ((hash & kHashMask) != hash_bits || st.size != size || st.tag != tag)
      return false;
    uptr i = 0;
    for (; i < size; i++) {
      if (stack[i] != st.trace[i])
        return false;
    }
    return true;
  }
  static uptr storage_size(const args_type &args) {
    return sizeof(MemoroStackDepotNode) + (args.st.size - 1) * sizeof(uptr);
  }
  static u32 hash(const args_type &args) {
    // murmur2
    const StackTrace &st = args.st;
    const u32 m = 0x5bd1e995;
    const u32 seed = 0x9747b28c;
    const u32 r = 24;
    u32 h = seed ^ (st.size * sizeof(uptr));
    for (uptr i = 0; i < st.size; i++) {
      u32 k = st.trace[i];
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
    return args.st.size > 0 && args.st.trace;
  }
  void store(const args_type &args, u32 hash) {
    // afaict this only gets called a new entry is created so alloc is safe here
    atomic_store(&hash_and_use_count, hash & kHashMask, memory_order_relaxed);
    const StackTrace &st = args.st;
    size = st.size;
    tag = st.tag;
    CHECK_EQ(chunk_vec, nullptr);
    chunk_vec = reinterpret_cast<decltype(chunk_vec)>(
        PersistentAlloc(sizeof(ChunkVec)));
    chunk_vec->Initialize(128); // hopefully not too big? or too small?
    internal_memcpy(stack, st.trace, size * sizeof(uptr));
  }
  args_type load() {
    return args_type(StackTrace(&stack[0], size, tag), chunk_vec, &lock);
  }
  MemoroStackDepotHandle get_handle() { return MemoroStackDepotHandle(this); }

  typedef MemoroStackDepotHandle handle_type;
};

COMPILER_CHECK(MemoroStackDepotNode::kMaxUseCount ==
               (u32)kStackDepotMaxUseCount);

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

// FIXME(dvyukov): this single reserved bit is used in TSan.
typedef InternalMmapVectorNoCtor<u32> MemoroStackDepotIndexes;
typedef StackDepotBase<MemoroStackDepotNode, 1,
                       MemoroStackDepotNode::kTabSizeLog>
    MemoroStackDepot;
static MemoroStackDepot theDepot;
static MemoroStackDepotIndexes theDepotIndexes;
static StaticSpinMutex theDepotIndexesLock;

void InitializeDepotLock() {
  theDepotIndexesLock.Init();
}

MemoroStackDepotHandle MemoroStackDepotPut_WithHandle(StackTrace stack) {
  bool inserted = false;
  MemoroStackDepotHandle theHandle =
      theDepot.Put(MemoroStackAndChunks(stack), &inserted);
  if (inserted) {
    SpinMutexLock m(&theDepotIndexesLock);
    theDepotIndexes.push_back(theHandle.id());
  }
  return theHandle;
}

MemoroStackAndChunks MemoroStackDepotGet(u32 id) { return theDepot.Get(id); }

void MemoroStackDepotLockAll() { theDepot.LockAll(); }

void MemoroStackDepotUnlockAll() { theDepot.UnlockAll(); }

void MemoroStackDepot_ForEachStackTrace(ForEachStackTraceCb func, void *arg) {
  for (u32 id : theDepotIndexes)
    func(theDepot.Get(id), arg);
}

bool MemoroMemoryChunk::ChunkComparator(const MemoroMemoryChunk &a,
                                        const MemoroMemoryChunk &b) {
  return a.timestamp_start < b.timestamp_start;
}

void SortCb(const MemoroStackAndChunks &_n, void *arg) {
  Sort(_n.chunks->data(), _n.chunks->size(),
       MemoroMemoryChunk::ChunkComparator);
}

void MemoroStackDepot_SortAllChunkVectors() {
  MemoroStackDepot_ForEachStackTrace(SortCb, nullptr);
}

} // namespace __memoro
