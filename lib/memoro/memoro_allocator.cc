//=-- memoro_allocator.cc -------------------------------------------------===//
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
// See memoro_allocator.h for details.
//
//===----------------------------------------------------------------------===//

#include "memoro_allocator.h"
#include "memoro_stackdepot.h"
#include "memoro_thread.h"
#include "memoro_timer.h"
#include "memoro_flags.h"
#include "sanitizer_common/sanitizer_allocator_checks.h"
#include "sanitizer_common/sanitizer_allocator_interface.h"
#include "sanitizer_common/sanitizer_errno_codes.h"

extern "C" void *memset(void *ptr, int value, uptr num);

namespace __memoro {

static Allocator allocator;

// Primary allocator for small fixed-size chunks
// Secondary for bigger chunks
void InitializeAllocator() {
  allocator.InitLinkerInitialized(
      common_flags()->allocator_release_to_os_interval_ms);
}

void PrintStats() {
  allocator.PrintStats();
}

void AllocatorThreadFinish() { allocator.SwallowCache(GetAllocatorCache()); }

void *GetBlockBegin(const void *p, bool *is_primary) {
  /* return allocator.GetBlockBeginUnsafe(p); */
  return allocator.GetBlockBegin(p);
}

static ChunkMetadata *Metadata(const void *p) {
  return reinterpret_cast<ChunkMetadata *>(allocator.GetMetaData(p));
}

static void RegisterAllocation(const StackTrace &stack, void *p, uptr size,
                               u64 ts) {
  // At least initialize the stack_trace_id
  ChunkMetadata *m = Metadata(p);
  CHECK(m);
  m->stack_trace_id = 0;
  m->requested_size = size; // This must always be present, or memoro_mz_size
                            // fails (and so does malloc_zone_from_ptr on Mac).

  if (!getFlags()->register_allocs)
    return;
  if (!p)
    return;
  // TODO tag with thread id?
  MemoroStackDepotHandle handle = MemoroStackDepotPut_WithHandle(stack);
  m->stack_trace_id = handle.id();
  m->num_reads = 0;
  m->num_writes = 0;
  m->latest_timestamp = 0; // access timestamps
  m->first_timestamp = 0;
  u64 now = get_timestamp();
  m->timestamp = now;
  m->alloc_call_time = timestamp_diff(ts, now);
  m->creating_thread = GetCurrentThread();
  m->multi_thread = 0;
  m->access_interval_low = 0xffffffff;
  m->access_interval_high = 0;
  atomic_store(reinterpret_cast<atomic_uint8_t *>(m), 1, memory_order_relaxed);
  // uptr allocatedSize = allocator.GetActuallyAllocatedSize(p);
  // Printf("memoro allocate %d bytes, actual size %d bytes, p %llx, metadata
  // %llx\n", size, allocatedSize, p, Metadata(p));
}

static void RegisterDeallocation(void *p) {
  if (!getFlags()->register_allocs)
    return;

  p = GetBlockBegin(p);
  if (p == nullptr)
    return;

  ChunkMetadata *m = Metadata(p);
  CHECK(m);

  if (m->stack_trace_id == 0)
    return;

  atomic_store(reinterpret_cast<atomic_uint8_t *>(m), 0, memory_order_relaxed);

  // store the record of this chunk along with its allocation point stack trace
  // TODO we could also store the free point stack trace?
  MemoroStackAndChunks sl = MemoroStackDepotGet(m->stack_trace_id);
  MemoroMemoryChunk chunk;
  chunk.allocated = 0;
  chunk.timestamp_start = m->timestamp;
  chunk.timestamp_end = get_timestamp();
  chunk.size = m->requested_size;
  chunk.num_writes = m->num_writes;
  chunk.num_reads = m->num_reads;
  chunk.timestamp_last_access = m->latest_timestamp;
  chunk.timestamp_first_access = m->first_timestamp;
  chunk.alloc_call_time = m->alloc_call_time;
  chunk.multi_thread = m->multi_thread;
  chunk.access_interval_low = m->access_interval_low;
  chunk.access_interval_high = m->access_interval_high;
  /* sl.chunks->push_back(chunk); */
  sl.PushChunk(chunk);
}

void *Allocate(const StackTrace &stack, uptr size, uptr alignment,
               bool cleared) {
  u64 ts = get_timestamp();
  if (size == 0)
    size = 1;
  if (size > kMaxAllowedMallocSize) {
    Report("WARNING: Memoro failed to allocate %zu bytes\n", size);
    return nullptr;
  }
  void *p = allocator.Allocate(GetAllocatorCache(), size, alignment);
  // Do not rely on the allocator to clear the memory (it's slow).
  if (cleared && allocator.FromPrimary(p))
    memset(p, 0, size);
  RegisterAllocation(stack, p, size, ts);
  if (&__sanitizer_malloc_hook)
    __sanitizer_malloc_hook(p, size);
  RunMallocHooks(p, size);
  return p;
}

void Deallocate(void *p) {
  if (&__sanitizer_free_hook)
    __sanitizer_free_hook(p);
  RunFreeHooks(p);
  RegisterDeallocation(p);
  allocator.Deallocate(GetAllocatorCache(), p);
}

void *Reallocate(const StackTrace &stack, void *p, uptr new_size,
                 uptr alignment) {
  u64 ts = get_timestamp();
  RegisterDeallocation(p);
  if (new_size > kMaxAllowedMallocSize) {
    Report("WARNING: Memoro failed to allocate %zu bytes\n", new_size);
    allocator.Deallocate(GetAllocatorCache(), p);
    return nullptr;
  }
  p = allocator.Reallocate(GetAllocatorCache(), p, new_size, alignment);
  RegisterAllocation(stack, p, new_size, ts);
  return p;
}

void GetAllocatorCacheRange(uptr *begin, uptr *end) {
  *begin = (uptr)GetAllocatorCache();
  *end = *begin + sizeof(AllocatorCache);
}

uptr GetMallocUsableSize(const void *p) {
  p = GetBlockBegin(p);
  if (!p)
    return 0;

  ChunkMetadata *m = Metadata(p);
  return m->requested_size;
}

void *memoro_memalign(uptr alignment, uptr size, const StackTrace &stack) {
  return Allocate(stack, size, alignment, kAlwaysClearMemory);
}

int memoro_posix_memalign(void **memptr, uptr alignment, uptr size,
                          const StackTrace &stack) {
  if (UNLIKELY(!CheckPosixMemalignAlignment(alignment))) {
    if (AllocatorMayReturnNull())
      return errno_EINVAL;
  }
  void *ptr = Allocate(stack, size, alignment, kAlwaysClearMemory);
  if (UNLIKELY(!ptr))
    // OOM error is already taken care of by Allocate.
    return errno_ENOMEM;
  CHECK(IsAligned((uptr)ptr, alignment));
  *memptr = ptr;
  return 0;
}

void *memoro_malloc(uptr size, const StackTrace &stack) {
  return Allocate(stack, size, 1, kAlwaysClearMemory);
}

void memoro_free(void *p) { Deallocate(p); }

void *memoro_realloc(void *p, uptr size, const StackTrace &stack) {
  return Reallocate(stack, p, size, 1);
}

void *memoro_calloc(uptr nmemb, uptr size, const StackTrace &stack) {
  size *= nmemb;
  return Allocate(stack, size, 1, true);
}

void *memoro_valloc(uptr size, const StackTrace &stack) {
  if (size == 0)
    size = GetPageSizeCached();
  return Allocate(stack, size, GetPageSizeCached(), kAlwaysClearMemory);
}

uptr memoro_mz_size(const void *p) { return GetMallocUsableSize(p); }

///// Interface to the common LSan module. /////

void LockAllocator() { allocator.ForceLock(); }

void UnlockAllocator() { allocator.ForceUnlock(); }

void GetAllocatorGlobalRange(uptr *begin, uptr *end) {
  *begin = (uptr)&allocator;
  *end = *begin + sizeof(allocator);
}

uptr GetUserBegin(uptr chunk) { return chunk; }

MemoroMetadata::MemoroMetadata(uptr chunk) {
  metadata_ = Metadata(reinterpret_cast<void *>(chunk)); // chunk is beginning
  // Printf("metadata pointer for %%lld is %lld\n", chunk, metadata_);
  CHECK(metadata_);
}

void ForEachChunk(ForEachChunkCallback callback, void *arg) {
  allocator.ForEachChunk(callback, arg);
}

} // namespace __memoro

using namespace __memoro;

extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE
uptr __sanitizer_get_current_allocated_bytes() {
  uptr stats[AllocatorStatCount];
  allocator.GetStats(stats);
  return stats[AllocatorStatAllocated];
}

SANITIZER_INTERFACE_ATTRIBUTE
uptr __sanitizer_get_heap_size() {
  uptr stats[AllocatorStatCount];
  allocator.GetStats(stats);
  return stats[AllocatorStatMapped];
}

SANITIZER_INTERFACE_ATTRIBUTE
uptr __sanitizer_get_free_bytes() { return 0; }

SANITIZER_INTERFACE_ATTRIBUTE
uptr __sanitizer_get_unmapped_bytes() { return 0; }

SANITIZER_INTERFACE_ATTRIBUTE
uptr __sanitizer_get_estimated_allocated_size(uptr size) { return size; }

SANITIZER_INTERFACE_ATTRIBUTE
int __sanitizer_get_ownership(const void *p) { return GetBlockBegin(p) != nullptr; }

SANITIZER_INTERFACE_ATTRIBUTE
uptr __sanitizer_get_allocated_size(const void *p) {
  return GetMallocUsableSize(p);
}

#if !SANITIZER_SUPPORTS_WEAK_HOOKS
// Provide default (no-op) implementation of malloc hooks.
SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE void
__sanitizer_malloc_hook(void *ptr, uptr size) {
  (void)ptr;
  (void)size;
}
SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE void
__sanitizer_free_hook(void *ptr) {
  (void)ptr;
}
#endif
} // extern "C"
