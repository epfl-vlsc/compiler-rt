//=-- hplgst_allocator.cc ---------------------------------------------------===//
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
// See hplgst_allocator.h for details.
//
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_allocator_interface.h"
#include "hplgst_stackdepot.h"
#include "hplgst_allocator.h"
#include "hplgst_timer.h"
#include "hplgst_thread.h"

extern "C" void *memset(void *ptr, int value, uptr num);

namespace __hplgst {

static Allocator allocator;

void InitializeAllocator() {
  allocator.InitLinkerInitialized(
      common_flags()->allocator_may_return_null,
      common_flags()->allocator_release_to_os_interval_ms);
}

bool PointerIsAllocator(void *p) {
  return allocator.PointerIsMineUnsafe(p);
}

void AllocatorThreadFinish() {
  allocator.SwallowCache(GetAllocatorCache());
}

void* GetBlockBegin(void * p) {
  return allocator.GetBlockBeginUnsafe(p);
}

static ChunkMetadata *Metadata(const void *p) {
  void * p_begin = allocator.GetBlockBegin(p);
  return reinterpret_cast<ChunkMetadata *>(allocator.GetMetaData(p_begin));
}

static void RegisterAllocation(const StackTrace &stack, void *p, uptr size, u64 ts) {
  if (!p) return;
  ChunkMetadata *m = Metadata(p);
  CHECK(m);
  // TODO tag with thread id?
  m->requested_size = size; // This must always be present, or hplgst_mz_size fails (and
                            // so does malloc_zone_from_ptr on Mac).
  HplgstStackDepotHandle handle = HplgstStackDepotPut_WithHandle(stack) ;
  m->stack_trace_id = handle.id();
  m->num_reads = 0;
  m->num_writes = 0;
  m->latest_timestamp = 0;  // access timestamps
  m->first_timestamp = 0;
  u64 now = get_timestamp();
  m->timestamp = now;
  m->alloc_call_time = timestamp_diff(ts, now);
  m->creating_thread = GetCurrentThread();
  m->multi_thread = 0;
  m->access_interval_low = 0xffffffff;
  m->access_interval_high = 0;
  atomic_store(reinterpret_cast<atomic_uint8_t *>(m), 1, memory_order_relaxed);
  //uptr allocatedSize = allocator.GetActuallyAllocatedSize(p);
  //Printf("hplgst allocate %d bytes, actual size %d bytes, p %llx, metadata %llx\n", size, allocatedSize, p, Metadata(p));
}

static void RegisterDeallocation(void *p) {
  if (!p) return;
  // get dealloc timestamp
  u64 ts = get_timestamp();
  ChunkMetadata *m = Metadata(p);
  //u64 diff_ns = timestamp_diff(m->timestamp, ts);
  CHECK(m);
  atomic_store(reinterpret_cast<atomic_uint8_t *>(m), 0, memory_order_relaxed);

  // store the record of this chunk along with its allocation point stack trace
  // TODO we could also store the free point stack trace?
  HplgstStackDepotHandle handle = HplgstStackDepotGetHandle(m->stack_trace_id);
  HplgstMemoryChunk chunk;
  chunk.allocated = 0;
  chunk.timestamp_start = m->timestamp;
  chunk.timestamp_end = ts;
  chunk.size = m->requested_size;
  chunk.num_writes = m->num_writes;
  chunk.num_reads = m->num_reads;
  chunk.timestamp_last_access = m->latest_timestamp;
  chunk.timestamp_first_access = m->first_timestamp;
  chunk.alloc_call_time = m->alloc_call_time;
  chunk.multi_thread = m->multi_thread;
  chunk.access_interval_low = m->access_interval_low;
  chunk.access_interval_high = m->access_interval_high;
  handle.new_chunk(chunk);
}

void *Allocate(const StackTrace &stack, uptr size, uptr alignment,
               bool cleared) {
  u64 ts = get_timestamp();
  if (size == 0)
    size = 1;
  if (size > kMaxAllowedMallocSize) {
    Report("WARNING: Hplgst failed to allocate %zu bytes\n", size);
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
    Report("WARNING: Heapologist failed to allocate %zu bytes\n", new_size);
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
  ChunkMetadata *m = Metadata(p);
  if (!m) return 0;
  return m->requested_size;
}

void *hplgst_memalign(uptr alignment, uptr size, const StackTrace &stack) {
  return Allocate(stack, size, alignment, kAlwaysClearMemory);
}

void *hplgst_malloc(uptr size, const StackTrace &stack) {
  return Allocate(stack, size, 1, kAlwaysClearMemory);
}

void hplgst_free(void *p) {
  Deallocate(p);
}

void *hplgst_realloc(void *p, uptr size, const StackTrace &stack) {
  return Reallocate(stack, p, size, 1);
}

void *hplgst_calloc(uptr nmemb, uptr size, const StackTrace &stack) {
  size *= nmemb;
  return Allocate(stack, size, 1, true);
}

void *hplgst_valloc(uptr size, const StackTrace &stack) {
  if (size == 0)
    size = GetPageSizeCached();
  return Allocate(stack, size, GetPageSizeCached(), kAlwaysClearMemory);
}

uptr hplgst_mz_size(const void *p) {
  return GetMallocUsableSize(p);
}

///// Interface to the common LSan module. /////

void LockAllocator() {
  allocator.ForceLock();
}

void UnlockAllocator() {
  allocator.ForceUnlock();
}

void GetAllocatorGlobalRange(uptr *begin, uptr *end) {
  *begin = (uptr)&allocator;
  *end = *begin + sizeof(allocator);
}

uptr GetUserBegin(uptr chunk) {
  return chunk;
}

HplgstMetadata::HplgstMetadata(uptr chunk) {
  metadata_ = Metadata(reinterpret_cast<void *>(chunk));
  //Printf("metadata pointer for %%lld is %lld\n", chunk, metadata_);
  CHECK(metadata_);
}

bool HplgstMetadata::allocated() const {
  return reinterpret_cast<ChunkMetadata *>(metadata_)->allocated;
}

uptr HplgstMetadata::requested_size() const {
  return reinterpret_cast<ChunkMetadata *>(metadata_)->requested_size;
}

u32 HplgstMetadata::stack_trace_id() const {
  return reinterpret_cast<ChunkMetadata *>(metadata_)->stack_trace_id;
}

u64 HplgstMetadata::timestamp_start() const {
  return reinterpret_cast<ChunkMetadata *>(metadata_)->timestamp;
}

void HplgstMetadata::set_latest_timestamp(u64 ts) {
  reinterpret_cast<ChunkMetadata *>(metadata_)->latest_timestamp = ts;
}

void HplgstMetadata::set_first_timestamp(u64 ts) {
  reinterpret_cast<ChunkMetadata *>(metadata_)->first_timestamp = ts;
}

u8 HplgstMetadata::num_reads() const {
  return reinterpret_cast<ChunkMetadata *>(metadata_)->num_reads;
}

u8 HplgstMetadata::num_writes() const {
  return reinterpret_cast<ChunkMetadata *>(metadata_)->num_writes;
}

void HplgstMetadata::incr_reads() {
  auto chunkmeta = reinterpret_cast<ChunkMetadata *>(metadata_);
  if (chunkmeta->num_reads < MAX_READWRITES)
    chunkmeta->num_reads++;
}

void HplgstMetadata::incr_writes() {
  auto chunkmeta = reinterpret_cast<ChunkMetadata *>(metadata_);
  if (chunkmeta->num_writes < MAX_READWRITES)
    chunkmeta->num_writes++;
}

u64 HplgstMetadata::first_timestamp() {
  return reinterpret_cast<ChunkMetadata *>(metadata_)->first_timestamp;
}

u64 HplgstMetadata::latest_timestamp() {
  return reinterpret_cast<ChunkMetadata *>(metadata_)->latest_timestamp;
}

u32 HplgstMetadata::creating_thread() {
  return reinterpret_cast<ChunkMetadata *>(metadata_)->creating_thread;
}

void HplgstMetadata::set_multi_thread() {
  reinterpret_cast<ChunkMetadata *>(metadata_)->multi_thread = 1;
}

u8 HplgstMetadata::multi_thread() const {
  return reinterpret_cast<ChunkMetadata *>(metadata_)->multi_thread;
}

u64 HplgstMetadata::alloc_call_time() const {
  return reinterpret_cast<ChunkMetadata *>(metadata_)->alloc_call_time;
}

void ForEachChunk(ForEachChunkCallback callback, void *arg) {
  allocator.ForEachChunk(callback, arg);
}

u32 HplgstMetadata::interval_low() const {
  return reinterpret_cast<ChunkMetadata *>(metadata_)->access_interval_low;
}
u32 HplgstMetadata::interval_high() const {
  return reinterpret_cast<ChunkMetadata *>(metadata_)->access_interval_high;
}
void HplgstMetadata::set_interval_low(u32 value) {
  reinterpret_cast<ChunkMetadata *>(metadata_)->access_interval_low = value;
}
void HplgstMetadata::set_interval_high(u32 value) {
  reinterpret_cast<ChunkMetadata *>(metadata_)->access_interval_high = value;
}

} // namespace __hplgst

using namespace __hplgst;

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
int __sanitizer_get_ownership(const void *p) { return Metadata(p) != nullptr; }

SANITIZER_INTERFACE_ATTRIBUTE
uptr __sanitizer_get_allocated_size(const void *p) {
  return GetMallocUsableSize(p);
}

#if !SANITIZER_SUPPORTS_WEAK_HOOKS
// Provide default (no-op) implementation of malloc hooks.
SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE
void __sanitizer_malloc_hook(void *ptr, uptr size) {
  (void)ptr;
  (void)size;
}
SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE
void __sanitizer_free_hook(void *ptr) {
  (void)ptr;
}
#endif
} // extern "C"
