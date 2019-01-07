//=-- memoro_allocator.h --------------------------------------------------===//
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
// Allocator for Memoro.
//
//===----------------------------------------------------------------------===//

#ifndef MEMORO_ALLOCATOR_H
#define MEMORO_ALLOCATOR_H

#include "memoro_common.h"
#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"

namespace __memoro {

void *Allocate(const StackTrace &stack, uptr size, uptr alignment,
               bool cleared);
void Deallocate(void *p);
void *Reallocate(const StackTrace &stack, void *p, uptr new_size,
                 uptr alignment);
uptr GetMallocUsableSize(const void *p);

template <typename Callable> void ForEachChunk(const Callable &callback);

void GetAllocatorCacheRange(uptr *begin, uptr *end);
void AllocatorThreadFinish();
void InitializeAllocator();
bool PointerIsAllocator(void *p);

void *GetBlockBegin(void *p);

const bool kAlwaysClearMemory = true;

#define MAX_READWRITES 255

struct ChunkMetadata {
  u8 allocated : 8; // Must be first.
  u8 num_reads : 8;
  u8 num_writes : 8;
  u8 multi_thread : 8;
#if SANITIZER_WORDSIZE == 64
  uptr requested_size : 64;
#else
  uptr requested_size : 32;
  uptr padding : 32;
#endif
  u32 stack_trace_id : 32;
  u32 creating_thread;
  u64 timestamp;
  u64 latest_timestamp;
  u64 first_timestamp;
  u64 alloc_call_time;
  u32 access_interval_low = 0xffffffff;
  u32 access_interval_high = 0;
};

#if SANITIZER_CAN_USE_ALLOCATOR64
#if defined(__powerpc64__)
const uptr kAllocatorSpace = 0xa0000000000ULL;
const uptr kAllocatorSize = 0x20000000000ULL; // 2T.
typedef DefaultSizeClassMap SizeClassMap;
#elif defined(__aarch64__) && SANITIZER_ANDROID
const uptr kAllocatorSpace = 0x3000000000ULL;
const uptr kAllocatorSize = 0x2000000000ULL; // 128G.
typedef VeryCompactSizeClassMap SizeClassMap;
#elif defined(__aarch64__)
// AArch64/SANITIZER_CAN_USER_ALLOCATOR64 is only for 42-bit VMA
// so no need to different values for different VMA.
const uptr kAllocatorSpace = 0x10000000000ULL;
const uptr kAllocatorSize = 0x10000000000ULL; // 3T.
typedef DefaultSizeClassMap SizeClassMap;
#elif SANITIZER_WINDOWS
const uptr kAllocatorSpace = ~(uptr)0;
const uptr kAllocatorSize = 0x8000000000ULL; // 500G
typedef DefaultSizeClassMap SizeClassMap;
#else
const uptr kAllocatorSpace = 0x600000000000ULL;
const uptr kAllocatorSize = 0x40000000000ULL; // 4T.
typedef DefaultSizeClassMap SizeClassMap;
#endif
template <typename AddressSpaceViewTy>
struct AP64 { // Allocator64 parameters. Deliberately using a short name.
  static const uptr kSpaceBeg = kAllocatorSpace;
  static const uptr kSpaceSize = kAllocatorSize;
  static const uptr kMetadataSize = sizeof(ChunkMetadata);
  typedef __memoro::SizeClassMap SizeClassMap;
  typedef NoOpMapUnmapCallback MapUnmapCallback;
  typedef AddressSpaceViewTy AddressSpaceView;
  static const uptr kFlags = 0;
};

template <typename AddressSpaceView>
using PrimaryAllocatorASVT = SizeClassAllocator64<AP64<AddressSpaceView>>;
using PrimaryAllocator = PrimaryAllocatorASVT<LocalAddressSpaceView>;
#else // Fallback to SizeClassAllocator32.
static const uptr kRegionSizeLog = 20;
static const uptr kNumRegions = SANITIZER_MMAP_RANGE_SIZE >> kRegionSizeLog;
#if SANITIZER_WORDSIZE == 32
typedef FlatByteMap<kNumRegions> ByteMap;
#elif SANITIZER_WORDSIZE == 64
typedef TwoLevelByteMap<(kNumRegions >> 12), 1 << 12> ByteMap;
#endif
typedef CompactSizeClassMap SizeClassMap;
struct AP32 {
  static const uptr kSpaceBeg = 0;
  static const u64 kSpaceSize = SANITIZER_MMAP_RANGE_SIZE;
  static const uptr kMetadataSize = 16;
  typedef __memoro::SizeClassMap SizeClassMap;
  static const uptr kRegionSizeLog = __memoro::kRegionSizeLog;
  typedef __memoro::ByteMap ByteMap;
  typedef NoOpMapUnmapCallback MapUnmapCallback;
  static const uptr kFlags = 0;
};
typedef SizeClassAllocator32<AP32> PrimaryAllocator;
#endif // SANITIZER_CAN_USE_ALLOCATOR64
typedef SizeClassAllocatorLocalCache<PrimaryAllocator> AllocatorCache;

#if defined(__i386__) || defined(__arm__)
static const uptr kMaxAllowedMallocSize = 1UL << 30;
#elif defined(__mips64) || defined(__aarch64__)
static const uptr kMaxAllowedMallocSize = 4UL << 30;
#else
static const uptr kMaxAllowedMallocSize = 8UL << 30;
#endif

typedef LargeMmapAllocator<> SecondaryAllocator;
typedef CombinedAllocator<PrimaryAllocator, AllocatorCache, SecondaryAllocator>
    Allocator;

AllocatorCache *GetAllocatorCache();

int memoro_posix_memalign(void **memptr, uptr alignment, uptr size,
                          const StackTrace &stack);
void *memoro_memalign(uptr alignment, uptr size, const StackTrace &stack);
void *memoro_malloc(uptr size, const StackTrace &stack);
void memoro_free(void *p);
void *memoro_realloc(void *p, uptr size, const StackTrace &stack);
void *memoro_calloc(uptr nmemb, uptr size, const StackTrace &stack);
void *memoro_valloc(uptr size, const StackTrace &stack);
uptr memoro_mz_size(const void *p);

} // namespace __memoro

#endif // MEMORO_ALLOCATOR_H
