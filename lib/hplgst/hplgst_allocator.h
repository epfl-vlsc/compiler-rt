//=-- hplgst_allocator.h ----------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of LeakSanitizer.
// Allocator for standalone LSan.
//
//===----------------------------------------------------------------------===//

#ifndef HPLGST_ALLOCATOR_H
#define HPLGST_ALLOCATOR_H

#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "hplgst_common.h"

namespace __hplgst {

void *Allocate(const StackTrace &stack, uptr size, uptr alignment,
               bool cleared);
void Deallocate(void *p);
void *Reallocate(const StackTrace &stack, void *p, uptr new_size,
                 uptr alignment);
uptr GetMallocUsableSize(const void *p);

template<typename Callable>
void ForEachChunk(const Callable &callback);

void GetAllocatorCacheRange(uptr *begin, uptr *end);
void AllocatorThreadFinish();
void InitializeAllocator();

const bool kAlwaysClearMemory = true;

struct ChunkMetadata {
  u8 allocated : 8;  // Must be first.
  ChunkTag tag : 2;
#if SANITIZER_WORDSIZE == 64
  uptr requested_size : 54;
#else
  uptr requested_size : 32;
  uptr padding : 22;
#endif
  u32 stack_trace_id;
};


#if SANITIZER_CAN_USE_ALLOCATOR64
# if defined(__powerpc64__)
  const uptr kAllocatorSpace =  0xa0000000000ULL;
const uptr kAllocatorSize  =  0x20000000000ULL;  // 2T.
typedef DefaultSizeClassMap SizeClassMap;
# elif defined(__aarch64__) && SANITIZER_ANDROID
  const uptr kAllocatorSpace =  0x3000000000ULL;
const uptr kAllocatorSize  =  0x2000000000ULL;  // 128G.
typedef VeryCompactSizeClassMap SizeClassMap;
# elif defined(__aarch64__)
  // AArch64/SANITIZER_CAN_USER_ALLOCATOR64 is only for 42-bit VMA
// so no need to different values for different VMA.
const uptr kAllocatorSpace =  0x10000000000ULL;
const uptr kAllocatorSize  =  0x10000000000ULL;  // 3T.
typedef DefaultSizeClassMap SizeClassMap;
# elif SANITIZER_WINDOWS
  const uptr kAllocatorSpace = ~(uptr)0;
const uptr kAllocatorSize  =  0x8000000000ULL;  // 500G
typedef DefaultSizeClassMap SizeClassMap;
# else
  const uptr kAllocatorSpace = 0x600000000000ULL;
  const uptr kAllocatorSize  =  0x40000000000ULL;  // 4T.
  typedef DefaultSizeClassMap SizeClassMap;
# endif
  struct AP64 {  // Allocator64 parameters. Deliberately using a short name.
    static const uptr kSpaceBeg = kAllocatorSpace;
    static const uptr kSpaceSize = kAllocatorSize;
    static const uptr kMetadataSize = 0;
    typedef __hplgst::SizeClassMap SizeClassMap;
    typedef NoOpMapUnmapCallback MapUnmapCallback;
    static const uptr kFlags = 0;
  };

  typedef SizeClassAllocator64<AP64> PrimaryAllocator;
#else  // Fallback to SizeClassAllocator32.
  static const uptr kRegionSizeLog = 20;
static const uptr kNumRegions = SANITIZER_MMAP_RANGE_SIZE >> kRegionSizeLog;
# if SANITIZER_WORDSIZE == 32
typedef FlatByteMap<kNumRegions> ByteMap;
# elif SANITIZER_WORDSIZE == 64
typedef TwoLevelByteMap<(kNumRegions >> 12), 1 << 12> ByteMap;
# endif
typedef CompactSizeClassMap SizeClassMap;
typedef SizeClassAllocator32<0, SANITIZER_MMAP_RANGE_SIZE, 16,
  SizeClassMap, kRegionSizeLog,
  ByteMap,
  NoOpMapUnmapCallback> PrimaryAllocator;
#endif  // SANITIZER_CAN_USE_ALLOCATOR64
  typedef SizeClassAllocatorLocalCache<PrimaryAllocator> AllocatorCache;

AllocatorCache *GetAllocatorCache();

void *hplgst_memalign(uptr alignment, uptr size, const StackTrace &stack);
void *hplgst_malloc(uptr size, const StackTrace &stack);
void hplgst_free(void *p);
void *hplgst_realloc(void *p, uptr size, const StackTrace &stack);
void *hplgst_calloc(uptr nmemb, uptr size, const StackTrace &stack);
void *hplgst_valloc(uptr size, const StackTrace &stack);
uptr hplgst_mz_size(const void *p);

}  // namespace __hplgst

#endif  // HPLGST_ALLOCATOR_H
