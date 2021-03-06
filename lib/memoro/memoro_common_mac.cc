//=-- memoro_common_mac.cc ------------------------------------------------===//
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
// Implementation of common functionality. Darwin-specific code.
//
//===----------------------------------------------------------------------===//

#include "memoro_common.h"
#include "sanitizer_common/sanitizer_platform.h"

#if SANITIZER_MAC

#include "memoro_allocator.h"
#include "sanitizer_common/sanitizer_allocator_internal.h"

#include <pthread.h>

namespace __memoro {

typedef struct {
  int disable_counter;
  u32 current_thread_id;
  AllocatorCache cache;
} thread_local_data_t;

static pthread_key_t key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;

// The main thread destructor requires the current thread id,
// so we can't destroy it until it's been used and reset to invalid tid
void restore_tid_data(void *ptr) {
  thread_local_data_t *data = (thread_local_data_t *)ptr;
  if (data->current_thread_id != kInvalidTid)
    pthread_setspecific(key, data);
}

static void make_tls_key() {
  CHECK_EQ(pthread_key_create(&key, restore_tid_data), 0);
}

static thread_local_data_t *get_tls_val(bool alloc) {
  pthread_once(&key_once, make_tls_key);

  thread_local_data_t *ptr = (thread_local_data_t *)pthread_getspecific(key);
  if (ptr == NULL && alloc) {
    ptr = (thread_local_data_t *)InternalAlloc(sizeof(*ptr));
    ptr->disable_counter = 0;
    ptr->current_thread_id = kInvalidTid;
    ptr->cache = AllocatorCache();
    pthread_setspecific(key, ptr);
  }

  return ptr;
}

bool DisabledInThisThread() {
  thread_local_data_t *data = get_tls_val(false);
  return data != nullptr && data->disable_counter > 0;
}

void DisableInThisThread() { ++get_tls_val(true)->disable_counter; }

void EnableInThisThread() {
  int *disable_counter = &get_tls_val(true)->disable_counter;
  if (*disable_counter == 0) {
    DisableCounterUnderflow();
  }
  --*disable_counter;
}

u32 GetCurrentThread() {
  thread_local_data_t *data = get_tls_val(false);
  CHECK(data);
  return data->current_thread_id;
}

void SetCurrentThread(u32 tid) { get_tls_val(true)->current_thread_id = tid; }

AllocatorCache *GetAllocatorCache() { return &get_tls_val(true)->cache; }

LoadedModule *GetLinker() { return nullptr; }

// Required on Linux for initialization of TLS behavior, but should not be
// required on Darwin.
void InitializePlatformSpecificModules() {}

} // namespace __memoro

#endif // SANITIZER_MAC
