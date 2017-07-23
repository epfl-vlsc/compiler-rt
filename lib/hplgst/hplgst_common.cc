//=-- hplgst_common.cc ------------------------------------------------------===//
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
// Implementation of common checking functionality.
//
//===----------------------------------------------------------------------===//

#include "hplgst_common.h"

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_procmaps.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_suppressions.h"
#include "sanitizer_common/sanitizer_report_decorator.h"
#include "sanitizer_common/sanitizer_tls_get_addr.h"

#if CAN_SANITIZE_LEAKS
namespace __hplgst {

// This mutex is used to prevent races between DoLeakCheck and IgnoreObject, and
// also to protect the global list of root regions.
BlockingMutex global_mutex(LINKER_INITIALIZED);


void DisableCounterUnderflow() {
  if (common_flags()->detect_leaks) {
    Report("Unmatched call to __hplgst_enable().\n");
    Die();
  }
}


#define LOG_POINTERS(...)                           \
  do {                                              \
    if (flags()->log_pointers) Report(__VA_ARGS__); \
  } while (0);

#define LOG_THREADS(...)                           \
  do {                                             \
    if (flags()->log_threads) Report(__VA_ARGS__); \
  } while (0);


void InitCommonHplgst() {
  //InitializeRootRegions();
  InitializePlatformSpecificModules();
}

class Decorator: public __sanitizer::SanitizerCommonDecorator {
 public:
  Decorator() : SanitizerCommonDecorator() { }
  const char *Error() { return Red(); }
  const char *Leak() { return Blue(); }
  const char *End() { return Default(); }
};

} // namespace __hplgst
#else // CAN_SANITIZE_LEAKS
namespace __hplgst {
void InitCommonHplgst() { }
void DoLeakCheck() { }
void DisableInThisThread() { }
void EnableInThisThread() { }
}
#endif // CAN_SANITIZE_LEAKS

using namespace __hplgst;  // NOLINT

extern "C" {
/*SANITIZER_INTERFACE_ATTRIBUTE
void __hplgst_ignore_object(const void *p) {
#if CAN_SANITIZE_LEAKS
  if (!common_flags()->detect_leaks)
    return;
  // Cannot use PointsIntoChunk or HplgstMetadata here, since the allocator is not
  // locked.
  BlockingMutexLock l(&global_mutex);
  IgnoreObjectResult res = IgnoreObjectLocked(p);
  if (res == kIgnoreObjectInvalid)
    VReport(1, "__hplgst_ignore_object(): no heap object found at %p", p);
  if (res == kIgnoreObjectAlreadyIgnored)
    VReport(1, "__hplgst_ignore_object(): "
           "heap object at %p is already being ignored\n", p);
  if (res == kIgnoreObjectSuccess)
    VReport(1, "__hplgst_ignore_object(): ignoring heap object at %p\n", p);
#endif // CAN_SANITIZE_LEAKS
}*/


SANITIZER_INTERFACE_ATTRIBUTE
void __hplgst_disable() {
#if CAN_SANITIZE_LEAKS
  __hplgst::DisableInThisThread();
#endif
}

SANITIZER_INTERFACE_ATTRIBUTE
void __hplgst_enable() {
#if CAN_SANITIZE_LEAKS
  __hplgst::EnableInThisThread();
#endif
}


#if !SANITIZER_SUPPORTS_WEAK_HOOKS
SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE
int __hplgst_is_turned_off() {
  return 0;
}

SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE
const char *__hplgst_default_suppressions() {
  return "";
}
#endif
} // extern "C"
