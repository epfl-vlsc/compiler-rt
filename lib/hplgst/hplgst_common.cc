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

#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_suppressions.h"
#include "sanitizer_common/sanitizer_report_decorator.h"
#include "sanitizer_common/sanitizer_tls_get_addr.h"

namespace __hplgst {

void DisableCounterUnderflow() { }
void InitCommonHplgst() { }

} // namespace __hplgst


using namespace __hplgst;  // NOLINT

extern "C" {

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
