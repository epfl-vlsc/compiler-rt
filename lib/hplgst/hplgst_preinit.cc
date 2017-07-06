//===-- hplgst_preinit.cc ---------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of LeakSanitizer.
//
// Call __hplgst_init at the very early stage of process startup.
//===----------------------------------------------------------------------===//

#include "hplgst.h"

#if SANITIZER_CAN_USE_PREINIT_ARRAY
  // We force __hplgst_init to be called before anyone else by placing it into
  // .preinit_array section.
  __attribute__((section(".preinit_array"), used))
  void (*__local_hplgst_preinit)(void) = __hplgst_init;
#endif
