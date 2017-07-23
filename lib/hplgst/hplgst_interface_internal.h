//===-- hplgst_interface_internal.h -------------------------------*- C++ -*-===//
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
// Calls to the functions declared in this header will be inserted by
// the instrumentation module.
//===----------------------------------------------------------------------===//

#ifndef HPLGST_INTERFACE_INTERNAL_H
#define HPLGST_INTERFACE_INTERNAL_H

#include <sanitizer_common/sanitizer_internal_defs.h>

// This header should NOT include any other headers.
// All functions in this header are extern "C" and start with __hplgst_.

//using __sanitizer::uptr;
//using __sanitizer::u32;

extern "C" {

// TODO find a use for a global like this or remove
typedef enum Type : __sanitizer::u32 {
  HPLGST_Test = 0,
} ToolType;

extern ToolType __hplgst_which_tool;

// This function should be called at the very beginning of the process,
// before any instrumented code is executed and before any call to malloc.
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_init(ToolType Tool, void *Ptr);
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_exit(void *Ptr);

// The instrumentation module will insert a call to one of these routines prior
// to each load and store instruction for which we do not have "fastpath"
// inlined instrumentation.  These calls constitute the "slowpath" for our
// tools.  We have separate routines for each type of memory access to enable
// targeted optimization.
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_aligned_load1(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_aligned_load2(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_aligned_load4(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_aligned_load8(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_aligned_load16(void *Addr);

SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_aligned_store1(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_aligned_store2(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_aligned_store4(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_aligned_store8(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_aligned_store16(void *Addr);

SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_unaligned_load2(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_unaligned_load4(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_unaligned_load8(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_unaligned_load16(void *Addr);

SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_unaligned_store2(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_unaligned_store4(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_unaligned_store8(void *Addr);
SANITIZER_INTERFACE_ATTRIBUTE void __hplgst_unaligned_store16(void *Addr);

// These cover unusually-sized accesses.
SANITIZER_INTERFACE_ATTRIBUTE
void __hplgst_unaligned_loadN(void *Addr, __sanitizer::uptr Size);
SANITIZER_INTERFACE_ATTRIBUTE
void __hplgst_unaligned_storeN(void *Addr, __sanitizer::uptr Size);

} // extern "C"

#endif // HPLGST_INTERFACE_INTERNAL_H
