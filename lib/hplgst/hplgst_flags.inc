//===-- hplgst_flags.inc ------------------------------------------*- C++ -*-===//
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
// Hplgst runtime flags.
//
//===----------------------------------------------------------------------===//

#ifndef HPLGST_FLAG
# error "Define HPLGST_FLAG prior to including this file!"
#endif

// HPLGST_FLAG(Type, Name, DefaultValue, Description)
// See COMMON_FLAG in sanitizer_flags.inc for more details.

HPLGST_FLAG(
    int, resolution, 0,
    "Aggregate two objects into one leak if this many stack frames match. If "
    "zero, the entire stack trace must match.")

// Flags controlling the root set of reachable memory.
HPLGST_FLAG(bool, use_globals, true,
          "Root set: include global variables (.data and .bss)")
HPLGST_FLAG(bool, use_stacks, true, "Root set: include thread stacks")
HPLGST_FLAG(bool, use_registers, true, "Root set: include thread registers")
HPLGST_FLAG(bool, use_tls, true,
          "Root set: include TLS and thread-specific storage")
HPLGST_FLAG(bool, use_root_regions, true,
          "Root set: include regions added via __hplgst_register_root_region().")

HPLGST_FLAG(const char *, suppressions, "", "Suppressions file name.")
