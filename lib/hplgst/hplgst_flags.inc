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

HPLGST_FLAG(bool, report_objects, false,
          "Print addresses of leaked objects after main leak report.")
HPLGST_FLAG(
    int, resolution, 0,
    "Aggregate two objects into one leak if this many stack frames match. If "
    "zero, the entire stack trace must match.")
HPLGST_FLAG(int, max_leaks, 0, "The number of leaks reported.")

// Flags controlling the root set of reachable memory.
HPLGST_FLAG(bool, use_globals, true,
          "Root set: include global variables (.data and .bss)")
HPLGST_FLAG(bool, use_stacks, true, "Root set: include thread stacks")
HPLGST_FLAG(bool, use_registers, true, "Root set: include thread registers")
HPLGST_FLAG(bool, use_tls, true,
          "Root set: include TLS and thread-specific storage")
HPLGST_FLAG(bool, use_root_regions, true,
          "Root set: include regions added via __hplgst_register_root_region().")
HPLGST_FLAG(bool, use_ld_allocations, true,
          "Root set: mark as reachable all allocations made from dynamic "
          "linker. This was the old way to handle dynamic TLS, and will "
          "be removed soon. Do not use this flag.")

HPLGST_FLAG(bool, use_unaligned, false, "Consider unaligned pointers valid.")
HPLGST_FLAG(bool, use_poisoned, false,
          "Consider pointers found in poisoned memory to be valid.")
HPLGST_FLAG(bool, log_pointers, false, "Debug logging")
HPLGST_FLAG(bool, log_threads, false, "Debug logging")
HPLGST_FLAG(const char *, suppressions, "", "Suppressions file name.")
