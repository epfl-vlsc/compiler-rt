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


HPLGST_FLAG(int, short_lifetime, 1000000, "Short lifetime detection threshold in nanoseconds [1M ns]")
HPLGST_FLAG(int, realloc_min_run, 4, "Minimum number of increasing allocation size to flag [4]")
HPLGST_FLAG(
        bool, replace_str, true,
"If set, uses custom wrappers and replacements for libc string functions "
"to find more errors.")
HPLGST_FLAG(bool, replace_intrin, true,
"If set, uses custom wrappers for memset/memcpy/memmove intrinsics.")
HPLGST_FLAG(bool, verbose_chunks, false,
"If set, output all recorded chunks at each allocation point.")
HPLGST_FLAG(int, percentile, 90,
"Percentile of high-chunk allocation points to report [90]")
// we may want to keep the suppressions file
//HPLGST_FLAG(const char *, suppressions, "", "Suppressions file name.")
