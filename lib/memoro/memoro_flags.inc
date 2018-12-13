//===-- memoro_flags.inc --------------------------------------------------===//
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
// Memoro runtime flags.
//
//===----------------------------------------------------------------------===//

#ifndef MEMORO_FLAG
# error "Define MEMORO_FLAG prior to including this file!"
#endif

// MEMORO_FLAG(Type, Name, DefaultValue, Description)
// See COMMON_FLAG in sanitizer_flags.inc for more details.

MEMORO_FLAG(
        bool, replace_str, true,
"If set, uses custom wrappers and replacements for libc string functions "
"to find more errors.")
MEMORO_FLAG(bool, replace_intrin, true,
"If set, uses custom wrappers for memset/memcpy/memmove intrinsics.")
MEMORO_FLAG(bool, verbose_chunks, false,
"If set, output all recorded chunks at each allocation point.")
MEMORO_FLAG(bool, no_output, false,
"Do not output trace or chunk files. Mostly used for testing.")
// we may want to keep the suppressions file, it maybe useful in future
//MEMORO_FLAG(const char *, suppressions, "", "Suppressions file name.")
