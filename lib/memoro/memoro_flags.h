//=-- memoro_flags.h ------------------------------------------------------===//
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
//===----------------------------------------------------------------------===//

#ifndef LLVM_MEMORO_FLAGS_H
#define LLVM_MEMORO_FLAGS_H

#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_internal_defs.h"

namespace __memoro {

struct Flags {
public:
#define MEMORO_FLAG(Type, Name, DefaultValue, Description) Type Name;

#include "memoro_flags.inc"

#undef MEMORO_FLAG

  void setDefaults();
};

extern "C" {
extern Flags MemoroFlagsDontUseDirectly;
}

inline Flags *getFlags() { return &MemoroFlagsDontUseDirectly; }

void InitializeFlags();

} // namespace __memoro

#endif // LLVM_MEMORO_FLAGS_H
