//
// Created by Stuart Byma on 17/07/17.
//

#ifndef LLVM_HPLGST_FLAGS_H
#define LLVM_HPLGST_FLAGS_H

#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_flag_parser.h"

namespace __hplgst {

  class Flags {
  public:
#define HPLGST_FLAG(Type, Name, DefaultValue, Description) Type Name;
#include "hplgst_flags.inc"
#undef HPLGST_FLAG

    void setDefaults();
  };

  extern Flags HplgstFlagsDontUseDirectly;
  inline Flags *getFlags() {
    return &HplgstFlagsDontUseDirectly;
  }

  void InitializeFlags();

} // namespace __esan

#endif //LLVM_HPLGST_FLAGS_H
