//=-- memoro_flags.cc --------------------------------------------------===//
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
//===----------------------------------------------------------------------===////

#include "memoro_flags.h"

using namespace __sanitizer;

namespace __memoro {

  static const char MemoroOptsEnv[] = "MEMORO_OPTIONS";

  Flags MemoroFlagsDontUseDirectly;

  void Flags::setDefaults() {
#define MEMORO_FLAG(Type, Name, DefaultValue, Description) Name = DefaultValue;

#include "memoro_flags.inc"

#undef MEMORO_FLAG
  }

  static void registerMemoroFlags(FlagParser *Parser, Flags *F) {
#define MEMORO_FLAG(Type, Name, DefaultValue, Description) \
  RegisterFlag(Parser, #Name, Description, &F->Name);

#include "memoro_flags.inc"

#undef MEMORO_FLAG
  }

  void InitializeFlags() {
    // Set all the default values.
    SetCommonFlagsDefaults();
    {
      CommonFlags cf;
      cf.CopyFrom(*common_flags());
      cf.external_symbolizer_path = GetEnv("MEMORO_SYMBOLIZER_PATH");
      // we need large context for mallocs to get unique allocation points
      cf.malloc_context_size = 30;
      cf.intercept_tls_get_addr = true;
      cf.exitcode = 23;
      OverrideCommonFlags(cf);
    }
    Flags *F = getFlags();
    F->setDefaults();

    FlagParser Parser;
    registerMemoroFlags(&Parser, F);
    RegisterCommonFlags(&Parser);
    Parser.ParseString(GetEnv(MemoroOptsEnv));

    InitializeCommonFlags();
    if (Verbosity())
      ReportUnrecognizedFlags();
    if (common_flags()->help)
      Parser.PrintFlagDescriptions();

    __sanitizer_set_report_path(common_flags()->log_path);

  }

}
