//
// Created by Stuart Byma on 17/07/17.
//

#include "hplgst_flags.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_flags.h"

using namespace __sanitizer;

namespace __hplgst {

  static const char HplgstOptsEnv[] = "HPLGST_OPTIONS";

  Flags HplgstFlagsDontUseDirectly;

  void Flags::setDefaults() {
#define HPLGST_FLAG(Type, Name, DefaultValue, Description) Name = DefaultValue;
#include "hplgst_flags.inc"
#undef HPLGST_FLAG
  }

  static void registerHplgstFlags(FlagParser *Parser, Flags *F) {
#define HPLGST_FLAG(Type, Name, DefaultValue, Description) \
  RegisterFlag(Parser, #Name, Description, &F->Name);
#include "hplgst_flags.inc"
#undef HPLGST_FLAG
  }

  void InitializeFlags() {
    // Set all the default values.
    SetCommonFlagsDefaults();
    {
      CommonFlags cf;
      cf.CopyFrom(*common_flags());
      cf.external_symbolizer_path = GetEnv("HPLGST_SYMBOLIZER_PATH");
      cf.malloc_context_size = 30;
      cf.intercept_tls_get_addr = true;
      cf.detect_leaks = true;
      cf.exitcode = 23;
      OverrideCommonFlags(cf);
    }
    SetCommonFlagsDefaults();
    Flags *F = getFlags();
    F->setDefaults();

    FlagParser Parser;
    registerHplgstFlags(&Parser, F);
    RegisterCommonFlags(&Parser);
    Parser.ParseString(GetEnv(HplgstOptsEnv));

    InitializeCommonFlags();
    if (Verbosity())
      ReportUnrecognizedFlags();
    if (common_flags()->help)
      Parser.PrintFlagDescriptions();

    __sanitizer_set_report_path(common_flags()->log_path);

  }

}
