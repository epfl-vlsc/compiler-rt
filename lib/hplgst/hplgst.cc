//=-- hplgst.cc -------------------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of LeakSanitizer.
// Standalone LSan RTL.
//
//===----------------------------------------------------------------------===//

#include "hplgst.h"

#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "hplgst_allocator.h"
#include "hplgst_common.h"
#include "hplgst_thread.h"

bool hplgst_inited;
bool hplgst_init_is_running;

namespace __hplgst {


}  // namespace __hplgst

using namespace __hplgst;  // NOLINT

static void InitializeFlags() {
  // Set all the default values.
  SetCommonFlagsDefaults();
  {
    CommonFlags cf;
    cf.CopyFrom(*common_flags());
    cf.external_symbolizer_path = GetEnv("LSAN_SYMBOLIZER_PATH");
    cf.malloc_context_size = 30;
    cf.intercept_tls_get_addr = true;
    cf.detect_leaks = true;
    cf.exitcode = 23;
    OverrideCommonFlags(cf);
  }

  Flags *f = flags();
  f->SetDefaults();

  FlagParser parser;
  RegisterHplgstFlags(&parser, f);
  RegisterCommonFlags(&parser);

  parser.ParseString(GetEnv("LSAN_OPTIONS"));

  SetVerbosity(common_flags()->verbosity);

  if (Verbosity()) ReportUnrecognizedFlags();

  if (common_flags()->help) parser.PrintFlagDescriptions();
}

extern "C" void __hplgst_init() {
  CHECK(!hplgst_init_is_running);
  if (hplgst_inited)
    return;
  hplgst_init_is_running = true;
  SanitizerToolName = "LeakSanitizer";
  CacheBinaryName();
  AvoidCVE_2016_2143();
  InitializeFlags();
  InitCommonHplgst();
  InitializeAllocator();
  ReplaceSystemMalloc();
  InitTlsSize();
  InitializeInterceptors();
  InitializeThreadRegistry();
  u32 tid = ThreadCreate(0, 0, true);
  CHECK_EQ(tid, 0);
  ThreadStart(tid, GetTid());
  SetCurrentThread(tid);

  if (common_flags()->detect_leaks && common_flags()->leak_check_at_exit)
    Atexit(DoLeakCheck);

  InitializeCoverage(common_flags()->coverage, common_flags()->coverage_dir);

  hplgst_inited = true;
  hplgst_init_is_running = false;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_print_stack_trace() {
  GET_STACK_TRACE_FATAL;
  stack.Print();
}
