//=-- memoro_tracewriter.h ------------------------------------------------===//
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
// Write binary files of traces and chunks to disk.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_MEMORO_TRACEWRITER_H
#define LLVM_MEMORO_TRACEWRITER_H

#include "memoro_common.h"
#include "memoro_stackdepot.h"

namespace __memoro {

class TraceWriter {
public:
  TraceWriter(u64 index_size, u64 data_size);

  ~TraceWriter();

  void WriteTrace(const char *trace_string);
  void WriteTrace(const uptr *trace, u32 sz);

  void WriteChunk(MemoroMemoryChunk &chunk, u32 trace_index);

  // write out the trace and chunk buffers to file
  bool OutputFiles();

private:
  typedef u16 RelativeIndex;

  bool WriteLargeBufferToFile(const fd_t outfile, const char *buffer, const u64 buffer_size);
  void resize(char *&data, u64 &length);
  char *trace_index;
  char *chunk_index;
  char *trace_data;
  char *chunk_data;
  u64 trace_data_length = 0;
  u64 chunk_data_length = 0;
  u64 trace_index_length = 0;
  u64 chunk_index_length = 0;
  u64 trace_data_position = 0;
  u64 chunk_data_position = 0;
  u64 trace_index_position = 0;
  u64 chunk_index_position = 0;
  u32 chunk_index_size = 0;
  u32 trace_index_size = 0;
};

} // namespace __memoro
#endif // LLVM_MEMORO_TRACEWRITER_H
