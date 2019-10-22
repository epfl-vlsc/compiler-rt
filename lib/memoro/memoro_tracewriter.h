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
  TraceWriter(u64 traces_count, u64 chunks_count);

  ~TraceWriter();

  void WriteTrace(const char *trace_string);
  /* void WriteTrace(const uptr *trace, u32 sz); */

  void WriteChunk(MemoroMemoryChunk &chunk);

  // write out the trace and chunk buffers to file
  bool OutputFiles();

private:
  typedef u16 RelativeIndex;

  bool WriteLargeBufferToFile(const fd_t outfile, const char *buffer, const u64 buffer_size);
  void resize(char *&data, u64 &length);
  bool flush(fd_t outfile, const char* buffer, u64 &buffer_size);
  char *trace_index;
  char *chunk_index;
  u32 chunk_index_size = 0;
  u32 trace_index_size = 0;
  u64 trace_index_length = 0;
  u64 chunk_index_length = 0;
  u64 trace_index_position = 0;
  u64 chunk_index_position = 0;

  char *trace_buffer;
  char *chunk_buffer;
  u64 trace_buffer_length = 0;
  u64 chunk_buffer_length = 0;
  u64 trace_buffer_position = 0;
  u64 chunk_buffer_position = 0;

  fd_t trace_outfile = kInvalidFd;
  fd_t chunk_outfile = kInvalidFd;
};

} // namespace __memoro
#endif // LLVM_MEMORO_TRACEWRITER_H
