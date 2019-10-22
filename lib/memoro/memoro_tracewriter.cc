//=-- memoro_tracewriter.cc -----------------------------------------------===//
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
// Format is a contiguous array of variable size entries, where entries
// are either stacktraces (allocation points) or chunk metadata.
// Array is preceded by a relative index to allow parsing, and a basic header.
//
// Chunk entries reference the allocation point they belong to by an index
//
//===----------------------------------------------------------------------===//

#include "memoro_tracewriter.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_posix.h"
#include <unistd.h>

namespace __memoro {

struct __attribute__((packed)) Header {
  u8 version_major = 0;
  u8 version_minor = 1;
  u8 compression_type = 0; // uncompressed at the moment
  u16 segment_start;
  u32 index_size;
};

TraceWriter::TraceWriter(u64 trace_count, u64 chunk_count) {
  // Indexes store the offset of items in the file, since traces are variable length
  trace_index_size = trace_count;
  chunk_index_size = chunk_count;
  trace_index_length = trace_count * sizeof(RelativeIndex);
  chunk_index_length = chunk_count * sizeof(RelativeIndex);
  trace_index = (char *)MmapOrDie(trace_index_length, "tracewriterindexbuffer");
  chunk_index = (char *)MmapOrDie(chunk_index_length, "tracewriterindexbuffer");

  // Buffers speed up writting to disk OnExit()
  trace_buffer_length = 64 * 1024 * 1024;
  chunk_buffer_length = 64 * 1024 * 1024;
  trace_buffer = (char *)MmapOrDie(trace_buffer_length, "tracewriterbuffer");
  chunk_buffer = (char *)MmapOrDie(chunk_buffer_length, "tracewriterbuffer");

  char namebuf[4096];
  uptr pid = internal_getpid();
  const char* pname = GetProcessName();

  // Opening trace file
  internal_snprintf(namebuf, 4096, "%s-%d.trace", pname, pid);
  trace_outfile = OpenFile(namebuf, FileAccessMode::WrOnly);
  if (trace_outfile == kInvalidFd) {
    Printf("open trace file failed!");
    Die();
  }

  off_t trace_start = sizeof(Header) + trace_index_length;
  off_t ret = lseek(trace_outfile, trace_start, SEEK_SET);
  if (ret == -1) {
    Printf("lseek trace file failed!");
    Die();
  }

  // Opening chunk file
  internal_snprintf(namebuf, 4096, "%s-%d.chunks", pname, pid);
  chunk_outfile = OpenFile(namebuf, FileAccessMode::WrOnly);
  if (chunk_outfile == kInvalidFd) {
    Printf("open chunk file failed!");
    Die();
  }

  off_t chunk_start = sizeof(Header) + chunk_index_length;
  ret = lseek(chunk_outfile, chunk_start, SEEK_SET);
  if (ret == -1) {
    Printf("lseek chunk file failed!");
    Die();
  }
}

void TraceWriter::WriteChunk(MemoroMemoryChunk &chunk) {
  // Append chunk index (TODO: remove!)
  size_t id_size = sizeof(RelativeIndex);
  size_t chunk_size = sizeof(MemoroMemoryChunk);
  // TODO: Should not be needed
  /* if (UNLIKELY(chunk_index_length - chunk_index_position < id_size)) */
  /*   resize(chunk_index, chunk_index_length); */
  internal_memcpy(chunk_index + chunk_index_position,
                  reinterpret_cast<const char*>(&chunk_size), id_size);
  chunk_index_position += id_size;

  // Flush chunks if out of capacity
  if (UNLIKELY(chunk_buffer_length - chunk_buffer_position < chunk_size))
    flush(chunk_outfile, chunk_buffer, chunk_buffer_position);

  // Append chunk to buffer
  internal_memcpy(chunk_buffer + chunk_buffer_position,
      reinterpret_cast<const char*>(&chunk), chunk_size);
  chunk_buffer_position += chunk_size;
}

// this version writes the stack trace addresses directly, assuming
// that downstream tools will use the symbolizer and binary to decode
// stuart: I haven't figure out how to do this yet
// TODO finish implementation and integrate symbolizing into Memoro visualizer
/* void TraceWriter::WriteTrace(const uptr *trace, u32 sz) { */
/*   Printf("the call stack size is %d\n", sz); */
/*   Printf("trace addrs are \n"); */
/*   for (u32 i = 0; i < sz && trace[i]; i++) { */
/*     uptr pc = StackTrace::GetPreviousInstructionPc(trace[i]); */
/*     Printf("%llx\n", pc); */
/*   } */
/*   return; */

/*   RelativeIndex size = static_cast<u16>(sz * sizeof(uptr)); // size in bytes */
/*   if (trace_index_length - trace_index_position < sizeof(size)) { */
/*     resize(trace_index, trace_index_length); // double */
/*   } */

/*   internal_memcpy(trace_index + trace_index_position, */
/*                   reinterpret_cast<const char *>(&size), sizeof(size)); */
/*   trace_index_position += sizeof(size); */
/*   trace_index_size++; */

/*   if (trace_data_length - trace_data_position < size) { */
/*     resize(trace_data, trace_data_length); // double */
/*   } */
/*   internal_memcpy(trace_data + trace_data_position, trace, size); */
/*   trace_data_position += size; */
/* } */

void TraceWriter::WriteTrace(const char *trace_string) {
  // Append trace index
  uptr len = internal_strlen(trace_string);
  size_t id_size = sizeof(RelativeIndex);
  size_t trace_size = static_cast<u16>(len);
  // TODO: Should not be needed
  /* if (UNLIKELY(trace_index_length - trace_index_position < id_size)) */
  /*   resize(trace_index, trace_index_length); */
  internal_memcpy(trace_index + trace_index_position,
                  reinterpret_cast<const char *>(&trace_size), id_size);
  trace_index_position += id_size;

  // Flush traces if out of capacity
  if (UNLIKELY(trace_buffer_length - trace_buffer_position < trace_size))
    flush(trace_outfile, trace_buffer, trace_buffer_position);

  // Append trace to buffer
  internal_memcpy(trace_buffer + trace_buffer_position,
      trace_string, trace_size);
  trace_buffer_position += trace_size;
}

bool TraceWriter::flush(fd_t outfile, const char* buffer, u64 &buffer_size) {
  bool retval = WriteLargeBufferToFile(outfile, buffer, buffer_size);
  buffer_size = 0;
  return retval;
}

bool TraceWriter::OutputFiles() {
  Header header;
  header.version_minor = 1;
  header.version_major = 0;
  header.segment_start = sizeof(Header);
  header.index_size = trace_index_size;
  // Printf("writer writing files ...\n");

  flush(trace_outfile, trace_buffer, trace_buffer_position);
  flush(chunk_outfile, chunk_buffer, chunk_buffer_position);

  // TRACES
  off_t off = lseek(trace_outfile, 0, SEEK_SET);
  if (off == -1) {
    Printf("lseek trace file failed!");
    return false;
  }

  if (!WriteLargeBufferToFile(trace_outfile, reinterpret_cast<char *>(&header), sizeof(Header))) {
    Printf("write header failed!!");
    return false;
  }

  if (!WriteLargeBufferToFile(trace_outfile, trace_index, trace_index_position)) {
    Printf("write trace index failed!!");
    return false;
  }

  CloseFile(trace_outfile);

  // CHUNKS
  header.index_size = chunk_index_size;

  off = lseek(chunk_outfile, 0, SEEK_SET);
  if (off == -1) {
    Printf("lseek chunk file failed!");
    return false;
  }

  if (!WriteLargeBufferToFile(chunk_outfile, reinterpret_cast<char *>(&header), sizeof(Header))) {
    Printf("write chunk header failed!!");
    return false;
  }

  if (!WriteLargeBufferToFile(chunk_outfile, chunk_index, chunk_index_position)) {
    Printf("write chunk index failed!!");
    return false;
  }

  CloseFile(chunk_outfile);

  return true;
}

TraceWriter::~TraceWriter() {
  UnmapOrDie(trace_index, trace_index_length);
  UnmapOrDie(chunk_index, chunk_index_length);
  UnmapOrDie(trace_buffer, trace_buffer_length);
  UnmapOrDie(chunk_buffer, chunk_buffer_length);
}

bool TraceWriter::WriteLargeBufferToFile(const fd_t outfile, const char *buffer, const u64 buffer_size) {
  uptr bytes_written = 0, total_written = 0;

  while (total_written < buffer_size) {
    if (!WriteToFile(outfile, buffer + total_written, buffer_size - total_written, &bytes_written))
      return false;

    total_written += bytes_written;
  }

  return true;
}

void TraceWriter::resize(char *&data, u64 &length) {
  // grow by doubling
  CHECK_GT(length, 0);
  char *new_data = (char *)MmapOrDie(length * 2, "tracewriterbuffer");
  internal_memcpy(new_data, data, length);
  char *old_data = data;
  data = new_data;
  UnmapOrDie(old_data, length);
  length = length * 2;
}
} // namespace __memoro
