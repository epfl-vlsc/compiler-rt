//
// Created by Stuart Byma on 06.09.17.
//

#include "memoro_tracewriter.h"
#include "sanitizer_common/sanitizer_file.h"

namespace __memoro {

  const u16 MAX_INDEX_SIZE = 1 << 16;

  struct __attribute__((packed)) Header {
    u8 version_major = 0;
    u8 version_minor = 1;
    u8 compression_type = 0;
    u16 segment_start;
    u32 index_size;
  };

  TraceWriter::TraceWriter(u64 index_size, u64 data_size) {
    trace_index = (char*)MmapOrDie(index_size, "tracewriterbuffer");
    chunk_index = (char*)MmapOrDie(index_size, "tracewriterbuffer");
    chunk_data = (char*)MmapOrDie(data_size, "tracewriterbuffer");
    trace_data = (char*)MmapOrDie(data_size, "tracewriterbuffer");
    trace_data_length = data_size;
    chunk_data_length = data_size;
    trace_index_length = index_size;
    chunk_index_length = index_size;
  }

  void TraceWriter::WriteChunk(MemoroMemoryChunk &chunk, u32 trace_index) {
    //Printf("writing chunk \n");

    RelativeIndex size = static_cast<u16>(sizeof(MemoroMemoryChunk));
    if (chunk_index_length - chunk_index_position < sizeof(size)) {
      resize(chunk_index, chunk_index_length); // double
    }
    internal_memcpy(chunk_index + chunk_index_position, reinterpret_cast<const char*>(&size), sizeof(size));
    chunk_index_position += sizeof(size);
    chunk_index_size++;

    chunk.stack_index = trace_index;
    if (chunk_data_length - chunk_data_position < sizeof(MemoroMemoryChunk)) {
      resize(chunk_data, chunk_data_length); // double
    }
    internal_memcpy(chunk_data + chunk_data_position, reinterpret_cast<char*>(&chunk), sizeof(MemoroMemoryChunk));
    chunk_data_position += sizeof(MemoroMemoryChunk);

  }

  // this version writes the stack trace addresses directly, assuming
  // that downstream tools will use the symbolizer and binary to decode
  void TraceWriter::WriteTrace(const uptr* trace, u32 sz) {
    Printf("the call stack size is %d\n", sz);
    Printf("trace addrs are \n");
    for (u32 i = 0; i < sz && trace[i]; i++) {
      uptr pc = StackTrace::GetPreviousInstructionPc(trace[i]);
      Printf("%llx\n", pc);
    }
    return;

    RelativeIndex size = static_cast<u16>(sz * sizeof(uptr)); // size in bytes
    if (trace_index_length - trace_index_position < sizeof(size)) {
      resize(trace_index, trace_index_length); // double
    }

    internal_memcpy(trace_index + trace_index_position, reinterpret_cast<const char*>(&size), sizeof(size));
    trace_index_position += sizeof(size);
    trace_index_size++;

    if (trace_data_length - trace_data_position < size) {
      resize(trace_data, trace_data_length); // double
    }
    internal_memcpy(trace_data + trace_data_position, trace, size);
    trace_data_position += size;

  }

  void TraceWriter::WriteTrace(const char *trace_string) {
    //Printf("writing trace capacity is %d, position is %d trace is: \n %s\n", trace_data_length, trace_data_position, trace_string);
    uptr len = internal_strlen(trace_string);
    //trace_index.push_back((RelativeIndex) len);
    //Printf("pushing back %d \n", len);

    auto size = static_cast<RelativeIndex >(len);
    if (trace_index_length - trace_index_position < sizeof(size)) {
      resize(trace_index, trace_index_length); // double
    }
    internal_memcpy(trace_index + trace_index_position, reinterpret_cast<const char*>(&size), sizeof(size));
    trace_index_position += sizeof(size);
    trace_index_size++;

    if (trace_data_length - trace_data_position < len) {
      resize(trace_data, trace_data_length); // double
    }
    internal_memcpy(trace_data + trace_data_position, trace_string, len);
    trace_data_position += len;
  }

  bool TraceWriter::OutputFiles() {
    Header header;
    header.version_minor = 1;
    header.version_major = 0;
    header.segment_start = sizeof(Header);
    header.index_size = trace_index_size;
    //Printf("writer writing files ...\n");

    uptr pid = internal_getpid();
    char namebuf[4096];
    internal_snprintf(namebuf, 4096, "%s-%d.trace", GetProcessName(), pid);
    //Printf("Trace file written to --> %s \n", namebuf);

    uptr bytes_written, total_written = 0;
    fd_t memoro_outfile = OpenFile(namebuf, FileAccessMode::WrOnly);
    WriteToFile(memoro_outfile, reinterpret_cast<char*>(&header), sizeof(Header), &bytes_written);
    total_written += bytes_written;
    if (bytes_written != sizeof(Header)) {
      Printf("write header failed!!");
      return false;
    }
    WriteToFile(memoro_outfile, trace_index, trace_index_position, &bytes_written);
    total_written += bytes_written;
    if (bytes_written != trace_index_position) {
      Printf("write trace index failed!!");
      return false;
    }
    WriteToFile(memoro_outfile, trace_data, trace_data_position, &bytes_written);
    total_written += bytes_written;
    if (bytes_written != trace_data_position) {
      Printf("write trace data failed!!");
      return false;
    }
    CloseFile(memoro_outfile);

    //Printf("total trace: %d \n", total_written);
    total_written = 0;

    header.index_size = chunk_index_size;
    internal_snprintf(namebuf, 4096, "%s-%d.chunks", GetProcessName(), pid);
    //Printf("Chunks file written to --> %s \n", namebuf);

    memoro_outfile = OpenFile(namebuf, FileAccessMode::WrOnly);
    WriteToFile(memoro_outfile, reinterpret_cast<char*>(&header), sizeof(Header), &bytes_written);
    total_written += bytes_written;
    if (bytes_written != sizeof(Header)) {
      Printf("write chunk header failed!!");
      return false;
    }
    //Printf("writing %d bytes to file\n", chunk_index_position);
    WriteToFile(memoro_outfile, chunk_index, chunk_index_position, &bytes_written);
    total_written += bytes_written;
    if (bytes_written != chunk_index_position) {
      Printf("write chunk index failed!!");
      return false;
    }
    //Printf("writing %d bytes to file\n", chunk_data_position);
    WriteToFile(memoro_outfile, chunk_data, chunk_data_position, &bytes_written);
    total_written += bytes_written;
    if (bytes_written != chunk_data_position) {
      Printf("write chunk data failed!!");
      return false;
    }
    CloseFile(memoro_outfile);

    // for some reason, almost a megabyte of zeroes gets tacked onto the end of the file :-/
/*    Printf("total chunk: %d \n", total_written);
    Printf("c data position was %d, index position was %d, total = %d \n", chunk_data_position, chunk_index_position,
           chunk_data_position+chunk_index_position);*/

    return true;
  }

  TraceWriter::~TraceWriter() {
    UnmapOrDie(trace_data, trace_data_length);
    UnmapOrDie(chunk_data, chunk_data_length);
  }

  void TraceWriter::resize(char *&data, u64 &length) {
    // grow by doubling
    CHECK_GT(length, 0);
    char *new_data = (char*)MmapOrDie(length*2,
                                 "tracewriterbuffer");
    internal_memcpy(new_data, data, length);
    char *old_data = data;
    data = new_data;
    UnmapOrDie(old_data, length);
    length = length*2;

  }
}
