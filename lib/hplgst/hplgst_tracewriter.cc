//
// Created by Stuart Byma on 06.09.17.
//

#include "hplgst_tracewriter.h"

namespace __hplgst {

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

  void TraceWriter::WriteChunk(HplgstMemoryChunk &chunk, u32 trace_index) {
    //Printf("writing chunk \n");

    RelativeIndex size = static_cast<u16>(sizeof(HplgstMemoryChunk));
    if (chunk_index_length - chunk_index_position < sizeof(size)) {
      resize(chunk_index, chunk_index_length); // double
    }
    internal_memcpy(chunk_index + chunk_index_position, reinterpret_cast<const char*>(&size), sizeof(size));
    chunk_index_position += sizeof(size);
    chunk_index_size++;

    chunk.stack_index = trace_index;
    if (chunk_data_length - chunk_data_position < sizeof(HplgstMemoryChunk)) {
      resize(chunk_data, chunk_data_length); // double
    }
    internal_memcpy(chunk_data + chunk_data_position, reinterpret_cast<char*>(&chunk), sizeof(HplgstMemoryChunk));
    chunk_data_position += sizeof(HplgstMemoryChunk);

  }

  // this version writes the stack trace addresses directly, assuming
  // that downstream tools will use the symbolizer and binary to decode
  void TraceWriter::WriteTrace(const uptr* trace, u32 sz) {
    Printf("the call stack size is %d\n", sz);
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

    RelativeIndex size = static_cast<u16>(len);
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

  TraceWriter::~TraceWriter() {
    Header header;
    header.version_minor = 1;
    header.version_major = 0;
    header.segment_start = sizeof(Header);
    header.index_size = trace_index_size;
    Printf("writer writing files ...");

    char namebuf[4096];
    ReadBinaryNameCached(namebuf, 4096);
    u32 len = internal_strlen(namebuf);
    internal_strncpy(namebuf + len, ".trace", 6);

    uptr bytes_written, total_written = 0;
    fd_t hplgst_outfile = OpenFile(namebuf, FileAccessMode::WrOnly);
    WriteToFile(hplgst_outfile, reinterpret_cast<char*>(&header), sizeof(Header), &bytes_written);
    total_written += bytes_written;
    if (bytes_written != sizeof(Header))
      Printf("write header failed!!");
    WriteToFile(hplgst_outfile, trace_index, trace_index_position, &bytes_written);
    total_written += bytes_written;
    if (bytes_written != trace_index_position)
      Printf("write trace index failed!!");
    WriteToFile(hplgst_outfile, trace_data, trace_data_position, &bytes_written);
    total_written += bytes_written;
    if (bytes_written != trace_data_position)
      Printf("write trace data failed!!");
    CloseFile(hplgst_outfile);

    //Printf("total trace: %d \n", total_written);
    total_written = 0;

    header.index_size = chunk_index_size;
    internal_strncpy(namebuf + len, ".chunks", 7);

    hplgst_outfile = OpenFile(namebuf, FileAccessMode::WrOnly);
    WriteToFile(hplgst_outfile, reinterpret_cast<char*>(&header), sizeof(Header), &bytes_written);
    total_written += bytes_written;
    if (bytes_written != sizeof(Header))
      Printf("write chunk header failed!!");
    WriteToFile(hplgst_outfile, chunk_index, chunk_index_position, &bytes_written);
    total_written += bytes_written;
    if (bytes_written != chunk_index_position)
      Printf("write chunk index failed!!");
    WriteToFile(hplgst_outfile, chunk_data, chunk_data_position, &bytes_written);
    total_written += bytes_written;
    if (bytes_written != chunk_data_position)
      Printf("write chunk data failed!!");
    CloseFile(hplgst_outfile);

    // for some reason, almost a megabyte of zeroes gets tacked onto the end of the file :-/
/*    Printf("total chunk: %d \n", total_written);
    Printf("c data position was %d, index position was %d, total = %d \n", chunk_data_position, chunk_index_position,
           chunk_data_position+chunk_index_position);*/
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
