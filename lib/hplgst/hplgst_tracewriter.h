//
// Created by Stuart Byma on 06.09.17.
//

#ifndef LLVM_HPLGST_TRACEWRITER_H
#define LLVM_HPLGST_TRACEWRITER_H

#include "hplgst_common.h"
#include "hplgst_stackdepot.h"

namespace __hplgst {

  class TraceWriter {
  public:
    TraceWriter(u64 index_size, u64 data_size);

    ~TraceWriter();

    void WriteTrace(const char *trace_string);

    void WriteChunk(HplgstMemoryChunk &chunk, u32 trace_index);

  private:
    typedef u16 RelativeIndex;

    void resize(char*& data, u64& length);
    char* trace_index;
    char* chunk_index;
    char* trace_data;
    char* chunk_data;
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

}
#endif //LLVM_HPLGST_TRACEWRITER_H
