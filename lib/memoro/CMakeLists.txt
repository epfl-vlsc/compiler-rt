add_compiler_rt_component(memoro)

set(MEMORO_CFLAGS ${SANITIZER_COMMON_CFLAGS})
append_rtti_flag(OFF MEMORO_CFLAGS)

include_directories(..)

set(MEMORO_COMMON_SOURCES
        memoro_common.cc
        memoro_common_linux.cc
        memoro_common_mac.cc)

set(MEMORO_SOURCES
        memoro.cc
        memoro_flags.cc
        memoro_allocator.cc
        memoro_linux.cc
        memoro_interceptors.cc
        memoro_interface.cpp
        memoro_timer.cc
        memoro_stackdepot.cc
        memoro_tracewriter.cc
        memoro_malloc_mac.cc
        memoro_preinit.cc
        memoro_thread.cc)

set(MEMORO_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_compiler_rt_object_libraries(RTMemoroCommon
    OS ${SANITIZER_COMMON_SUPPORTED_OS}
    ARCHS ${MEMORO_COMMON_SUPPORTED_ARCH}
    SOURCES ${MEMORO_COMMON_SOURCES}
    CFLAGS ${MEMORO_CFLAGS})

if(COMPILER_RT_HAS_MEMORO)
  if(APPLE)
    add_weak_symbols("memoro" WEAK_SYMBOL_LINK_FLAGS)
    add_weak_symbols("sanitizer_common" WEAK_SYMBOL_LINK_FLAGS)

    add_compiler_rt_runtime(clang_rt.memoro
      SHARED
      OS ${SANITIZER_COMMON_SUPPORTED_OS}
      ARCHS ${MEMORO_SUPPORTED_ARCH}
      SOURCES ${MEMORO_SOURCES}
      OBJECT_LIBS RTMemoroCommon
                  RTInterception
                  RTSanitizerCommon
                  RTSanitizerCommonLibc
                  RTSanitizerCommonSymbolizer
      CFLAGS ${MEMORO_CFLAGS}
      LINK_FLAGS ${WEAK_SYMBOL_LINK_FLAGS}
      PARENT_TARGET memoro)
  else()
    set(MEMORO_COMMON_RUNTIME_OBJECT_LIBS
      RTMemoroCommon
      RTInterception
      RTSanitizerCommon
      RTSanitizerCommonLibc
      RTSanitizerCommonSymbolizer)

    foreach(arch ${MEMORO_SUPPORTED_ARCH})
      add_compiler_rt_runtime(clang_rt.memoro
        STATIC
        ARCHS ${arch}
        SOURCES ${MEMORO_SOURCES}
                $<TARGET_OBJECTS:RTInterception.${arch}>
                $<TARGET_OBJECTS:RTSanitizerCommon.${arch}>
                $<TARGET_OBJECTS:RTSanitizerCommonLibc.${arch}>
                $<TARGET_OBJECTS:RTMemoroCommon.${arch}>
        OBJECT_LIBS ${MEMORO_COMMON_RUNTIME_OBJECT_LIBS}
        CFLAGS ${MEMORO_CFLAGS})

    endforeach()
  endif()
endif()
