include_directories(..)

set(HPLGST_CFLAGS ${SANITIZER_COMMON_CFLAGS})
append_rtti_flag(OFF HPLGST_CFLAGS)

set(HPLGST_COMMON_SOURCES
  hplgst_common.cc
  hplgst_common_linux.cc
  hplgst_common_mac.cc)

set(HPLGST_SOURCES
  hplgst.cc
        hplgst_flags.cc
  hplgst_allocator.cc
  hplgst_linux.cc
  hplgst_interceptors.cc
        hplgst_interface.cpp
        hplgst_timer.cc
        hplgst_stackdepot.cc
        hplgst_tracewriter.cc
  hplgst_malloc_mac.cc
  hplgst_preinit.cc
  hplgst_thread.cc)

set(HPLGST_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_compiler_rt_object_libraries(RTHplgstCommon
    OS ${SANITIZER_COMMON_SUPPORTED_OS}
    ARCHS ${HPLGST_COMMON_SUPPORTED_ARCH}
    SOURCES ${HPLGST_COMMON_SOURCES}
    CFLAGS ${HPLGST_CFLAGS})

if(COMPILER_RT_HAS_HPLGST)
  add_compiler_rt_component(hplgst)
  if(APPLE)
    add_weak_symbols("hplgst" WEAK_SYMBOL_LINK_FLAGS)
    add_weak_symbols("sanitizer_common" WEAK_SYMBOL_LINK_FLAGS)

    add_compiler_rt_runtime(clang_rt.hplgst
      SHARED
      OS ${SANITIZER_COMMON_SUPPORTED_OS}
      ARCHS ${HPLGST_SUPPORTED_ARCH}
      SOURCES ${HPLGST_SOURCES}
      OBJECT_LIBS RTHplgstCommon
                  RTInterception
                  RTSanitizerCommon
                  RTSanitizerCommonLibc
      CFLAGS ${HPLGST_CFLAGS}
      LINK_FLAGS ${WEAK_SYMBOL_LINK_FLAGS}
      PARENT_TARGET hplgst)
  else()
    foreach(arch ${HPLGST_SUPPORTED_ARCH})
      add_compiler_rt_runtime(clang_rt.hplgst
        STATIC
        ARCHS ${arch}
        SOURCES ${HPLGST_SOURCES}
                $<TARGET_OBJECTS:RTInterception.${arch}>
                $<TARGET_OBJECTS:RTSanitizerCommon.${arch}>
                $<TARGET_OBJECTS:RTSanitizerCommonLibc.${arch}>
                $<TARGET_OBJECTS:RTHplgstCommon.${arch}>
        CFLAGS ${HPLGST_CFLAGS})

    endforeach()
  endif()
endif()
