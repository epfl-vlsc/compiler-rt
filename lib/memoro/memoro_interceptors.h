//
// Created by Stuart Byma on 03/08/17.
//

#ifndef LLVM_MEMORO_INTERCEPTORS_H
#define LLVM_MEMORO_INTERCEPTORS_H

#include "interception/interception.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_platform_interceptors.h"

// Use macro to describe if specific function should be
// intercepted on a given platform.
#if !SANITIZER_WINDOWS
# define MEMORO_INTERCEPT_ATOLL_AND_STRTOLL 1
# define MEMORO_INTERCEPT_FORK 1
#else
# define MEMORO_INTERCEPT_ATOLL_AND_STRTOLL 0
# define MEMORO_INTERCEPT_FORK 0
#endif


#if SANITIZER_LINUX && !SANITIZER_ANDROID
# define MEMORO_INTERCEPT___STRDUP 1
#else
# define MEMORO_INTERCEPT___STRDUP 0
#endif

DECLARE_REAL(int, memcmp, const void *a1, const void *a2, __sanitizer::uptr size)
DECLARE_REAL(void*, memcpy, void *to, const void *from, __sanitizer::uptr size)
DECLARE_REAL(void*, memset, void *block, int c, __sanitizer::uptr size)
DECLARE_REAL(char*, strchr, const char *str, int c)
DECLARE_REAL(SIZE_T, strlen, const char *s)
DECLARE_REAL(char*, strncpy, char *to, const char *from, __sanitizer::uptr size)
DECLARE_REAL(__sanitizer::uptr, strnlen, const char *s, __sanitizer::uptr maxlen)
DECLARE_REAL(char*, strstr, const char *s1, const char *s2)

#if !SANITIZER_MAC
#define MEMORO_INTERCEPT_FUNC(name)                                        \
  do {                                                                   \
    if ((!INTERCEPT_FUNCTION(name) || !REAL(name)))                      \
      VReport(1, "AddressSanitizer: failed to intercept '" #name "'\n"); \
  } while (0)
#define MEMORO_INTERCEPT_FUNC_VER(name, ver)                                     \
  do {                                                                         \
    if ((!INTERCEPT_FUNCTION_VER(name, ver) || !REAL(name)))                   \
      VReport(                                                                 \
          1, "AddressSanitizer: failed to intercept '" #name "@@" #ver "'\n"); \
  } while (0)
#else
// OS X interceptors don't need to be initialized with INTERCEPT_FUNCTION.
#define MEMORO_INTERCEPT_FUNC(name)
#endif  // SANITIZER_MAC

#endif //LLVM_MEMORO_INTERCEPTORS_H
