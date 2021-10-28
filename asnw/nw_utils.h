#pragma once

#ifdef __cplusplus 
extern "C" {
#endif
#include <stdlib.h>


// 强制inline
#ifndef FORCE_INLINE
#define FORCE_INLINE inline __attribute__((always_inline))
#endif

// __GLIBC_PREREQ定义在stdlib中
#include <stdlib.h>
#if !__GLIBC_PREREQ(2, 3)
#define __builtin_expect(x, expected_value) (x)
#endif
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#include <assert.h>
#define nw_assert_msg(exp, msg) assert((exp) && (msg))

#define nw_assert_retval(exp, val)                 \
    do {                                        \
        if (likely(exp)) break;                 \
        assert(exp);                            \
        return (val);                           \
    } while (0)

#define nw_assert_retnone(exp)                     \
    do {                                        \
        if (likely(exp)) break;                 \
        assert(exp);                            \
        return;                                 \
    } while (0)

#define nw_assert_break(exp)                       \
    if (unlikely(!(exp))) {                 \
        assert(exp);                        \
        break;                              \
    }

#define nw_assert_continue(exp)                    \
    if (unlikely(!(exp))) {                 \
        assert(exp);                        \
        continue;                           \
    }

#ifndef ARRAY_LEN
#define ARRAY_LEN(array) (sizeof(array)/sizeof(array[0]))
#endif

#ifndef STRNCPY
#define STRNCPY(dst, src) \
do{ \
strncpy(dst, src, sizeof(dst)); \
dst[sizeof(dst)-1] = '\0'; \
}while(0)
#endif

#ifndef SPRINTF
#define SPRINTF(dst, fmt, ...) \
do{\
	int n = snprintf(dst, sizeof(dst), fmt, ##__VA_ARGS__); \
	dst[sizeof(dst) - 1] = '\0'; \
}while(0)
#endif

#ifndef SWAP
#define SWAP(a,b) do{a^=b;b^=a;a^=b;}while(0)
#endif

#ifndef BZERO
#define BZERO(p) memset((p), 0, sizeof(*(p)))
#endif

#define NW_CONCAT(a,b) a##b
#define NW_CONCAT3(a,b,c) a##b##c


#define GET_BIT(d, k) (((d) >> (k)) & 1)
#define SET_BIT(d, k) ((d) |= (1 << (k)))
#define CLEAN_BIT(d, k) ((d) &= (~(1 << (k))))

#ifndef OBJ_PTR_FROM_MEMBER
#define OBJ_PTR_FROM_MEMBER(type, member, member_ptr) ((type*)((uintptr_t)(member_ptr) - offsetof(type, member)))
#endif

#ifdef __cplusplus 
}
#endif