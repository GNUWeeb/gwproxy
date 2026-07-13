// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWPROXY__COMMON_H
#define GWPROXY__COMMON_H

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

#ifndef __unused
#define __unused	__attribute__((__unused__))
#endif

#ifndef __cold
#define __cold		__attribute__((__cold__))
#endif

#ifndef __hot
#define __hot		__attribute__((__hot__))
#endif

#ifndef noinline
#define noinline	__attribute__((__noinline__))
#endif

#ifdef __CHECKER__
#define __must_hold(x) __attribute__((context(x,1,1)))
#define __acquires(x)  __attribute__((context(x,0,1)))
#define __releases(x)  __attribute__((context(x,1,0)))
#else
#define __must_hold(x)
#define __acquires(x)
#define __releases(x)
#endif

#define PTR_TO_U64(x) ((uint64_t)(uintptr_t)(x))
#define U64_TO_PTR(x) ((void *)(uintptr_t)(x))

#endif /* #ifndef GWPROXY__COMMON_H */
