#ifndef LICGEN_COMMON_H
#define LICGEN_COMMON_H

#if defined(UNIX)
#define U64(C) C##UL
#elif defined(WINDOWS)
#define U64(C)  C##ULL
#endif

#endif //LICGEN_COMMON_H
