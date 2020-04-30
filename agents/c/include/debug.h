#ifndef DEBUG_H_
#define DEBUG_H_

#ifdef DEBUG
#define DEBUG_PRINT(x, ...) printf(x, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(x, ...)
#endif

#endif
