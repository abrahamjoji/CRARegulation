#ifndef TINYCRC_H
#define TINYCRC_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Fictional vendored library for inventory tests. Not an upstream project. */
uint32_t tinycrc32(const unsigned char *data, size_t length);
const char *tinycrc_version(void);
#ifdef __cplusplus
}
#endif
#endif
