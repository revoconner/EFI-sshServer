/* Freestanding string.h for this project. Implementations live in uefirt.c. */
#ifndef RT_STRING_H_
#define RT_STRING_H_
#include <stddef.h>
void  *memcpy(void *d, const void *s, size_t n);
void  *memmove(void *d, const void *s, size_t n);
void  *memset(void *d, int c, size_t n);
int    memcmp(const void *a, const void *b, size_t n);
void  *memchr(const void *s, int c, size_t n);
size_t strlen(const char *s);
int    strcmp(const char *a, const char *b);
int    strncmp(const char *a, const char *b, size_t n);
char  *strncpy(char *d, const char *s, size_t n);
char  *strcpy(char *d, const char *s);
char  *strcat(char *d, const char *s);
char  *strchr(const char *s, int c);
char  *strrchr(const char *s, int c);
char  *strstr(const char *h, const char *n);
int    strncasecmp(const char *a, const char *b, size_t n);
int    strcasecmp(const char *a, const char *b);
#endif
