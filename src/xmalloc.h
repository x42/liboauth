#ifndef _OAUTH_XMALLOC_H
#define _OAUTH_XMALLOC_H      1 

/* Prototypes for functions defined in xmalloc.c  */
void *xmalloc (size_t size);
void *xcalloc (size_t nmemb, size_t size);
void *xrealloc (void *ptr, size_t size);
char *xstrdup (const char *s);

/* POSIX - avoid compiler warnings with '-posix -std=c99 -pedantic' */
int strncasecmp(const char *s1, const char *s2, size_t n);
int snprintf(char *str, size_t size, const char *format, ...);
FILE *popen(const char *command, const char *type);
int pclose(FILE *stream);

#endif
