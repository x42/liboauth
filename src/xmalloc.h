#ifndef _OAUTH_XMALLOC_H
#define _OAUTH_XMALLOC_H      1 

#if HAVE_CONFIG_H
# include <config.h>
#endif

#ifndef USE_GPL

#define xmalloc malloc
#define xcalloc calloc
#define xrealloc realloc
#define xstrdup strdup

#else 

/* Prototypes for functions defined in xmalloc.c  */
void *xmalloc (size_t n);
void *xcalloc (size_t n, size_t s);
void *xrealloc (void *p, size_t n);
char *xstrdup (const char *p);

/* POSIX prototypes - avoid compiler warnings with '-posix' */
int strncasecmp(const char *s1, const char *s2, size_t n);
int snprintf(char *str, size_t size, const char *format, ...);
FILE *popen(const char *command, const char *type);
int pclose(FILE *stream);
#endif // USE_GPL

#endif
