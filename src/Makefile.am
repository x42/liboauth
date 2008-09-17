lib_LTLIBRARIES = liboauth.la
include_HEADERS = oauth.h 

liboauth_la_SOURCES=oauth.c config.h xmalloc.c xmalloc.h oauth_http.c
liboauth_la_LIBADD=-lm -lcrypto @CURL_LIBS@
liboauth_la_LDFLAGS=-g -Wall 
liboauth_la_CFLAGS=-Wall @LIBOAUTH_CFLAGS@
