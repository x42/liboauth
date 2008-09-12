noinst_PROGRAMS = oauthtest oauthexample oauthdatapost

OAUTHDIR =../src
INCLUDES = -I$(srcdir)/$(OAUTHDIR)

oauthtest_SOURCES = oauthtest.c
oauthtest_LDADD = $(OAUTHDIR)/liboauth.la -lssl
oauthtest_CFLAGS = -Wall @LIBOAUTH_CFLAGS@

oauthexample_SOURCES = oauthexample.c
oauthexample_LDADD = $(OAUTHDIR)/liboauth.la -lssl
oauthexample_CFLAGS = -Wall @LIBOAUTH_CFLAGS@

oauthdatapost_SOURCES = oauthdatapost.c
oauthdatapost_LDADD = $(OAUTHDIR)/liboauth.la -lssl
oauthdatapost_CFLAGS = -Wall @LIBOAUTH_CFLAGS@
