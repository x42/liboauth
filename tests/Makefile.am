noinst_PROGRAMS = oauthexample oauthdatapost tcwiki tceran tcother oauthtest oauthtest2 oauthsign oauthbodyhash
ACLOCAL_AMFLAGS= -I m4

OAUTHDIR =../src
INCLUDES = -I$(srcdir)/$(OAUTHDIR)

tcwiki_SOURCES = selftest_wiki.c commontest.c commontest.h
tcwiki_LDADD = $(OAUTHDIR)/liboauth.la -lssl
tcwiki_CFLAGS = -Wall @LIBOAUTH_CFLAGS@ -DTEST_UNICODE

tceran_SOURCES = selftest_eran.c commontest.c commontest.h
tceran_LDADD = $(OAUTHDIR)/liboauth.la -lssl
tceran_CFLAGS = -Wall @LIBOAUTH_CFLAGS@ -DTEST_UNICODE

tcother_SOURCES = selftest_other.c commontest.c commontest.h
tcother_LDADD = $(OAUTHDIR)/liboauth.la -lssl
tcother_CFLAGS = -Wall @LIBOAUTH_CFLAGS@ -DTEST_UNICODE

oauthtest_SOURCES = oauthtest.c
oauthtest_LDADD = $(OAUTHDIR)/liboauth.la -lssl
oauthtest_CFLAGS = -Wall @LIBOAUTH_CFLAGS@

oauthtest2_SOURCES = oauthtest2.c
oauthtest2_LDADD = $(OAUTHDIR)/liboauth.la -lssl
oauthtest2_CFLAGS = -Wall @LIBOAUTH_CFLAGS@

oauthexample_SOURCES = oauthexample.c
oauthexample_LDADD = $(OAUTHDIR)/liboauth.la -lssl
oauthexample_CFLAGS = -Wall @LIBOAUTH_CFLAGS@

oauthsign_SOURCES = oauthsign.c
oauthsign_LDADD = $(OAUTHDIR)/liboauth.la -lssl
oauthsign_CFLAGS = -Wall @LIBOAUTH_CFLAGS@

oauthdatapost_SOURCES = oauthdatapost.c
oauthdatapost_LDADD = $(OAUTHDIR)/liboauth.la -lssl
oauthdatapost_CFLAGS = -Wall @LIBOAUTH_CFLAGS@

oauthbodyhash_SOURCES = oauthbodyhash.c
oauthbodyhash_LDADD = $(OAUTHDIR)/liboauth.la -lssl
oauthbodyhash_CFLAGS = -Wall @LIBOAUTH_CFLAGS@
