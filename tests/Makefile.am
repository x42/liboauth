noinst_PROGRAMS = oauthexample oauthdatapost tcwiki tceran tcother oauthtest oauthtest2 oauthsign oauthbodyhash
ACLOCAL_AMFLAGS= -I m4

OAUTHDIR =../src
INCLUDES = -I$(srcdir)/$(OAUTHDIR)
MYCFLAGS = @LIBOAUTH_CFLAGS@ @HASH_CFLAGS@ @CURL_CFLAGS@ 
MYLDADD  = $(OAUTHDIR)/liboauth.la @HASH_LIBS@ @CURL_LIBS@

tcwiki_SOURCES = selftest_wiki.c commontest.c commontest.h
tcwiki_LDADD = $(MYLDADD)
tcwiki_CFLAGS = -Wall -DTEST_UNICODE

tceran_SOURCES = selftest_eran.c commontest.c commontest.h
tceran_LDADD = $(MYLDADD)
tceran_CFLAGS = -Wall $(MYCFLAGS)

tcother_SOURCES = selftest_other.c commontest.c commontest.h
tcother_LDADD = $(MYLDADD)
tcother_CFLAGS = -Wall $(MYCFLAGS)

oauthtest_SOURCES = oauthtest.c
oauthtest_LDADD = $(MYLDADD)
oauthtest_CFLAGS = -Wall $(MYCFLAGS)

oauthtest2_SOURCES = oauthtest2.c
oauthtest2_LDADD = $(MYLDADD)
oauthtest2_CFLAGS = -Wall $(MYCFLAGS)

oauthexample_SOURCES = oauthexample.c
oauthexample_LDADD = $(MYLDADD)
oauthexample_CFLAGS = -Wall $(MYCFLAGS)

oauthsign_SOURCES = oauthsign.c
oauthsign_LDADD = $(MYLDADD)
oauthsign_CFLAGS = -Wall $(MYCFLAGS)

oauthdatapost_SOURCES = oauthdatapost.c
oauthdatapost_LDADD = $(MYLDADD)
oauthdatapost_CFLAGS = -Wall $(MYCFLAGS)

oauthbodyhash_SOURCES = oauthbodyhash.c
oauthbodyhash_LDADD = $(MYLDADD)
oauthbodyhash_CFLAGS = -Wall $(MYCFLAGS)
