noinst_PROGRAMS = oauthtest oauthexample

OAUTHDIR =../src
INCLUDES = -I$(srcdir)/$(OAUTHDIR)

oauthtest_SOURCES = oauthtest.c
oauthtest_LDADD = $(OAUTHDIR)/liboauth.la -lssl

oauthexample_SOURCES = oauthexample.c
oauthexample_LDADD = $(OAUTHDIR)/liboauth.la -lssl
