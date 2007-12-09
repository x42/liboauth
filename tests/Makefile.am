noinst_PROGRAMS = oauthtest

OAUTHDIR =../src
INCLUDES = -I$(srcdir)/$(OAUTHDIR)

oauthtest_SOURCES = oauthtest.c
oauthtest_LDADD = $(OAUTHDIR)/liboauth.la 

check: $(noinst_PROGRAMS)
	 date
	 uname -a
	 @echo "-----------------------------------------------------------------"
	 @echo "running oauth test tool"
	 ./oauthtest 
	 @echo "-----------------------------------------------------------------"
