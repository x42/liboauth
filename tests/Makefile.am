noinst_PROGRAMS = oauthtest

OAUTHDIR =../src
INCLUDES = -I$(srcdir)/$(OAUTHDIR)

oauthtest_SOURCES = oauthtest.c
oauthtest_LDADD = $(LTCSMPTEDIR)/liboauth.la 

check: $(noinst_PROGRAMS)
	 date
	 uname -a
	 @echo "-----------------------------------------------------------------"
	 @echo "running oauth test tool"
	 ./oauthtest  || FAIL=1
	 @echo "-----------------------------------------------------------------"
	 @if [ -z "${FAIL}" ]; then 
	 @echo "  ${PACKAGE}-${VERSION} selftest failed."
	 @else
	 @echo "  ${PACKAGE}-${VERSION} passed all tests."
	 @fi
	 @echo "-----------------------------------------------------------------"
