SUBDIRS = @subdirs@

EXTRA_DIST=liboauth.lsm.in oauth.pc.in Doxyfile.in

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = oauth.pc

TESTS=tests/oauthtest

CLEANFILES = stamp-doxygen stamp-doc

dox: stamp-doxygen

stamp-doxygen: src/oauth.h doc/mainpage.dox
	$(DOXYGEN) Doxyfile && touch stamp-doxygen
	cp doc/man/man3/oauth.h.3 doc/oauth.3
