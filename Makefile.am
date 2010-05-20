SUBDIRS = @subdirs@

EXTRA_DIST=liboauth.lsm.in oauth.pc.in Doxyfile.in COPYING.GPL COPYING.MIT LICENSE.OpenSSL

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = oauth.pc

TESTS=tests/tcwiki tests/tceran tests/tcother

CLEANFILES = stamp-doxygen stamp-doc

MAINTAINERCLEANFILES = \
	src/Makefile.in \
	tests/Makefile.in \
	tests/atconfig \
	doc/Makefile.in \
	Makefile.in \
	aclocal.m4 \
	compile \
	config.guess \
	config.h.in \
	config.sub \
	configure \
	depcomp \
	install-sh \
	missing

dox: stamp-doxygen

stamp-doxygen: src/oauth.h doc/mainpage.dox
	$(DOXYGEN) Doxyfile && touch stamp-doxygen
	cp doc/man/man3/oauth.h.3 doc/oauth.3
