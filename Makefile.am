SUBDIRS = @subdirs@

EXTRA_DIST=liboauth.lsm.in liboauth.spec.in auth.pc.in Doxyfile.in

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = oauth.pc

#  if you write a self-test script named `chk', uncomment the
#  following and add `chk' to the EXTRA_DIST list
#TESTS=chk

CLEANFILES = stamp-doxygen stamp-doc

dox: stamp-doxygen

stamp-doxygen: src/framerate.h src/framerate.c doc/mainpage.dox
	$(DOXYGEN) Doxyfile
	touch stamp-doxygen
