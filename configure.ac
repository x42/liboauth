AC_PREREQ(2.57)
AC_INIT([liboauth], [-], [robin AT gareus DOT org])
#AM_MAINTAINER_MODE

AC_PATH_PROG(SED, sed, "", $PATH:/bin:/usr/bin:/usr/local/bin)
if test -z "$SED"; then
  AC_MSG_WARN([sed was not found])
fi

AC_MSG_CHECKING([liboauth version])
VERSION=`$SED -ne 's/^#define LIBOAUTH_VERSION "\(.*\)"/\1/p' ${srcdir}/src/oauth.h 2>/dev/null`
AC_MSG_RESULT($VERSION)
if test -z "$VERSION"; then
  AC_MSG_ERROR([version number can not be retrieved from src/oauth.h])
fi

AC_CONFIG_SRCDIR([src/oauth.c])
AC_CONFIG_TESTDIR([tests])
AC_CANONICAL_TARGET([])
AC_COPYRIGHT([Copyright (C) Robin Gareus 2007, 2008])
AM_INIT_AUTOMAKE(liboauth,$VERSION)

AM_CONFIG_HEADER(src/config.h)

AC_SUBST(VERSION)
ISODATE=`date +%Y-%m-%d`
AC_SUBST(ISODATE)

AC_CANONICAL_HOST

AC_PROG_INSTALL
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_LN_S
AC_PROG_LIBTOOL
AM_PROG_LIBTOOL
AM_PROG_CC_C_O

AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h time.h string.h alloca.h stdio.h stdarg.h math.h openssl/hmac.h)

AC_HEADER_MAJOR
AC_FUNC_ALLOCA
AC_STRUCT_TM
AC_STRUCT_ST_BLOCKS
AC_FUNC_CLOSEDIR_VOID

AH_TEMPLATE([HAVE_CURL], [Define as 1 if you have libcurl])
AH_TEMPLATE([USE_LGPL], [Define as 1 if you agree with the GNU Lesser General Public License])


dnl *** configuration options ***
AC_ARG_ENABLE(lgpl, AC_HELP_STRING([--enable-lgpl],[compile coder under LGPL]))
report_license="MIT"
if test "$enable_lgpl" == "yes"; then
  AC_DEFINE(USE_LGPL, 1, [Define if you agree with the GNU Lesser General Public License])
  USE_LGPL=1 report_license="LGPL"
fi

report_curl="no"
PKG_CHECK_MODULES(CURL, libcurl, [ AC_DEFINE(HAVE_CURL, 1, [Define if you have libcurl]) HAVE_CURL=1 report_curl="libcurl" ], [ report_curl="commandline http client" ] )
#CURL_LIBS="-lcurl"
AC_SUBST(CURL_LIBS)


dnl *** complier flags ***
#LIBOAUTH_CFLAGS="-g -posix -std=c99 -pedantic"
LIBOAUTH_CFLAGS=""
AC_SUBST(LIBOAUTH_CFLAGS)


dnl *** doxygen ***
AC_ARG_VAR(DOXYGEN, Doxygen)
AC_PATH_PROG(DOXYGEN, doxygen, no)

if test "$DOXYGEN" != "no"; then
  DOXMAKE='run "make dox" to generate API html reference: doc/html/index.html'
fi

dnl *** graphviz ***
dnl (needed for Doxyfile.in)
AC_ARG_VAR(DOT, The 'dot' program from graphviz)
AC_PATH_PROG(DOT, dot, no)
if test "$DOT" != "no"; then
  HAVEDOT=YES
  DOTPATH=$( dirname "$DOT" )
else
  HAVEDOT=NO
fi
AC_SUBST(HAVEDOT)
AC_SUBST(DOTPATH)


dnl *** perl ***
dnl (needed for Doxyfile.in)
AC_ARG_VAR(PERL, Perl)
AC_PATH_PROG(PERL, perl, no)
if test "$PERL" == "no"; then
  AC_MSG_WARN([dude, where's your perl? doxygen will not like this!)])
fi


dnl *** output ***
subdirs="src doc tests"
AC_SUBST(subdirs)

AC_OUTPUT(Makefile src/Makefile doc/Makefile tests/Makefile liboauth.lsm oauth.pc Doxyfile doc/mainpage.dox)

AC_MSG_NOTICE([

 liboauth configured:
 -----------------------

  license:                $report_license
  http integration:       $report_curl
  generate documentation: $DOXYGEN
  installation prefix:    $prefix

 type "make" followed my "make install" as root.
 $DOXMAKE
])
