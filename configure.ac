AC_PREREQ(2.57)
AC_INIT([liboauth], [-], [robin AT gareus DOT org], [], [http://liboauth.sourceforge.net/])
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

VERSION_CUR=`$SED -ne 's/^#define LIBOAUTH_CUR\s*\([0-9]*\)/\1/p' ${srcdir}/src/oauth.h 2>/dev/null`
VERSION_REV=`$SED -ne 's/^#define LIBOAUTH_REV\s*\([0-9]*\)/\1/p' ${srcdir}/src/oauth.h 2>/dev/null`
VERSION_AGE=`$SED -ne 's/^#define LIBOAUTH_AGE\s*\([0-9]*\)/\1/p' ${srcdir}/src/oauth.h 2>/dev/null`
VERSION_INFO=${VERSION_CUR}:${VERSION_REV}:${VERSION_AGE}

AC_CONFIG_SRCDIR([src/oauth.c])
AC_CONFIG_TESTDIR([tests])
AC_CANONICAL_TARGET([])
AC_COPYRIGHT([Copyright (C) Robin Gareus 2007-2010])
AM_INIT_AUTOMAKE(liboauth,$VERSION)

AM_CONFIG_HEADER(src/config.h)

AC_SUBST(VERSION)
AC_SUBST(VERSION_INFO)
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
AC_CONFIG_MACRO_DIR([m4])

AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h time.h string.h alloca.h stdio.h stdarg.h math.h)

AC_HEADER_MAJOR
AC_FUNC_ALLOCA
AC_STRUCT_TM
AC_STRUCT_ST_BLOCKS
AC_FUNC_CLOSEDIR_VOID

AH_TEMPLATE([HAVE_CURL], [Define as 1 if you have libcurl])
AH_TEMPLATE([USE_NSS], [Define to use NSS instead of OpenSSL])
AH_TEMPLATE([HAVE_SHELL_CURL], [Define if you can invoke curl via a shell command. This is only used if HAVE_CURL is not defined.])
AH_TEMPLATE([OAUTH_CURL_TIMEOUT], [Define the number of seconds for the HTTP request to timeout; if not defined no timeout (or libcurl default) is used.])

# PKGconfig oauth.pc.in
PC_REQ=""
PC_LIB=""

dnl *** configuration options ***
AC_ARG_ENABLE(curl, AC_HELP_STRING([--disable-curl],[do not use curl]))
AC_ARG_ENABLE(libcurl, AC_HELP_STRING([--disable-libcurl],[do not use libcurl]))
AC_ARG_ENABLE(nss, AC_HELP_STRING([--enable-nss],[use NSS instead of OpenSSL]))
AC_ARG_WITH([curltimeout], AC_HELP_STRING([--with-curltimeout@<:@=<int>@:>@],[use CURLOPT_TIMEOUT with libcurl HTTP requests. Timeout is given in seconds (default=60). Note: using this option also sets CURLOPT_NOSIGNAL. see http://curl.haxx.se/libcurl/c/curl_easy_setopt.html#CURLOPTTIMEOUT]))

report_curl="no"
dnl ** check for commandline executable curl 
if test "${enable_curl}" != "no"; then
  AC_PATH_PROG(CURL, curl, no, $PATH:/bin:/usr/bin:/usr/local/bin)
  if test "$CURL" != "no"; then
  AC_DEFINE(HAVE_SHELL_CURL, 1)
  report_curl="shell command"
  fi
fi

dnl ** check for libcurl
if test "${enable_libcurl}" != "no"; then
  PKG_CHECK_MODULES(CURL, libcurl, [ AC_DEFINE(HAVE_CURL, 1) HAVE_CURL=1 PC_REQ="$PC_REQ libcurl" PC_LIB="$PC_LIB -lcurl" report_curl="libcurl" ])
fi

report_curltimeout="-"
if test -n "${with_curltimeout}"; then
  if test "${with_curltimeout}" == "yes"; then
    AC_DEFINE(OAUTH_CURL_TIMEOUT, 60)
    report_curltimeout="60"
  else 
    if test "${with_curltimeout}" -gt 0; then
    AC_DEFINE_UNQUOTED(OAUTH_CURL_TIMEOUT, [${with_curltimeout}])
    report_curltimeout=${with_curltimeout}
    fi
  fi
fi

AC_SUBST(CURL_LIBS)

dnl ** crypto/hash lib (OpenSSL or NSS)
if test "${enable_nss}" == "yes"; then
  PKG_CHECK_MODULES(NSS, nss, [ AC_DEFINE(USE_NSS, 1) USE_NSS=1 PC_REQ="$PC_REQ nss" ])
  HASH_LIBS=${NSS_LIBS}
  HASH_CFLAGS=${NSS_CFLAGS}
  report_hash="NSS"
else
  AC_CHECK_HEADERS(openssl/hmac.h)
  HASH_LIBS="-lcrypto"
  HASH_CFLAGS=""
  report_hash="OpenSSL"
  PC_LIB="$PC_LIB -lssl"
  PC_REQ="$PC_REQ libssl"
fi

AC_SUBST(HASH_LIBS)
AC_SUBST(HASH_CFLAGS)

dnl *** other complier/linker flags ***
#LIBOAUTH_CFLAGS="-Wall -g -posix -std=c99 -pedantic"
LIBOAUTH_CFLAGS="-Wall"
LIBOAUTH_LDFLAGS="-Wall -export-symbols-regex '^oauth_.*'"
AC_SUBST(LIBOAUTH_CFLAGS)
AC_SUBST(LIBOAUTH_LDFLAGS)


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

# PKGconfig oauth.pc.in
AC_SUBST(PC_REQ)
AC_SUBST(PC_LIB)


dnl *** output ***
subdirs="src doc tests"
AC_SUBST(subdirs)

AC_OUTPUT(Makefile src/Makefile doc/Makefile tests/Makefile liboauth.lsm oauth.pc Doxyfile doc/mainpage.dox)

AC_MSG_NOTICE([

 liboauth configured:
 -----------------------

  version:                $VERSION
  interface revision:     $VERSION_INFO
  hash/signature:         $report_hash
  http integration:       $report_curl
  libcurl-timeout:        $report_curltimeout
  generate documentation: $DOXYGEN
  installation prefix:    $prefix

 type "make" followed my "make install" as root.
 $DOXMAKE
])
