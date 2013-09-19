dnl
dnl $Id$
dnl

PHP_ARG_WITH(iconv, for iconv support,
[  --without-iconv[=DIR]   Exclude iconv support], yes)

if test "$PHP_ICONV" != "no"; then

  PHP_SETUP_ICONV(ICONV_SHARED_LIBADD, [
    iconv_avail="yes";
  ],[
    iconv_avail="no";
  ])

  iconv_avail="yes";

  if test "$iconv_avail" != "no"; then
    PHP_ICONV_PREFIX="$ICONV_DIR"

    CFLAGS="-I$PHP_ICONV_PREFIX/include $CFLAGS"
    LDFLAGS="-L$PHP_ICONV_PREFIX/$PHP_LIBDIR $LDFLAGS"

    PHP_ICONV_H_PATH="$PHP_ICONV_PREFIX/include/iconv.h"

    iconv_impl_name="glibc"

    # Create the directories for a VPATH build:
    $php_shtool mkdir -p ext/iconv
    
    echo > ext/iconv/php_have_bsd_iconv.h
    echo > ext/iconv/php_have_glibc_iconv.h
    echo > ext/iconv/php_have_libiconv.h
    echo > ext/iconv/php_have_ibm_iconv.h

    PHP_DEFINE([HAVE_GLIBC_ICONV],1,[ext/iconv])
    AC_DEFINE([HAVE_GLIBC_ICONV],1,[glibc's iconv implementation])
    PHP_DEFINE([PHP_ICONV_IMPL],[\"glibc\"],[ext/iconv])
    AC_DEFINE([PHP_ICONV_IMPL],["glibc"],[Which iconv implementation to use])

    PHP_DEFINE([ICONV_SUPPORTS_ERRNO],0,[ext/iconv])
    AC_DEFINE([ICONV_SUPPORTS_ERRNO],0,[Whether iconv supports error no or not])

    PHP_NEW_EXTENSION(iconv, iconv.c, $ext_shared,, [-I\"$PHP_ICONV_PREFIX/include\"])
    PHP_SUBST(ICONV_SHARED_LIBADD)
    PHP_INSTALL_HEADERS([ext/iconv/])
  fi
fi
