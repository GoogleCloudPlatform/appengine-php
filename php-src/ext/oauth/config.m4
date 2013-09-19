dnl
dnl $Id: config.m4 299931 2010-05-29 04:55:04Z datibbaw $
dnl

PHP_ARG_ENABLE(oauth, for oauth support,
[  --enable-oauth          Include oauth support])

if test "$PHP_OAUTH" != "no"; then
  PHP_SUBST(OAUTH_SHARED_LIBADD)

  PHP_NEW_EXTENSION(oauth, oauth.c provider.c, $ext_shared)
  CFLAGS="$CFLAGS -Wall -g"

  AC_MSG_CHECKING(for cURL in default path)
  for i in /usr/local /usr; do
    if test -r $i/include/curl/easy.h; then
      CURL_DIR=$i
      AC_MSG_RESULT(found in $i)
      break
    fi
  done

  if test -z "$CURL_DIR"; then
    AC_MSG_RESULT(cURL not found, cURL support disabled)
  else
    PHP_ADD_LIBRARY(curl,,OAUTH_SHARED_LIBADD)
    AC_DEFINE(OAUTH_USE_CURL, 1, [Whether cURL is present and should be used])
  fi

  PHP_ADD_EXTENSION_DEP(oauth, hash)
fi
