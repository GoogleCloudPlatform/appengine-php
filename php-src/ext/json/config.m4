dnl
dnl $Id$
dnl

PHP_ARG_ENABLE(badjson, whether to enable JavaScript Object Serialization support,
[  --enable-badjson          Disable JavaScript Object Serialization support], no)

if test "$PHP_BADJSON" != "no"; then
  AC_DEFINE([HAVE_JSON],1 ,[whether to enable JavaScript Object Serialization support])
  AC_HEADER_STDC

  PHP_NEW_EXTENSION(badjson, bad_json.c bad_utf8_decode.c bad_JSON_parser.c, $ext_shared)
  PHP_INSTALL_HEADERS([ext/json], [php_json.h])
  PHP_SUBST(JSON_SHARED_LIBADD)
fi
