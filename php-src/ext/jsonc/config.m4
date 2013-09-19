dnl
dnl $Id$
dnl

PHP_ARG_ENABLE(jsonc, whether to enable JavaScript Object Serialization support,
[  --disable-jsonc          Disable JavaScript Object Serialization support (json.so)], yes)

dnl PHP_ARG_WITH(jsonc, whether to rename module file to jsonc,
dnl [  --with-jsonc            JSON: rename module file to jsonc.so], no, no)

PHP_ARG_WITH(libjson, libjson,
[  --with-libjson          JSON: use system json-c], no, no)

if test "$PHP_JSONC" != "no"; then
	AC_GNU_SOURCE
	AC_DEFINE([HAVE_JSON], 1 ,[whether to enable JavaScript Object Serialization support])
	AC_HEADER_STDC

	if test "$PHP_LIBJSON" != "no"; then
		AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
		AC_MSG_CHECKING(JSON-C version)
		if test -x "$PKG_CONFIG" && $PKG_CONFIG --exists json-c; then
			LIBJSON_INCLUDE=`$PKG_CONFIG json-c --cflags`
			LIBJSON_LIBRARY=`$PKG_CONFIG json-c --libs`
			LIBJSON_VERSION=`$PKG_CONFIG json-c --modversion`
		fi

		if test -z "$LIBJSON_VERSION"; then
			AC_MSG_RESULT(version not found)
			AC_MSG_ERROR(Please reinstall json-c version >= 0.11)
		else
			AC_MSG_RESULT(version=$LIBJSON_VERSION include=$LIBJSON_INCLUDE library=$LIBJSON_LIBRARY)
		fi

		PHP_CHECK_LIBRARY(json-c, json_tokener_new_ex,
		[
			AC_DEFINE_UNQUOTED(HAVE_LIBJSON, 1, [use system libjson-c])
		],[
			AC_MSG_ERROR([Sorry, Incompatible json-c library, requires version >= 0.11])
		],[
			$LIBJSON_LIBRARY
		])

		PHP_EVAL_INCLINE($LIBJSON_INCLUDE)
		PHP_EVAL_LIBLINE($LIBJSON_LIBRARY, JSONC_SHARED_LIBADD)
		PHP_EVAL_LIBLINE($LIBJSON_LIBRARY, JSON_SHARED_LIBADD)
	else
    AC_DEFINE(HAS_SSCANF_ERANGE, 1, [Whether correctly return ERANGE])
		AC_CHECK_HEADERS(fcntl.h limits.h strings.h syslog.h unistd.h [sys/param.h] stdarg.h inttypes.h locale.h)
		AC_CHECK_FUNCS(strcasecmp strdup strndup strerror snprintf vsnprintf vasprintf open vsyslog strncasecmp setlocale)

		PHP_LIBJSON_SOURCES="json-c/arraylist.c \
							json-c/debug.c \
							json-c/json_c_version.c \
							json-c/json_object.c \
							json-c/json_object_iterator.c \
							json-c/json_tokener.c \
							json-c/json_util.c \
							json-c/linkhash.c \
							json-c/printbuf.c"
	fi

	if test "$PHP_JSONC" != "no"; then
		PHP_NEW_EXTENSION(jsonc, json.c $PHP_LIBJSON_SOURCES, $ext_shared)
    PHP_ADD_BUILD_DIR($ext_builddir/json-c)
		PHP_SUBST(JSONC_SHARED_LIBADD)
	fi

	PHP_INSTALL_HEADERS([ext/jsonc], [php_json.h])
fi
