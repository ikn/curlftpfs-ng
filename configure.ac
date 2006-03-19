AC_INIT(curlftpfs, 0.4)
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
AC_PROG_LIBTOOL
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH

PKG_CHECK_MODULES(GLIB, [glib-2.0])
PKG_CHECK_MODULES(FUSE, [fuse >= 2.2])

LIBCURL_CHECK_CONFIG([yes], [7.7.2], [], [AC_MSG_ERROR(["libcurl not found"])])
if test "$libcurl_protocol_FTP" != yes; then
	AC_MSG_ERROR(["We need libcurl with support for FTP protocol."])
fi

CFLAGS="$CFLAGS -Wall -W -D_REENTRANT $GLIB_CFLAGS $FUSE_CFLAGS $LIBCURL_CPPFLAGS"
LIBS="$GLIB_LIBS $FUSE_LIBS $LIBCURL"

have_fuse_opt_parse=no
AC_CHECK_FUNC([fuse_opt_parse], [have_fuse_opt_parse=yes])
if test "$have_fuse_opt_parse" = no; then
	CFLAGS="$CFLAGS -Icompat"
fi
AM_CONDITIONAL(FUSE_OPT_COMPAT, test "$have_fuse_opt_parse" = no)

AC_CONFIG_FILES([Makefile compat/Makefile])
AC_OUTPUT
