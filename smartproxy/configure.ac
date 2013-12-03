AC_PREREQ(2.59)
m4_include(../version.m4)
AC_INIT([ipa-server],
        IPA_VERSION,
        [https://hosted.fedoraproject.org/projects/freeipa/newticket])

AM_INIT_AUTOMAKE([foreign])

AM_MAINTAINER_MODE

AC_SUBST(VERSION)
AC_SUBST([INSTALL_DATA], ['$(INSTALL) -m 644 -p'])

AC_PROG_MKDIR_P
AC_PROG_AWK
AC_PROG_SED

AC_PATH_PROG(XGETTEXT, xgettext, [no])
if test "x$XGETTEXT" = "xno"; then
    AC_MSG_ERROR([xgettext not found, install gettext])
fi

AC_PATH_PROG(MSGFMT, msgfmt, [no])
if test "x$MSGFMT" = "xno"; then
    AC_MSG_ERROR([msgfmt not found, install gettext])
fi

AC_PATH_PROG(MSGINIT, msginit, [no])
if test "x$MSGINIT" = "xno"; then
    AC_MSG_ERROR([msginit not found, install gettext])
fi

AC_PATH_PROG(MSGMERGE, msgmerge, [no])
if test "x$MSGMERGE" = "xno"; then
    AC_MSG_ERROR([msgmerge not found, install gettext])
fi

AC_PATH_PROG(MSGCMP, msgcmp, [no])
if test "x$MSGCMP" = "xno"; then
    AC_MSG_ERROR([msgcmp not found, install gettext])
fi

AC_PATH_PROG(MSGATTRIB, msgattrib, [no])
if test "x$MSGATTRIB" = "xno"; then
    AC_MSG_ERROR([msgattrib not found, install gettext])
fi

AC_PATH_PROG(TX, tx, [/usr/bin/tx])

AC_ARG_WITH([gettext_domain],
  [AS_HELP_STRING([--with-gettext-domain=name],
    [set the name of the i18n message catalog])],
  [],
  [with_gettext_domain=ipa])
AC_SUBST(GETTEXT_DOMAIN, $with_gettext_domain)

dnl ---------------------------------------------------------------------------
dnl - Set the data install directory since we don't use pkgdatadir
dnl ---------------------------------------------------------------------------

IPA_DATA_DIR="$datadir/ipa"
IPA_SYSCONF_DIR="$sysconfdir/ipa"
LOGROTATE_DIR="$sysconfdir/logrotate.d"
AC_SUBST(IPA_DATA_DIR)
AC_SUBST(IPA_SYSCONF_DIR)
AC_SUBST(LOGROTATE_DIR)

# Files

AC_CONFIG_FILES([
    Makefile
    man/Makefile
])

AC_OUTPUT
