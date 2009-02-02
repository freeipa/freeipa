AC_PREREQ(2.59)
m4_include(../version.m4)
AC_INIT([ipa-server],
        IPA_VERSION,
        [https://hosted.fedoraproject.org/projects/freeipa/newticket])

#AC_CONFIG_SRCDIR([ipaserver/ipaldap.py])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

AM_MAINTAINER_MODE
#AC_PROG_CC
#AC_STDC_HEADERS
#AC_DISABLE_STATIC
#AC_PROG_LIBTOOL

#AC_HEADER_STDC

AC_SUBST(VERSION)

dnl ---------------------------------------------------------------------------
dnl - Set the data install directory since we don't use pkgdatadir
dnl ---------------------------------------------------------------------------

IPA_DATA_DIR="$datadir/ipa"
IPA_SYSCONF_DIR="$sysconfdir/ipa"
AC_SUBST(IPA_DATA_DIR)
AC_SUBST(IPA_SYSCONF_DIR)

# Files

AC_CONFIG_FILES([
    Makefile
    conf/Makefile
    html/Makefile
    share/Makefile
    tools/Makefile
    tools/man/Makefile
    updates/Makefile
])

AC_OUTPUT
