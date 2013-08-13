AC_PREREQ(2.59)
m4_include(../../version.m4)
AC_INIT([ipa-tests],
        IPA_VERSION,
        [https://hosted.fedoraproject.org/projects/freeipa/newticket])

AM_INIT_AUTOMAKE([foreign])

AM_MAINTAINER_MODE

AC_SUBST(VERSION)
AC_SUBST([INSTALL_DATA], ['$(INSTALL) -m 644 -p'])

AC_PROG_MKDIR_P
AC_PROG_AWK
AC_PROG_SED

# Files

AC_CONFIG_FILES([
    Makefile
])

AC_OUTPUT
