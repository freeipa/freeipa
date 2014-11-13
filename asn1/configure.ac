AC_PREREQ(2.59)
m4_include(../version.m4)
AC_INIT([ipa-server],
        IPA_VERSION,
        [https://hosted.fedoraproject.org/projects/freeipa/newticket])

AC_CONFIG_HEADERS([config.h])
AC_PROG_CC_C99
AC_PROG_LIBTOOL

AM_INIT_AUTOMAKE([foreign])

AM_MAINTAINER_MODE

AC_SUBST(VERSION)

# Files

AC_CONFIG_FILES([
    Makefile
    asn1c/Makefile
])

AC_OUTPUT
