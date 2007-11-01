AC_PREREQ(2.59c)
AC_INIT([freeipa-client],
        [0.3.1],
        [https://hosted.fedoraproject.org/projects/freeipa/newticket])

AC_CONFIG_SRCDIR([ipaclient/__init__.py])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

AM_MAINTAINER_MODE

AC_SUBST(VERSION)

dnl ---------------------------------------------------------------------------
dnl - Check for Python
dnl ---------------------------------------------------------------------------

AC_MSG_NOTICE([Checking for Python])
have_python=no
AM_PATH_PYTHON(2.3)

if test "x$PYTHON" = "x" ; then
  AC_MSG_ERROR([Python not found])
fi

dnl ---------------------------------------------------------------------------
dnl - Set the data install directory since we don't use pkgdatadir
dnl ---------------------------------------------------------------------------

IPA_DATA_DIR="$datadir/ipa"
AC_SUBST(IPA_DATA_DIR)

dnl ---------------------------------------------------------------------------
dnl Finish
dnl ---------------------------------------------------------------------------

# Files

AC_CONFIG_FILES([
    Makefile
    firefox/Makefile
    ipaclient/Makefile
    ipa-install/Makefile
])

AC_OUTPUT

echo "
                    FreeIPA client $VERSION
                    ========================

	prefix:                   ${prefix}
	exec_prefix:              ${exec_prefix}
        libdir:                   ${libdir}
        bindir:                   ${bindir}
        sbindir:                  ${sbindir}
        sysconfdir:               ${sysconfdir}
        localstatedir:            ${localstatedir}
        datadir:                  ${datadir}
	source code location:	  ${srcdir}
        Maintainer mode:          ${USE_MAINTAINER_MODE}
"
