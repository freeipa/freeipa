AC_PREREQ(2.59)
AC_INIT([ipa-client],
        [0.99.0],
        [http://www.freeipa.org/])

AM_INIT_AUTOMAKE([foreign])

AC_SUBST(VERSION)

dnl ---------------------------------------------------------------------------
dnl - Check for Python
dnl ---------------------------------------------------------------------------

AC_MSG_NOTICE([Checking for Python])
have_python=no
AM_PATH_PYTHON([2.3])

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
])

AC_OUTPUT

echo "
                    IPA client $VERSION
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
