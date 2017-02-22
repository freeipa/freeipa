AC_PREREQ(2.59)
AC_CONFIG_MACRO_DIRS([m4])
m4_include(VERSION.m4)
AC_INIT([freeipa],
        IPA_VERSION,
        [https://hosted.fedoraproject.org/projects/freeipa/newticket])

dnl Make sure the build directory name does not contain spaces!
dnl Spaces are causing problems in libtool, makefiles, autoconf itself,
dnl gettextize framework etc.
case "$PWD" in
  *\ * | *\	*)
    AC_MSG_ERROR([whitespace in working directory path is not supported]) ;;
esac

AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign 1.9 tar-pax])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])

AC_PROG_CC_C99
AC_DISABLE_STATIC
LT_INIT

AC_HEADER_STDC

AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])

dnl ---------------------------------------------------------------------------
dnl - Check for NSPR/NSS
dnl ---------------------------------------------------------------------------
PKG_CHECK_MODULES([NSPR], [nspr])
PKG_CHECK_MODULES([NSS], [nss])

dnl ---------------------------------------------------------------------------
dnl - Check for KRB5
dnl ---------------------------------------------------------------------------

PKG_CHECK_MODULES([KRB5], [krb5])

dnl ---------------------------------------------------------------------------
dnl - Check for OpenLDAP SDK
dnl ---------------------------------------------------------------------------

SAVE_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$NSPR_CFLAGS $NSS_CFLAGS"
AC_CHECK_LIB([ldap_r], [ldap_search], [], AC_MSG_ERROR([libldap_r not found]))
AC_CHECK_LIB([lber], [ber_peek_tag], [], AC_MSG_ERROR([liblber not found]))
LDAP_LIBS="-lldap_r -llber"
LDAP_CFLAGS=""
AC_SUBST(LDAP_LIBS)
AC_SUBST(LDAP_CFLAGS)

dnl ---------------------------------------------------------------------------
dnl - Check for OpenSSL Crypto library
dnl ---------------------------------------------------------------------------
PKG_CHECK_MODULES([CRYPTO], [libcrypto])

dnl ---------------------------------------------------------------------------
dnl - Check for Python
dnl ---------------------------------------------------------------------------

AC_MSG_NOTICE([Checking for Python])
AM_PATH_PYTHON([2.7], [],
               [AC_MSG_ERROR([Python not found])])

AC_MSG_CHECKING($(basename $PYTHON) module setuptools )
$PYTHON -c "import setuptools" 2>/dev/null
if test $? -eq 0; then
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([$PYTHON module setuptools is required for installation])
fi

dnl ---------------------------------------------------------------------------
dnl - Check for POPT
dnl ---------------------------------------------------------------------------
POPT_LIBS=
PKG_CHECK_MODULES([POPT], [popt], [],
    [AC_CHECK_HEADER([popt.h], [], [AC_MSG_ERROR([popt.h not found])])
     AC_CHECK_LIB([popt], [poptGetContext], [POPT_LIBS="-lpopt"])
     AC_SUBST(POPT_LIBS)
    ]
)

dnl ---------------------------------------------------------------------------
dnl - Check for SASL
dnl ---------------------------------------------------------------------------
PKG_CHECK_MODULES([SASL], [libsasl2])

dnl ---------------------------------------------------------------------------
dnl - Check for XMLRPC-C
dnl ---------------------------------------------------------------------------
PKG_CHECK_MODULES([XMLRPC], [xmlrpc xmlrpc_client xmlrpc_util], [],
                  [try_xmlrpc_fallback=true])
if test x"$try_xmlrpc_fallback" = xtrue; then
    XMLRPC_LIBS=
    AC_CHECK_HEADER([xmlrpc-c/base.h], [],
                    [AC_MSG_ERROR([xmlrpc-c/base.h not found])])

    AC_CHECK_LIB([xmlrpc_client], [xmlrpc_client_init2],
                 [XMLRPC_LIBS="-lxmlrpc -lxmlrpc_client -lxmlrpc_util"])
    if test "x$XMLRPC_LIBS" = "x" ; then
        AC_MSG_ERROR([xmlrpc-c not found])
    fi
    AC_SUBST(XMLRPC_LIBS)
fi

dnl ---------------------------------------------------------------------------
dnl - Check for libini_config
dnl ---------------------------------------------------------------------------
PKG_CHECK_MODULES([INI], [ini_config >= 1.1.0])

dnl ---------------------------------------------------------------------------
dnl - Check for server dependencies
dnl ---------------------------------------------------------------------------
m4_include([server.m4])

dnl cmocka and nss_wrapper are optional dependencies used only in server
dnl but they use AM_CONDITIONAL which need to be executed every time
dnl it simpler to have them directly in configure.ac
m4_include([unit_tests.m4])

dnl ---------------------------------------------------------------------------
dnl - Get /etc/sysconfig directory path
dnl ---------------------------------------------------------------------------
AC_ARG_WITH([sysconfenvdir],
     [AS_HELP_STRING([--with-sysconfenvdir=DIR],
                     [Directory for daemon environment files])],
     [sysconfenvdir=$with_sysconfenvdir],
     [sysconfenvdir="${sysconfdir}/sysconfig"])
AC_SUBST([sysconfenvdir])

dnl ---------------------------------------------------------------------------
dnl - Set the data install directory since we don't use pkgdatadir
dnl ---------------------------------------------------------------------------

IPA_DATA_DIR="$datadir/ipa"
IPA_SYSCONF_DIR="$sysconfdir/ipa"
AC_SUBST(IPA_DATA_DIR)
AC_SUBST(IPA_SYSCONF_DIR)

dnl ---------------------------------------------------------------------------
dnl Translations
dnl ---------------------------------------------------------------------------
# POTFILES.in needs to be created before calling AM_GNU_GETTEXT
AC_CONFIG_COMMANDS([po/POTFILES.in],
    [find_start_pwd=`pwd` && dnl
     cd "${ac_abs_top_srcdir}" && dnl strip prefixes from find
     find . dnl
          -path "./rpmbuild" -prune -o dnl
          -path "./${PACKAGE}-*" -prune -o dnl dist directories
          -path '*/build' -prune -o dnl Python builds
          -path '*/dist' -prune -o dnl Python dists
          -path './conf*' -prune -o dnl generated by configure
          -name '*.py' -print -o dnl
          -name '*.c' -print -o dnl
          -name '*.h' -print dnl
          > po/POTFILES.in && dnl
     cd "${find_start_pwd}"])
AC_SUBST(GETTEXT_DOMAIN, [ipa])
AM_GNU_GETTEXT_VERSION([0.18.2])
AM_GNU_GETTEXT([external])

dnl integrate our custom hacks into gettextize infrastructure
AC_CONFIG_COMMANDS([po/Makefile-hackit],
    [echo "include Makefile.hack" >> "${ac_abs_top_srcdir}/po/Makefile"])

AC_PROG_MKDIR_P
AC_PROG_AWK
AC_PROG_SED

AC_PATH_PROG(MSGATTRIB, msgattrib, [no])
if test "x$MSGATTRIB" = "xno"; then
    AC_MSG_ERROR([msgattrib not found, install gettext])
fi
AC_SUBST([MSGATTRIB])

dnl ---------------------------------------------------------------------------
dnl IPA platform
dnl ---------------------------------------------------------------------------
AC_ARG_WITH([ipaplatform],
    [AC_HELP_STRING([--with-ipaplatform], [IPA platform module to use])],
    [IPAPLATFORM=${withval}],
    [IPAPLATFORM=""])
AC_MSG_CHECKING([supported IPA platform])

if test "x${IPAPLATFORM}" == "x"; then
    if test -r "/etc/os-release"; then
        IPAPLATFORM=$(. /etc/os-release; echo "$ID")
    else
        AC_MSG_ERROR([unable to read /etc/os-release])
    fi
    if test "x${IPAPLATFORM}" == "x"; then
        AC_MSG_ERROR([unable to find ID variable in /etc/os-release])
    fi
fi

if test ! -d "${srcdir}/ipaplatform/${IPAPLATFORM}"; then
    AC_MSG_ERROR([IPA platform ${IPAPLATFORM} is not supported])
fi

AC_SUBST([IPAPLATFORM])
AC_MSG_RESULT([${IPAPLATFORM}])


dnl ---------------------------------------------------------------------------
dnl Version information from VERSION.m4 and command line
dnl ---------------------------------------------------------------------------
dnl Are we in source tree?
AM_CONDITIONAL([IS_GIT_SNAPSHOT],
               [test "IPA_VERSION_IS_GIT_SNAPSHOT" == "yes"])
AM_COND_IF([IS_GIT_SNAPSHOT], [
    AC_MSG_CHECKING([if source directory is a Git reposistory])
    if test ! -e "${srcdir}/.git"; then
        AC_MSG_ERROR([Git reposistory is required by VERSION.m4 ]
                     [IPA_VERSION_IS_GIT_SNAPSHOT but not found])
    else
        AC_MSG_RESULT([yes])
    fi
])

AC_ARG_WITH([vendor-suffix],
    [AS_HELP_STRING([--with-vendor-suffix=STRING],
                   [Vendor string used by package system, e.g. "-1.fc24"])],
    [VENDOR_SUFFIX=${withval}],
    [VENDOR_SUFFIX=""])

AC_SUBST([API_VERSION], [IPA_API_VERSION])
AC_SUBST([DATA_VERSION], [IPA_DATA_VERSION])
AC_SUBST([NUM_VERSION], [IPA_NUM_VERSION])
AC_SUBST(VENDOR_SUFFIX)
AC_SUBST([VERSION], [IPA_VERSION])
AC_SUBST([GIT_VERSION], [IPA_GIT_VERSION])
# used by Makefile.am for files depending on templates
AC_SUBST([CONFIG_STATUS])

dnl ---------------------------------------------------------------------------
dnl Finish
dnl ---------------------------------------------------------------------------

# Turn on the additional warnings last, so -Werror doesn't affect other tests.

AC_ARG_ENABLE([more-warnings],
    [AC_HELP_STRING([--enable-more-warnings],
    [Maximum compiler warnings])],
    [set_more_warnings="$enableval"],
    [ if test -d $srcdir/../.hg; then
          set_more_warnings=yes
      else
          set_more_warnings=no
      fi
    ]
)
AC_MSG_CHECKING(for more warnings)
if test "$GCC" = "yes" -a "$set_more_warnings" != "no"; then
        AC_MSG_RESULT(yes)
        CFLAGS="\
        -Wall \
        -Wchar-subscripts -Wmissing-declarations -Wmissing-prototypes \
        -Wnested-externs -Wpointer-arith \
        -Wcast-align -Wsign-compare \
        $CFLAGS"

        for option in -Wno-strict-aliasing -Wno-sign-compare; do
                SAVE_CFLAGS="$CFLAGS"
                CFLAGS="$CFLAGS $option"
                AC_MSG_CHECKING([whether gcc understands $option])
                AC_TRY_COMPILE([], [],
                        has_option=yes,
                        has_option=no,)
                if test $has_option = no; then
                        CFLAGS="$SAVE_CFLAGS"
                fi
                AC_MSG_RESULT($has_option)
                unset has_option
                unset SAVE_CFLAGS
        done
        unset option
else
        AC_MSG_RESULT(no)
fi

AM_CONDITIONAL([VERBOSE_MAKE], [test "x${AM_DEFAULT_VERBOSITY}" == "x1"])

dnl ---------------------------------------------------------------------------
dnl Linters
dnl ---------------------------------------------------------------------------
AC_ARG_ENABLE([i18ntests],
    [AC_HELP_STRING(
        [--disable-i18ntests],
        [do not execute ipatests/i18n.py (depends on python-polib)])],
    [],
    [enable_i18ntests="yes"]
)
AC_SUBST([i18ntests])
AM_CONDITIONAL([WITH_POLINT], [test "x${enable_i18ntests}" == "xyes"])

AC_ARG_ENABLE([pylint],
    [AS_HELP_STRING([--disable-pylint], [skip Pylint in make lint target])],
    [PYLINT=$enableval],
    [PYLINT=yes]
)
if test x$PYLINT != xno; then
    AC_MSG_CHECKING([for Pylint])
    $PYTHON -m pylint --version > /dev/null
    if test "$?" != "0"; then
        AC_MSG_ERROR([cannot find pylint for $PYTHON])
    else
        AC_MSG_RESULT([yes])
    fi
fi
AC_SUBST([PYLINT])
AM_CONDITIONAL([WITH_PYLINT], [test "x${PYLINT}" != "xno"])


AC_ARG_WITH([jslint],
    AS_HELP_STRING([--with-jslint=[FILE]],
                   [path to JavaScript linter. Default is autodetection of ]
                   [utility "jsl" ]),
dnl --without-jslint will set JSLINT=no
        [JSLINT=$with_jslint],
        [AC_PATH_PROG([JSLINT], [jsl])]
)
if test "x${JSLINT}" == "x"; then
    AC_MSG_ERROR([cannot find JS lint])
fi
AC_SUBST([JSLINT])
AM_CONDITIONAL([WITH_JSLINT], [test "x${JSLINT}" != "xno"])


# Flags

AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)


# Files
AC_CONFIG_LINKS([ipaplatform/__init__.py:ipaplatform/$IPAPLATFORM/__init__.py
                 ipaplatform/constants.py:ipaplatform/$IPAPLATFORM/constants.py
                 ipaplatform/paths.py:ipaplatform/$IPAPLATFORM/paths.py
                 ipaplatform/services.py:ipaplatform/$IPAPLATFORM/services.py
                 ipaplatform/tasks.py:ipaplatform/$IPAPLATFORM/tasks.py
                ]
)

AC_CONFIG_FILES([
    Makefile
    asn1/Makefile
    asn1/asn1c/Makefile
    client/Makefile
    client/man/Makefile
    contrib/completion/Makefile
    contrib/Makefile
    daemons/dnssec/Makefile
    daemons/Makefile
    daemons/ipa-kdb/Makefile
    daemons/ipa-sam/Makefile
    daemons/ipa-otpd/Makefile
    daemons/ipa-slapi-plugins/Makefile
    daemons/ipa-slapi-plugins/libotp/Makefile
    daemons/ipa-slapi-plugins/ipa-cldap/Makefile
    daemons/ipa-slapi-plugins/ipa-dns/Makefile
    daemons/ipa-slapi-plugins/ipa-enrollment/Makefile
    daemons/ipa-slapi-plugins/ipa-lockout/Makefile
    daemons/ipa-slapi-plugins/ipa-otp-counter/Makefile
    daemons/ipa-slapi-plugins/ipa-otp-lasttoken/Makefile
    daemons/ipa-slapi-plugins/ipa-pwd-extop/Makefile
    daemons/ipa-slapi-plugins/ipa-extdom-extop/Makefile
    daemons/ipa-slapi-plugins/ipa-winsync/Makefile
    daemons/ipa-slapi-plugins/ipa-version/Makefile
    daemons/ipa-slapi-plugins/ipa-uuid/Makefile
    daemons/ipa-slapi-plugins/ipa-modrdn/Makefile
    daemons/ipa-slapi-plugins/ipa-sidgen/Makefile
    daemons/ipa-slapi-plugins/ipa-range-check/Makefile
    daemons/ipa-slapi-plugins/topology/Makefile
    init/systemd/Makefile
    init/Makefile
    install/Makefile
    install/certmonger/Makefile
    install/conf/Makefile
    install/html/Makefile
    install/migration/Makefile
    install/share/Makefile
    install/share/advise/Makefile
    install/share/advise/legacy/Makefile
    install/share/csrgen/Makefile
    install/share/profiles/Makefile
    install/share/schema.d/Makefile
    install/ui/Makefile
    install/ui/css/Makefile
    install/ui/src/Makefile
    install/ui/src/libs/Makefile
    install/ui/images/Makefile
    install/ui/build/Makefile
    install/ui/build/dojo/Makefile
    install/ui/build/freeipa/Makefile
    install/tools/Makefile
    install/tools/man/Makefile
    install/updates/Makefile
    install/restart_scripts/Makefile
    install/wsgi/Makefile
    install/oddjob/Makefile
    ipaclient/Makefile
    ipalib/Makefile
    ipaplatform/Makefile
    ipapython/Makefile
    ipaserver/Makefile
    ipatests/Makefile
    ipatests/man/Makefile
    po/Makefile.in
    po/Makefile.hack
    util/Makefile
])

AC_OUTPUT

echo "
                    IPA Server $VERSION
                    ========================

        vendor version:           ${VERSION}${VENDOR_SUFFIX}
        prefix:                   ${prefix}
        exec_prefix:              ${exec_prefix}
        libdir:                   ${libdir}
        bindir:                   ${bindir}
        sbindir:                  ${sbindir}
        sysconfdir:               ${sysconfdir}
        sysconfenvdir:            ${sysconfenvdir}
        localstatedir:            ${localstatedir}
        datadir:                  ${datadir}
        krb5rundir:               ${krb5rundir}
        systemdsystemunitdir:     ${systemdsystemunitdir}
        systemdtmpfilesdir:       ${systemdtmpfilesdir}
        source code location:     ${srcdir}
        compiler:                 ${CC}
        cflags:                   ${CFLAGS}
        LDAP libs:                ${LDAP_LIBS}
        KRB5 libs:                ${KRB5_LIBS}
        KRAD libs:                ${KRAD_LIBS}
        OpenSSL crypto libs:      ${CRYPTO_LIBS}
"
