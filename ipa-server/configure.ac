AC_PREREQ(2.59)
AC_INIT([ipa-server],
        [0.6.0],
        [https://hosted.fedoraproject.org/projects/freeipa/newticket])

AC_CONFIG_SRCDIR([ipaserver/ipaldap.py])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

AM_MAINTAINER_MODE
AC_PROG_CC
AC_STDC_HEADERS
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_HEADER_STDC

AC_SUBST(VERSION)

dnl ---------------------------------------------------------------------------
dnl - Check for DS slapi plugin
dnl ---------------------------------------------------------------------------

AC_CHECK_HEADER(dirsrv/slapi-plugin.h)

dnl ---------------------------------------------------------------------------
dnl - Check for KRB5
dnl ---------------------------------------------------------------------------

KRB5_LIBS=
AC_CHECK_HEADER(krb5.h)

krb5_impl=mit

if test "x$ac_cv_header_krb5_h" = "xyes" ; then
  dnl lazy check for Heimdal Kerberos
  AC_CHECK_HEADERS(heim_err.h)
  if test $ac_cv_header_heim_err_h = yes ; then
    krb5_impl=heimdal
  else
    krb5_impl=mit
  fi

  if test "x$krb5_impl" = "xmit"; then
    AC_CHECK_LIB(k5crypto, main,
      [krb5crypto=k5crypto],
      [krb5crypto=crypto])

    AC_CHECK_LIB(krb5, main,
      [have_krb5=yes
	KRB5_LIBS="-lkrb5 -l$krb5crypto -lcom_err"],
      [have_krb5=no],
      [-l$krb5crypto -lcom_err])

  elif test "x$krb5_impl" = "xheimdal"; then
    AC_CHECK_LIB(des, main,
      [krb5crypto=des],
      [krb5crypto=crypto])

    AC_CHECK_LIB(krb5, main,
      [have_krb5=yes
	KRB5_LIBS="-lkrb5 -l$krb5crypto -lasn1 -lroken -lcom_err"],
      [have_krb5=no],
      [-l$krb5crypto -lasn1 -lroken -lcom_err])

    AC_DEFINE(HAVE_HEIMDAL_KERBEROS, 1,
      [define if you have HEIMDAL Kerberos])

  else
    have_krb5=no
    AC_MSG_WARN([Unrecognized Kerberos5 Implementation])
  fi

  if test "x$have_krb5" = "xyes" ; then
    ol_link_krb5=yes

    AC_DEFINE(HAVE_KRB5, 1,
      [define if you have Kerberos V])

  else
    AC_MSG_ERROR([Required Kerberos 5 support not available])
  fi

fi

AC_SUBST(KRB5_LIBS)

dnl ---------------------------------------------------------------------------
dnl - Check for LDAP
dnl ---------------------------------------------------------------------------

LDAP_LIBS=
AC_CHECK_HEADER(ldap.h)
AC_CHECK_HEADER(lber.h)

AC_CHECK_LIB(ldap, ldap_search, with_ldap=yes)
dnl Check for other libraries we need to link with to get the main routines.
test "$with_ldap" != "yes" && { AC_CHECK_LIB(ldap, ldap_open, [with_ldap=yes with_ldap_lber=yes], , -llber) }
test "$with_ldap" != "yes" && { AC_CHECK_LIB(ldap, ldap_open, [with_ldap=yes with_ldap_lber=yes with_ldap_krb=yes], , -llber -lkrb) }
test "$with_ldap" != "yes" && { AC_CHECK_LIB(ldap, ldap_open, [with_ldap=yes with_ldap_lber=yes with_ldap_krb=yes with_ldap_des=yes], , -llber -lkrb -ldes) }
dnl Recently, we need -lber even though the main routines are elsewhere,
dnl because otherwise be get link errors w.r.t. ber_pvt_opt_on.  So just
dnl check for that (it's a variable not a fun but that doesn't seem to
dnl matter in these checks)  and stick in -lber if so.  Can't hurt (even to
dnl stick it in always shouldn't hurt, I don't think) ... #### Someone who
dnl #### understands LDAP needs to fix this properly.
test "$with_ldap_lber" != "yes" && { AC_CHECK_LIB(lber, ber_pvt_opt_on, with_ldap_lber=yes) }

if test "$with_ldap" = "yes"; then
  if test "$with_ldap_des" = "yes" ; then
    LDAP_LIBS="${LDAP_LIBS} -ldes"
  fi
  if test "$with_ldap_krb" = "yes" ; then
    LDAP_LIBS="${LDAP_LIBS} -lkrb"
  fi
  if test "$with_ldap_lber" = "yes" ; then
    LDAP_LIBS="${LDAP_LIBS} -llber"
  fi
  LDAP_LIBS="${LDAP_LIBS} -lldap"
else
  AC_MSG_ERROR([LDAP not found])
fi

AC_SUBST(LDAP_LIBS)

dnl ---------------------------------------------------------------------------
dnl - Check for Mozilla LDAP SDK
dnl ---------------------------------------------------------------------------

PKG_CHECK_MODULES(MOZLDAP, mozldap > 6)

dnl ---------------------------------------------------------------------------
dnl - Check for OpenSSL Crypto library
dnl ---------------------------------------------------------------------------
dnl This is a very simple check, we should probably check also for MD4_Init and
dnl probably also the version we are using is recent enough
SSL_LIBS=
AC_CHECK_LIB(crypto, DES_set_key_unchecked, [SSL_LIBS="-lcrypto"])
AC_SUBST(SSL_LIBS)

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

# Turn on the additional warnings last, so -Werror doesn't affect other tests.

AC_ARG_ENABLE(more-warnings,
	[AC_HELP_STRING([--enable-more-warnings],
	[Maximum compiler warnings])],
	set_more_warnings="$enableval",[
        	if test -d $srcdir/../.hg; then
        		set_more_warnings=yes
              	else
                  	set_more_warnings=no
              	fi
        ])
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

# Flags

AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)

# Files

AC_CONFIG_FILES([
    Makefile
    ipa-gui/Makefile
    ipa-gui/ipagui/Makefile
    ipa-gui/ipagui/config/Makefile
    ipa-gui/ipagui/forms/Makefile
    ipa-gui/ipagui/helpers/Makefile
    ipa-gui/ipagui/static/Makefile
    ipa-gui/ipagui/static/css/Makefile
    ipa-gui/ipagui/static/images/Makefile
    ipa-gui/ipagui/static/images/template/Makefile
    ipa-gui/ipagui/static/images/branding/Makefile
    ipa-gui/ipagui/static/images/objects/Makefile
    ipa-gui/ipagui/static/javascript/Makefile
    ipa-gui/ipagui/subcontrollers/Makefile
    ipa-gui/ipagui/templates/Makefile
    ipa-gui/ipagui/tests/Makefile
    ipa-gui/ipa_gui.egg-info/Makefile
    ipa-install/Makefile
    ipa-install/share/Makefile
    ipa-kpasswd/Makefile
    ipaserver/Makefile
    ipa-slapi-plugins/Makefile
    ipa-slapi-plugins/dna/Makefile
    ipa-slapi-plugins/ipa-memberof/Makefile
    ipa-slapi-plugins/ipa-pwd-extop/Makefile
    xmlrpc-server/Makefile
    xmlrpc-server/test/Makefile
    man/Makefile
])

AC_OUTPUT

echo "
                    IPA Server $VERSION
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
	compiler:		  ${CC}
	cflags:		          ${CFLAGS}
        LDAP libs:                ${LDAP_LIBS}
        KRB5 libs:                ${KRB5_LIBS}
        OpenSSL libs:             ${SSL_LIBS}
        Maintainer mode:          ${USE_MAINTAINER_MODE}
"
