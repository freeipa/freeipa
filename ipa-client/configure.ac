AC_PREREQ(2.59)
AC_INIT([ipa-client],
        [0.6.0],
        [https://hosted.fedoraproject.org/projects/freeipa/newticket])

AC_CONFIG_SRCDIR([ipaclient/__init__.py])
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
dnl - Check for POPT
dnl ---------------------------------------------------------------------------

POPT_LIBS=
AC_CHECK_HEADER(popt.h)
AC_CHECK_LIB(popt, poptGetContext, [POPT_LIBS="-lpopt"])
AC_SUBST(POPT_LIBS)

dnl ---------------------------------------------------------------------------
dnl - Check for SASL
dnl ---------------------------------------------------------------------------

SASL_LIBS=
AC_CHECK_HEADER(sasl/sasl.h)
AC_CHECK_LIB(sasl2, sasl_client_init, [SASL_LIBS="-lsasl2"])
AC_SUBST(SASL_LIBS)

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
