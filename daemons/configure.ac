AC_PREREQ(2.59)
m4_include(../version.m4)
AC_INIT([ipa-server],
        IPA_VERSION,
        [https://hosted.fedoraproject.org/projects/freeipa/newticket])

AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

AM_MAINTAINER_MODE
AC_PROG_CC
AC_STDC_HEADERS
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_HEADER_STDC

AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])

AC_SUBST(VERSION)

dnl ---------------------------------------------------------------------------
dnl - Check for NSPR
dnl ---------------------------------------------------------------------------
AC_CHECK_HEADER(nspr4/nspr.h)
AC_CHECK_HEADER(nspr/nspr.h)
if test "x$ac_cv_header_nspr4_nspr_h" = "xno" && test "x$ac_cv_header_nspr_nspr_h" = "xno" ; then
	AC_MSG_ERROR([Required NSPR header not available (nspr-devel)])
fi
if test "x$ac_cv_header_nspr4_nspr_h" = "xyes" ; then
	NSPR4="-I/usr/include/nspr4"
fi
if test "x$ac_cv_header_nspr_nspr_h" = "xyes" ; then
	NSPR4="-I/usr/include/nspr"
fi

dnl ---------------------------------------------------------------------------
dnl - Check for NSS
dnl ---------------------------------------------------------------------------
SAVE_CPPFLAGS=$CPPFLAGS
CPPFLAGS=$NSPR4
AC_CHECK_HEADER(nss3/nss.h)
AC_CHECK_HEADER(nss/nss.h)
CPPFLAGS=$SAVE_CPPFLAGS
if test "x$ac_cv_header_nss3_nss_h" = "xno" && test "x$ac_cv_header_nss_nss_h" = "xno" ; then
	AC_MSG_ERROR([Required NSS header not available (nss-devel)])
fi
if test "x$ac_cv_header_nss3_nss_h" = "xyes" ; then
	NSS3="-I/usr/include/nss3"
fi
if test "x$ac_cv_header_nss_nss_h" = "xyes" ; then
	NSS3="-I/usr/include/nss"
fi

dnl ---------------------------------------------------------------------------
dnl - Check for DS slapi plugin
dnl ---------------------------------------------------------------------------

# Need to hack CPPFLAGS to be able to correctly detetct slapi-plugin.h
SAVE_CPPFLAGS=$CPPFLAGS
CPPFLAGS=$NSPR4
AC_CHECK_HEADER(dirsrv/slapi-plugin.h)
if test "x$ac_cv_header_dirsrv_slapi-plugin_h" = "xno" ; then
	AC_MSG_ERROR([Required 389-ds header not available (389-ds-base-devel)])
fi
AC_CHECK_HEADER(dirsrv/repl-session-plugin.h)
if test "x$ac_cv_header_dirsrv_repl_session_plugin_h" = "xno" ; then
	AC_MSG_ERROR([Required 389-ds header not available (389-ds-base-devel)])
fi
CPPFLAGS=$SAVE_CPPFLAGS

if test "x$ac_cv_header_dirsrv_slapi_plugin_h" = "xno" ; then
	AC_MSG_ERROR([Required DS slapi plugin header not available (fedora-ds-base-devel)])
fi

dnl ---------------------------------------------------------------------------
dnl - Check for KRB5
dnl ---------------------------------------------------------------------------

KRB5_LIBS=
AC_CHECK_HEADER(krb5.h, [], [AC_MSG_ERROR([krb5.h not found])])

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
dnl - Check for Mozilla LDAP *and* OpenLDAP SDK
dnl ---------------------------------------------------------------------------

dnl The mozldap libraries are always needed because ipa-slapi-plugins/dna/ 
dnl will not build against OpenLDAP.
SAVE_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$NSPR4 $NSS3"
AC_CHECK_HEADER(svrcore.h)
AC_CHECK_HEADER(svrcore/svrcore.h)
if test "x$ac_cv_header_svrcore_h" = "xno" && test "x$ac_cv_header_svrcore_svrcore_h" = "xno" ; then
	AC_MSG_ERROR([Required svrcore header not available (svrcore-devel)])
fi
if test "x$ac_cv_header_svrcore_svrcore_h" = "yes" ; then
	CPPFLAGS="$CPPFLAGS -I/usr/include/svrcore"
fi

CPPFLAGS=$SAVE_CPPFLAGS
AC_CHECK_HEADER(mozldap/ldap.h)
if test "x$ac_cv_header_mozldap_ldap_h" = "xno" ; then
	AC_MSG_ERROR([Required MOZLDAP header not available (mozldap-devel)])
fi
PKG_CHECK_MODULES(MOZLDAP, mozldap > 6)

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
    OPENLDAP_LIBS="${OPENLDAP_LIBS} -ldes"
  fi
  if test "$with_ldap_krb" = "yes" ; then
    OPENLDAP_LIBS="${OPENLDAP_LIBS} -lkrb"
  fi
  if test "$with_ldap_lber" = "yes" ; then
    OPENLDAP_LIBS="${OPENLDAP_LIBS} -llber"
  fi
  OPENLDAP_LIBS="${OPENLDAP_LIBS} -lldap"
else
  AC_MSG_ERROR([OpenLDAP not found])
fi

AC_SUBST(OPENLDAP_LIBS)

OPENLDAP_CFLAGS="${OPENLDAP_CFLAGS} -DWITH_OPENLDAP"
AC_SUBST(OPENLDAP_CFLAGS)

dnl ---------------------------------------------------------------------------
dnl - Check for OpenSSL Crypto library
dnl ---------------------------------------------------------------------------
dnl This is a very simple check, we should probably check also for MD4_Init and
dnl probably also the version we are using is recent enough
SSL_LIBS=
AC_CHECK_HEADER(openssl/des.h, [], [AC_MSG_ERROR([openssl/des.h not found])])
AC_CHECK_LIB(crypto, DES_set_key_unchecked, [SSL_LIBS="-lcrypto"])
AC_SUBST(SSL_LIBS)

dnl ---------------------------------------------------------------------------
dnl - Check for UUID library
dnl ---------------------------------------------------------------------------
AC_CHECK_HEADERS(uuid/uuid.h,,[AC_MSG_ERROR([uuid/uuid.h not found])])

AC_CHECK_LIB(uuid, uuid_generate_time, [UUID_LIBS="-luuid"])
AC_SUBST(UUID_LIBS)

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
    ipa-kpasswd/Makefile
    ipa-slapi-plugins/Makefile
    ipa-slapi-plugins/ipa-enrollment/Makefile
    ipa-slapi-plugins/ipa-pwd-extop/Makefile
    ipa-slapi-plugins/ipa-winsync/Makefile
    ipa-slapi-plugins/ipa-version/Makefile
    ipa-slapi-plugins/ipa-uuid/Makefile
    ipa-slapi-plugins/ipa-modrdn/Makefile
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
        LDAP libs:                ${OPENLDAP_LIBS}
        KRB5 libs:                ${KRB5_LIBS}
        OpenSSL libs:             ${SSL_LIBS}
        Maintainer mode:          ${USE_MAINTAINER_MODE}
"
