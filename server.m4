dnl server dependencies

dnl ---------------------------------------------------------------------------
dnl - Check for DS slapi plugin
dnl ---------------------------------------------------------------------------

# Need to hack CPPFLAGS to be able to correctly detect slapi-plugin.h
SAVE_CPPFLAGS=$CPPFLAGS
CPPFLAGS=$NSPR_CFLAGS
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

dnl -- dirsrv is needed for the extdom unit tests --
PKG_CHECK_MODULES([DIRSRV], [dirsrv  >= 1.3.0])
# slapi-plugin.h includes nspr.h
DIRSRV_CFLAGS="$DIRSRV_CFLAGS $NSPR_CFLAGS"

dnl -- sss_idmap is needed by the extdom exop --
PKG_CHECK_MODULES([SSSIDMAP], [sss_idmap])
PKG_CHECK_MODULES([SSSNSSIDMAP], [sss_nss_idmap >= 1.15.2])
AC_CHECK_LIB([sss_nss_idmap],
             [sss_nss_getlistbycert],
             [ ],
             [AC_MSG_ERROR([Required sss_nss_getlistbycert symbol in sss_nss_idmap not found])],
             [])

dnl --- if sss_nss_idmap provides _timeout() API, use it
bck_cflags="$CFLAGS"
CFLAGS="$CFLAGS -DIPA_389DS_PLUGIN_HELPER_CALLS"
AC_CHECK_DECLS([sss_nss_getpwnam_timeout], [], [], [[#include <sss_nss_idmap.h>]])
CFLAGS="$bck_cflags"

if test "x$ac_cv_have_decl_sss_nss_getpwnam_timeout" = xyes ; then
    AC_DEFINE(USE_SSS_NSS_TIMEOUT,1,[Use extended NSS API provided by SSSD])
fi

dnl -- sss_certmap and certauth.h are needed by the IPA KDB certauth plugin --
PKG_CHECK_EXISTS([sss_certmap],
                 [PKG_CHECK_MODULES([SSSCERTMAP], [sss_certmap])],
                 [AC_MSG_NOTICE([sss_certmap not found])])
AC_CHECK_HEADER([krb5/certauth_plugin.h],
                [have_certauth_plugin=yes],
                [have_certauth_plugin=no])

dnl -- Check if we can build the kdcpolicy plugin
AC_CHECK_HEADER([krb5/kdcpolicy_plugin.h],
                [have_kdcpolicy_plugin=yes],
                [have_kdcpolicy_plugin=no])

dnl ---------------------------------------------------------------------------
dnl - Check for KRB5 krad
dnl ---------------------------------------------------------------------------

AC_CHECK_HEADER(krad.h, [], [AC_MSG_ERROR([krad.h not found])])
AC_CHECK_LIB(krad, main, [ ], [AC_MSG_ERROR([libkrad not found])])
KRAD_LIBS="-lkrad"
krb5rundir="${localstatedir}/run/krb5kdc"
AC_SUBST(KRAD_LIBS)
AC_SUBST(krb5rundir)

dnl ---------------------------------------------------------------------------
dnl - Check for UUID library
dnl ---------------------------------------------------------------------------
PKG_CHECK_MODULES([UUID], [uuid])

dnl ---------------------------------------------------------------------------
dnl Check for ndr_krb5pac and other samba libraries
dnl ---------------------------------------------------------------------------

PKG_CHECK_MODULES([TALLOC], [talloc])
PKG_CHECK_MODULES([TEVENT], [tevent])
PKG_CHECK_MODULES([NDRPAC], [ndr_krb5pac])
PKG_CHECK_MODULES([NDRNBT], [ndr_nbt])
PKG_CHECK_MODULES([NDR], [ndr])
PKG_CHECK_MODULES([SAMBAUTIL], [samba-util])
SAMBA40EXTRA_LIBPATH="-L`$PKG_CONFIG --variable=libdir samba-util`/samba -Wl,-rpath=`$PKG_CONFIG --variable=libdir samba-util`/samba"
AC_SUBST(SAMBA40EXTRA_LIBPATH)

bck_cflags="$CFLAGS"
CFLAGS="$NDRPAC_CFLAGS"
AC_CHECK_MEMBER(
    [struct PAC_DOMAIN_GROUP_MEMBERSHIP.domain_sid],
    [AC_DEFINE([HAVE_STRUCT_PAC_DOMAIN_GROUP_MEMBERSHIP], [1],
               [struct PAC_DOMAIN_GROUP_MEMBERSHIP is available.])],
    [AC_MSG_NOTICE([struct PAC_DOMAIN_GROUP_MEMBERSHIP is not available])],
                 [[#include <ndr.h>
                   #include <gen_ndr/krb5pac.h>]])

CFLAGS="$bck_cflags"

LIBPDB_NAME=""
AC_CHECK_LIB([samba-passdb],
             [make_pdb_method],
             [LIBPDB_NAME="samba-passdb"; HAVE_LIBPDB=1],
             [LIBPDB_NAME="pdb"],
             [$SAMBA40EXTRA_LIBPATH])

if test "x$LIB_PDB_NAME" = "xpdb" ; then
  AC_CHECK_LIB([$LIBPDB_NAME],
               [make_pdb_method],
               [HAVE_LIBPDB=1],
               [AC_MSG_ERROR([Neither libpdb nor libsamba-passdb does have make_pdb_method])],
               [$SAMBA40EXTRA_LIBPATH])
fi

AC_SUBST(LIBPDB_NAME)

AC_CHECK_LIB([$LIBPDB_NAME],[pdb_enum_upn_suffixes],
             [AC_DEFINE([HAVE_PDB_ENUM_UPN_SUFFIXES], [1], [Ability to enumerate UPN suffixes])],
             [AC_MSG_WARN([libpdb does not have pdb_enum_upn_suffixes, no support for realm domains in ipasam])],
             [$SAMBA40EXTRA_LIBPATH])

AC_CHECK_LIB([smbldap],[smbldap_get_ldap],
             [AC_DEFINE([HAVE_SMBLDAP_GET_LDAP], [1], [struct smbldap_state is opaque])],
             [AC_MSG_WARN([libsmbldap is not opaque, not using smbldap_get_ldap])],
             [$SAMBA40EXTRA_LIBPATH])

AC_CHECK_LIB([smbldap],[smbldap_set_bind_callback],
             [AC_DEFINE([HAVE_SMBLDAP_SET_BIND_CALLBACK], [1], [struct smbldap_state is opaque])],
             [AC_MSG_WARN([libsmbldap is not opaque, not using smbldap_set_bind_callback])],
             [$SAMBA40EXTRA_LIBPATH])

dnl ---------------------------------------------------------------------------
dnl Check for libunistring
dnl ---------------------------------------------------------------------------

AC_CHECK_HEADERS([unicase.h],,AC_MSG_ERROR([Could not find unicase.h]))
AC_CHECK_LIB([unistring],
             [ulc_casecmp],
             [UNISTRING_LIBS="-lunistring"],
             [AC_MSG_ERROR([libunistring does not have ulc_casecmp])])
AC_SUBST(UNISTRING_LIBS)


dnl ---------------------------------------------------------------------------
dnl Check for libverto
dnl ---------------------------------------------------------------------------

PKG_CHECK_MODULES([LIBVERTO], [libverto])

dnl ---------------------------------------------------------------------------
dnl - Check for systemd directories
dnl ---------------------------------------------------------------------------

PKG_CHECK_EXISTS([systemd], [], [AC_MSG_ERROR([systemd not found])])
AC_ARG_WITH([systemdsystemunitdir],
            AS_HELP_STRING([--with-systemdsystemunitdir=DIR],
               [Directory for systemd service files]),
            [systemdsystemunitdir=$with_systemdsystemunitdir],
        [systemdsystemunitdir=$($PKG_CONFIG --define-variable=prefix='${prefix}' --variable=systemdsystemunitdir systemd)])
AC_SUBST([systemdsystemunitdir])

AC_ARG_WITH([systemdtmpfilesdir],
            AS_HELP_STRING([--with-systemdtmpfilesdir=DIR],
               [Directory for systemd-tmpfiles configuration files]),
            [systemdtmpfilesdir=$with_systemdtmpfilesdir],
        [systemdtmpfilesdir=$($PKG_CONFIG --define-variable=prefix='${prefix}' --variable=tmpfilesdir systemd)])
AC_SUBST([systemdtmpfilesdir])

