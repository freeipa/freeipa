dnl ---------------------------------------------------------------------------
dnl - Check for DS slapi plugin
dnl ---------------------------------------------------------------------------

# Need to hack CPPFLAGS to be able to correctly detetct slapi-plugin.h
SAVE_CPPFLAGS=$CPPFLAGS
CPPFLAGS=$NSPR_CFLAGS
AC_CHECK_HEADER([dirsrv/slapi-plugin.h], [],
    [AC_MSG_ERROR([Required 389-ds header not available (389-ds-base-devel)])])

AC_CHECK_HEADER([dirsrv/repl-session-plugin.h], [],
    [AC_MSG_ERROR([Required 389-ds header not available (389-ds-base-devel)])])
CPPFLAGS=$SAVE_CPPFLAGS

dnl ---------------------------------------------------------------------------
dnl - Check for KRB5 (libkrad, kdb.h)
dnl ---------------------------------------------------------------------------

AC_CHECK_HEADER(krad.h, [], [AC_MSG_ERROR([krad.h not found])])
AC_CHECK_LIB(krad, main, [], [AC_MSG_ERROR([libkrad not found])])
KRAD_LIBS="-lkrad"
krb5rundir="${localstatedir}/run/krb5kdc"
AC_SUBST(KRAD_LIBS)
AC_SUBST(krb5rundir)

AC_CHECK_HEADER(kdb.h, [], [AC_MSG_ERROR([kdb.h not found])])
AC_CHECK_MEMBER(
    [kdb_vftabl.free_principal],
    [AC_DEFINE([HAVE_KDB_FREEPRINCIPAL], [1],
               [KDB driver API has free_principal callback])],
    [AC_MSG_NOTICE([KDB driver API has no free_principal callback])],
    [[#include <kdb.h>]])
AC_CHECK_MEMBER(
    [kdb_vftabl.free_principal_e_data],
    [AC_DEFINE([HAVE_KDB_FREEPRINCIPAL_EDATA], [1],
               [KDB driver API has free_principal_e_data callback])],
    [AC_MSG_NOTICE([KDB driver API has no free_principal_e_data callback])],
    [[#include <kdb.h>]])

if test "x$ac_cv_member_kdb_vftabl_free_principal" = "xno" \
    -a "x$ac_cv_member_kdb_vftable_free_principal_e_data" = "xno" ; then
    AC_MSG_WARN([KDB driver API does not allow to free Kerberos ]
                [principal data.])
    AC_MSG_WARN([KDB driver will leak memory on Kerberos principal use])
    AC_MSG_WARN([See https://github.com/krb5/krb5/pull/596 for details])
fi

dnl ---------------------------------------------------------------------------
dnl - Check for UUID library
dnl ---------------------------------------------------------------------------
PKG_CHECK_MODULES([UUID], [uuid])

dnl ---------------------------------------------------------------------------
dnl Check for ndr_krb5pac and other samba libraries
dnl ---------------------------------------------------------------------------

PKG_PROG_PKG_CONFIG()
PKG_CHECK_MODULES([TALLOC], [talloc])
PKG_CHECK_MODULES([TEVENT], [tevent])
PKG_CHECK_MODULES([NDRPAC], [ndr_krb5pac])
PKG_CHECK_MODULES([NDRNBT], [ndr_nbt])
PKG_CHECK_MODULES([NDR], [ndr])
PKG_CHECK_MODULES([SAMBAUTIL], [samba-util])
SMB_INTERNAL_LIBDIR="$($PKG_CONFIG --variable=libdir samba-util)/samba"
SAMBA40EXTRA_LIBPATH="-L$SMB_INTERNAL_LIBDIR -Wl,-rpath=$SMB_INTERNAL_LIBDIR"
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
               [AC_MSG_ERROR([Neither libpdb nor libsamba-passdb does have ]
                             [make_pdb_method])],
               [$SAMBA40EXTRA_LIBPATH])
fi

AC_SUBST(LIBPDB_NAME)

AC_CHECK_LIB([$LIBPDB_NAME], [pdb_enum_upn_suffixes],
             [AC_DEFINE([HAVE_PDB_ENUM_UPN_SUFFIXES], [1],
                        [Ability to enumerate UPN suffixes])],
             [AC_MSG_WARN([libpdb does not have pdb_enum_upn_suffixes, ]
                          [no support for realm domains in ipasam])],
             [$SAMBA40EXTRA_LIBPATH])

dnl ---------------------------------------------------------------------------
dnl Check for libunistring
dnl ---------------------------------------------------------------------------
AC_CHECK_HEADERS([unicase.h], [], AC_MSG_ERROR([Could not find unicase.h]))
AC_CHECK_LIB([unistring],
             [ulc_casecmp],
             [UNISTRING_LIBS="-lunistring"],
             [AC_MSG_ERROR([libunistring does not have ulc_casecmp])])
AC_SUBST(UNISTRING_LIBS)

dnl ---------------------------------------------------------------------------
dnl Check for libverto
dnl ---------------------------------------------------------------------------
PKG_CHECK_MODULES([LIBVERTO], [libverto])

dnl -- sss_idmap is needed by the extdom exop --
PKG_CHECK_MODULES([SSSIDMAP], [sss_idmap])
PKG_CHECK_MODULES([SSSNSSIDMAP], [sss_nss_idmap >= 1.14.0])

dnl ---------------------------------------------------------------------------
dnl - Check for systemd directories
dnl ---------------------------------------------------------------------------
PKG_CHECK_EXISTS([systemd], [], [AC_MSG_ERROR([systemd not found])])
def_systemdsystemunitdir=$($PKG_CONFIG --define-variable=prefix='${prefix}' \
                                       --variable=systemdsystemunitdir systemd)
AC_ARG_WITH([systemdsystemunitdir],
    [AS_HELP_STRING([--with-systemdsystemunitdir=DIR],
                   [Directory for systemd service files])],
    [systemdsystemunitdir=$with_systemdsystemunitdir],
    [systemdsystemunitdir=$def_systemdsystemunitdir])
AC_SUBST([systemdsystemunitdir])

def_systemdtmpfilesdir=$($PKG_CONFIG --define-variable=prefix='${prefix}' \
                                     --variable=tmpfilesdir systemd)
AC_ARG_WITH([systemdtmpfilesdir],
    [AS_HELP_STRING([--with-systemdtmpfilesdir=DIR],
                    [Directory for systemd-tmpfiles configuration files])],
    [systemdtmpfilesdir=$with_systemdtmpfilesdir],
    [systemdtmpfilesdir=$def_systemdtmpfilesdir])
AC_SUBST([systemdtmpfilesdir])
