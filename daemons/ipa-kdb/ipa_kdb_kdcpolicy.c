/*
 * Copyright (C) 2018  FreeIPA Contributors see COPYING for license
 */

#include <errno.h>
#include <syslog.h>
#include <krb5/kdcpolicy_plugin.h>

#include "ipa_krb5.h"
#include "ipa_kdb.h"

static krb5_error_code
ipa_kdcpolicy_check_as(krb5_context context, krb5_kdcpolicy_moddata moddata,
                       const krb5_kdc_req *request,
                       const krb5_db_entry *client,
                       const krb5_db_entry *server,
                       const char *const *auth_indicators,
                       const char **status, krb5_deltat *lifetime_out,
                       krb5_deltat *renew_lifetime_out)
{
    *status = NULL;
    *lifetime_out = 0;
    *renew_lifetime_out = 0;

    krb5_klog_syslog(LOG_INFO, "IPA kdcpolicy: checking AS-REQ.");

    return 0;
}

static krb5_error_code
ipa_kdcpolicy_check_tgs(krb5_context context, krb5_kdcpolicy_moddata moddata,
                        const krb5_kdc_req *request,
                        const krb5_db_entry *server,
                        const krb5_ticket *ticket,
                        const char *const *auth_indicators,
                        const char **status, krb5_deltat *lifetime_out,
                        krb5_deltat *renew_lifetime_out)
{
    *status = NULL;
    *lifetime_out = 0;
    *renew_lifetime_out = 0;

    krb5_klog_syslog(LOG_INFO, "IPA kdcpolicy: checking TGS-REQ.");

    return 0;
}

krb5_error_code kdcpolicy_ipakdb_initvt(krb5_context context,
                                        int maj_ver, int min_ver,
                                        krb5_plugin_vtable vtable)
{
    krb5_kdcpolicy_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt = (krb5_kdcpolicy_vtable)vtable;
    vt->name = "ipakdb";
    vt->init = NULL;
    vt->fini = NULL;
    vt->check_as = ipa_kdcpolicy_check_as;
    vt->check_tgs = ipa_kdcpolicy_check_tgs;
    return 0;
}
