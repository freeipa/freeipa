/* Authors: Rob Crittenden <rcritten@redhat.com>
 *
 * Copyright (C) 2009  Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <krb5.h>
#include <popt.h>
#include <errno.h>

#include "ipa-client-common.h"
#include "config.h"

int
remove_principal(krb5_context context, krb5_keytab ktid, const char *principal, int debug)
{
    krb5_error_code krberr;
    krb5_keytab_entry entry, entry2;
    int rval = 0;
    int removed = 0;

    memset(&entry, 0, sizeof(entry));
    krberr = krb5_parse_name(context, principal, &entry.principal);
    if (krberr) {
        fprintf(stderr, _("Unable to parse principal name\n"));
        if (debug)
            fprintf(stderr, _("krb5_parse_name %1$d: %2$s\n"),
                            krberr, error_message(krberr));
        rval = 4;
        goto done;
    }

    /* Loop through the keytab and remove all entries with this principal name
     * irrespective of the encryption type. A failure to find one after the
     * first means we're done.
     */
    fprintf(stderr, _("Removing principal %s\n"), principal);
    while (1) {
        memset(&entry2, 0, sizeof(entry2));
        krberr = krb5_kt_get_entry(context, ktid,
                                entry.principal,
                                0,
                                0,
                                &entry2);
        if (krberr) {
            if (removed > 0)
                /* not found but we've removed some, we're done */
                break;
            if (krberr == ENOENT) {
                fprintf(stderr, _("Failed to open keytab\n"));
                rval = 3;
                goto done;
            }
            fprintf(stderr, _("principal not found\n"));
            if (debug)
                fprintf(stderr, _("krb5_kt_get_entry %1$d: %2$s\n"),
                                krberr, error_message(krberr));
            rval = 5;
            break;
        }

        krberr = krb5_kt_remove_entry(context, ktid, &entry2);
        if (krberr) {
            fprintf(stderr, _("Unable to remove entry\n"));
            if (debug) {
                fprintf(stdout, _("kvno %d\n"), entry2.vno);
                fprintf(stderr, _("krb5_kt_remove_entry %1$d: %2$s\n"),
                                krberr, error_message(krberr));
            }
            rval = 6;
            break;
        }

        krb5_free_keytab_entry_contents(context, &entry2);
        removed++;
    }

    if (entry2.principal)
        krb5_free_keytab_entry_contents(context, &entry2);

done:

    return rval;
}

int
remove_realm(krb5_context context, krb5_keytab ktid, const char *realm, int debug)
{
    krb5_error_code krberr;
    krb5_keytab_entry entry;
    krb5_kt_cursor kt_cursor;
    char * entry_princ_s = NULL;
    int rval = 0;
    bool realm_found = false;

    krberr = krb5_kt_start_seq_get(context, ktid, &kt_cursor);
    memset(&entry, 0, sizeof(entry));
    while (krb5_kt_next_entry(context, ktid, &entry, &kt_cursor) == 0) {
        krberr = krb5_unparse_name(context, entry.principal, &entry_princ_s);
        if (krberr) {
            fprintf(stderr, _("Unable to parse principal\n"));
            if (debug) {
                fprintf(stderr, _("krb5_unparse_name %1$d: %2$s\n"),
                                krberr, error_message(krberr));
            }
            rval = 4;
            goto done;
        }

        /* keytab entries are locked when looping. Temporarily suspend
         * the looping. */
        krb5_kt_end_seq_get(context, ktid, &kt_cursor);

        if (strstr(entry_princ_s, realm) != NULL) {
            realm_found = true;
            rval = remove_principal(context, ktid, entry_princ_s, debug);
            if (rval != 0)
                goto done;
            /* Have to reset the cursor */
            krberr = krb5_kt_start_seq_get(context, ktid, &kt_cursor);
        }
    }

    if (!realm_found) {
        fprintf(stderr, _("realm not found\n"));
        return 5;
    }

done:

    return rval;
}

int
main(int argc, const char **argv)
{
    krb5_context context;
    krb5_error_code krberr;
    krb5_keytab ktid;
    krb5_kt_cursor cursor;
    char * ktname = NULL;
    char * atrealm = NULL;
    poptContext pc;
    static const char *keytab = NULL;
    static const char *principal = NULL;
    static const char *realm = NULL;
    int debug = 0;
    int ret, rval = 0;
    struct poptOption options[] = {
        { "debug", 'd', POPT_ARG_NONE, &debug, 0,
          _("Print debugging information"), _("Debugging output") },
        { "principal", 'p', POPT_ARG_STRING, &principal, 0,
          _("The principal to get a keytab for (ex: ftp/ftp.example.com@EXAMPLE.COM)"),
          _("Kerberos Service Principal Name") },
        { "keytab", 'k', POPT_ARG_STRING, &keytab, 0,
          _("File were to store the keytab information"), _("Keytab File Name") },
        { "realm", 'r', POPT_ARG_STRING, &realm, 0,
          _("Remove all principals in this realm"), _("Realm name") },
        POPT_AUTOHELP
        POPT_TABLEEND
    };

    ret = init_gettext();
    if (ret) {
        exit(1);
    }

    memset(&ktid, 0, sizeof(ktid));

    krberr = krb5_init_context(&context);
    if (krberr) {
        fprintf(stderr, _("Kerberos context initialization failed\n"));
        exit(1);
    }

    pc = poptGetContext("ipa-rmkeytab", argc, (const char **)argv, options, 0);
    ret = poptGetNextOpt(pc);
    if (ret != -1 || (!principal && !realm) || !keytab) {
        poptPrintUsage(pc, stderr, 0);
        rval = 1;
        goto cleanup;
    }

    ret = asprintf(&ktname, "WRFILE:%s", keytab);
    if (ret == -1) {
        rval = 2;
        goto cleanup;
    }

    /* The remove_realm function just does a substring match. Ensure that
     * the string we pass in looks like a realm.
     */
    if (realm) {
        if (realm[0] != '@') {
            ret = asprintf(&atrealm, "@%s", realm);
            if (ret == -1) {
                rval = 2;
                goto cleanup;
            }
        } else {
            atrealm = strdup(realm);

            if (NULL == atrealm) {
                rval = 2;
                goto cleanup;
            }
        }
    }

    krberr = krb5_kt_resolve(context, ktname, &ktid);
    if (krberr) {
        fprintf(stderr, _("Failed to open keytab '%1$s': %2$s\n"), keytab,
            error_message(krberr));
        rval = 3;
        goto cleanup;
    }
    krberr = krb5_kt_start_seq_get(context, ktid, &cursor);
    if (krberr) {
        fprintf(stderr, _("Failed to open keytab '%1$s': %2$s\n"), keytab,
            error_message(krberr));
        rval = 3;
        goto cleanup;
    }
    krb5_kt_end_seq_get(context, ktid, &cursor);

    if (principal)
        rval = remove_principal(context, ktid, principal, debug);
    else if (realm)
        rval = remove_realm(context, ktid, atrealm, debug);

cleanup:
    if (rval == 0 || rval > 3) {
        krberr = krb5_kt_close(context, ktid);
        if (krberr) {
            fprintf(stderr, _("Closing keytab failed\n"));
            if (debug)
                fprintf(stderr, _("krb5_kt_close %1$d: %2$s\n"),
                                krberr, error_message(krberr));
        }
    }

    krb5_free_context(context);

    poptFreeContext(pc);

    free(atrealm);
    free(ktname);

    return rval;
}
