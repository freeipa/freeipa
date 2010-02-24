/* Authors: Rob Crittenden <rcritten@redhat.com>
 *
 * Copyright (C) 2009  Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <krb5.h>
#include <popt.h>
#include <errno.h>

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
        fprintf(stderr, "Unable to parse principal name\n");
        if (debug)
            fprintf(stderr, "krb5_parse_name %d: %s\n", krberr, error_message(krberr));
        rval = 4;
        goto done;
    }

    /* Loop through the keytab and remove all entries with this principal name
     * irrespective of the encryption type. A failure to find one after the
     * first means we're done.
     */
    fprintf(stderr, "Removing principal %s\n", principal);
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
                fprintf(stderr, "Failed to open keytab\n");
                rval = 3;
                goto done;
            }
            fprintf(stderr, "principal not found\n");
            if (debug)
                fprintf(stderr, "krb5_kt_get_entry %d: %s\n", krberr, error_message(krberr));
            rval = 5;
            break;
        }

        krberr = krb5_kt_remove_entry(context, ktid, &entry2);
        if (krberr) {
            fprintf(stderr, "Unable to remove entry\n");
            if (debug) {
                fprintf(stdout, "kvno %d\n", entry2.vno);
                fprintf(stderr, "krb5_kt_remove_entry %d: %s\n", krberr, error_message(krberr));
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

    krberr = krb5_kt_start_seq_get(context, ktid, &kt_cursor);
    memset(&entry, 0, sizeof(entry));
    while (krb5_kt_next_entry(context, ktid, &entry, &kt_cursor) == 0) {
        krberr = krb5_unparse_name(context, entry.principal, &entry_princ_s);
        if (krberr) {
            fprintf(stderr, "Unable to parse principal\n");
            if (debug) {
                fprintf(stderr, "krb5_unparse_name %d: %s\n", krberr, error_message(krberr));
            }
            rval = 4;
            goto done;
        }

        /* keytab entries are locked when looping. Temporarily suspend
         * the looping. */
        krb5_kt_end_seq_get(context, ktid, &kt_cursor);

        if (strstr(entry_princ_s, realm) != NULL) {
            rval = remove_principal(context, ktid, entry_princ_s, debug);
            if (rval != 0)
                goto done;
            /* Have to reset the cursor */
            krberr = krb5_kt_start_seq_get(context, ktid, &kt_cursor);
        }
    }

done:

    return rval;
}

int
main(int argc, char **argv)
{
    krb5_context context;
    krb5_error_code krberr;
    krb5_keytab ktid;
    char * ktname;
    char * atrealm;
    poptContext pc;
    static const char *keytab = NULL;
    static const char *principal = NULL;
    static const char *realm = NULL;
    int debug = 0;
    int ret, rval;
    struct poptOption options[] = {
        { "debug", 'd', POPT_ARG_NONE, &debug, 0, "Print debugging information", "Debugging output" },
        { "principal", 'p', POPT_ARG_STRING, &principal, 0, "The principal to get a keytab for (ex: ftp/ftp.example.com@EXAMPLE.COM)", "Kerberos Service Principal Name" },
        { "keytab", 'k', POPT_ARG_STRING, &keytab, 0, "File were to store the keytab information", "Keytab File Name" },
        { "realm", 'r', POPT_ARG_STRING, &realm, 0, "Remove all principals in this realm", "Realm name" },
        POPT_AUTOHELP
        POPT_TABLEEND
    };

    memset(&ktid, 0, sizeof(ktid));

    krberr = krb5_init_context(&context);
    if (krberr) {
        fprintf(stderr, "Kerberos context initialization failed\n");
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
        if (realm[0] != '@')
            ret = asprintf(&atrealm, "@%s", realm);
            if (ret == -1) {
                rval = 2;
                goto cleanup;
            }
        else
            atrealm = strcpy(atrealm, realm);
    }

    krberr = krb5_kt_resolve(context, ktname, &ktid);
    if (krberr) {
        fprintf(stderr, "Failed to open keytab '%s'\n", keytab);
        rval = 3;
        goto cleanup;
    }

    if (principal)
        rval = remove_principal(context, ktid, principal, debug);
    else if (realm)
        rval = remove_realm(context, ktid, atrealm, debug);

cleanup:
    if (rval == 0 || rval > 3) {
        krberr = krb5_kt_close(context, ktid);
        if (krberr) {
            fprintf(stderr, "Closing keytab failed\n");
            if (debug)
                fprintf(stderr, "krb5_kt_close %d: %s\n", krberr, error_message(krberr));
        }
    }

    krb5_free_context(context);

    poptFreeContext(pc);

    return rval;
}
