/*
 * Copyright (C) 2020  FreeIPA Contributors see COPYING for license
 */
#include <gen_ndr/ndr_krb5pac.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#include <ndr.h>
#include <popt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#define IPAPWD_PASSWORD_MAX_LEN 1024

typedef enum {
    OP_SERVICE_TICKET,
    OP_IMPERSONATE
} pac_operation_t;

pac_operation_t operation = OP_SERVICE_TICKET;
char *keytab_path         = NULL;
char *ccache_path         = NULL;
bool init_tgt             = true;
const gss_OID *import_name_oid   = &GSS_C_NT_USER_NAME;

TALLOC_CTX *frame = NULL;

gss_OID_desc mech_krb5 = {9, "\052\206\110\206\367\022\001\002\002"};

/* NDR printing interface passes flags but the actual public print function
 * does not accept flags. Generated ndr helpers actually have a small wrapper
 * but since it is a static to the generated C code unit, we have to reimplement
 * it here.
 */
static void
print_flags_PAC_DATA(struct ndr_print *ndr,
                     const char *name,
                     int unused,
                     const struct PAC_DATA *r)
{
    ndr_print_PAC_DATA(ndr, name, r);
}

/*
 * Print content of a PAC buffer, annotated by the libndr helpers
 */
static void
print_pac(gss_buffer_desc *pac, gss_buffer_desc *display)
{
    struct ndr_print *ndr = NULL;
    DATA_BLOB blob;
    struct ndr_pull *ndr_pull = NULL;
    void *st                  = NULL;
    int flags                 = NDR_SCALARS | NDR_BUFFERS;
    enum ndr_err_code ndr_err;
    struct ndr_interface_call ndr_call = {
        .name        = "PAC_DATA",
        .struct_size = sizeof(struct PAC_DATA),
        .ndr_push    = (ndr_push_flags_fn_t)ndr_push_PAC_DATA,
        .ndr_pull    = (ndr_pull_flags_fn_t)ndr_pull_PAC_DATA,
        .ndr_print   = (ndr_print_function_t)print_flags_PAC_DATA,
    };

    ndr        = talloc_zero(frame, struct ndr_print);
    ndr->print = ndr_print_string_helper;
    ndr->depth = 0;

    blob            = data_blob_const(pac->value, pac->length);
    ndr_pull        = ndr_pull_init_blob(&blob, ndr);
    ndr_pull->flags = LIBNDR_FLAG_REF_ALLOC;

    st      = talloc_zero_size(ndr, ndr_call.struct_size);
    ndr_err = ndr_call.ndr_pull(ndr_pull, flags, st);
    if (ndr_err) {
        fprintf(stderr,
                "Error parsing buffer '%.*s': %s\n",
                (int)display->length,
                (char *)display->value,
                ndr_map_error2string(ndr_err));
        return;
    }

    ndr_call.ndr_print(ndr, ndr_call.name, flags, st);
    printf("%s\n", (char *)ndr->private_data);
    talloc_free(ndr);
}

static void
display_error(int type, OM_uint32 code)
{
    OM_uint32 min, ctx = 0;
    gss_buffer_desc status;

    do {
        (void)gss_display_status(&min, code, type, GSS_C_NO_OID, &ctx, &status);
        fprintf(stderr, "%.*s\n", (int)status.length, (char *)status.value);
        gss_release_buffer(&min, &status);
    } while (ctx != 0);
}

static void
log_error(const char *fn, uint32_t maj, uint32_t min)
{
    fprintf(stderr, "%s: ", fn);
    display_error(GSS_C_GSS_CODE, maj);
    display_error(GSS_C_MECH_CODE, min);
}

static gss_name_t
import_name(const char *name)
{
    OM_uint32 maj, min;
    gss_name_t gss_name;
    gss_name             = GSS_C_NO_NAME;
    gss_buffer_desc buff = GSS_C_EMPTY_BUFFER;

    buff.value  = (void *)name;
    buff.length = strlen(name);

    maj = gss_import_name(&min, &buff, *import_name_oid, &gss_name);
    if (GSS_ERROR(maj)) {
        log_error("gss_import_name()", maj, min);
        return GSS_C_NO_NAME;
    }

    return gss_name;
}

static bool
store_creds_into_cache(gss_cred_id_t creds, const char *cache)
{
    OM_uint32 maj, min;
    gss_key_value_element_desc store_elm = {"ccache", cache};
    gss_key_value_set_desc store         = {1, &store_elm};

    maj = gss_store_cred_into(
        &min, creds, GSS_C_INITIATE, GSS_C_NO_OID, 1, 1, &store, NULL, NULL);
    if (maj != GSS_S_COMPLETE) {
        log_error("gss_store_cred_into()", maj, min);
        return false;
    }

    return true;
}

static void
dump_attribute(gss_name_t name, gss_buffer_t attribute)
{
    OM_uint32 major, minor;
    gss_buffer_desc value;
    gss_buffer_desc display_value;
    int authenticated = 0;
    int complete      = 0;
    int more          = -1;
    int whole_pac     = 0;

    whole_pac = attribute->length == strlen("urn:mspac:");
    while (more != 0) {
        value.value         = NULL;
        display_value.value = NULL;

        major = gss_get_name_attribute(&minor,
                                       name,
                                       attribute,
                                       &authenticated,
                                       &complete,
                                       &value,
                                       &display_value,
                                       &more);
        if (GSS_ERROR(major)) {
            log_error("gss_get_name_attribute()", major, minor);
            return;
        }

        if (whole_pac) {
            print_pac(&value, attribute);
        }

        (void)gss_release_buffer(&minor, &value);
        (void)gss_release_buffer(&minor, &display_value);
    }
}

static void
enumerate_attributes(gss_name_t name)
{
    OM_uint32 major, minor;
    int is_mechname;
    gss_buffer_set_t attrs = GSS_C_NO_BUFFER_SET;
    size_t i;

    major = gss_inquire_name(&minor, name, &is_mechname, NULL, &attrs);
    if (GSS_ERROR(major)) {
        log_error("gss_inquire_name()", major, minor);
        return;
    }
    if (GSS_ERROR(major)) {
        printf("gss_inquire_name: (%d, %d)\n", major, minor);
        return;
    }

    if (attrs != GSS_C_NO_BUFFER_SET) {
        for (i = 0; i < attrs->count; i++)
            dump_attribute(name, &attrs->elements[i]);
    }

    (void)gss_release_buffer_set(&minor, &attrs);
}

static bool
establish_contexts(gss_OID imech,
                   gss_cred_id_t icred,
                   gss_cred_id_t acred,
                   gss_name_t tname,
                   OM_uint32 flags,
                   gss_ctx_id_t *ictx,
                   gss_ctx_id_t *actx,
                   gss_name_t *src_name,
                   gss_OID *amech,
                   gss_cred_id_t *deleg_cred)
{
    OM_uint32 minor, imaj, amaj;
    gss_buffer_desc itok, atok;

    *ictx = *actx = GSS_C_NO_CONTEXT;
    imaj = amaj = GSS_S_CONTINUE_NEEDED;
    itok.value = atok.value = NULL;
    itok.length = atok.length = 0;
    for (;;) {
        (void)gss_release_buffer(&minor, &itok);
        imaj = gss_init_sec_context(&minor,
                                    icred,
                                    ictx,
                                    tname,
                                    imech,
                                    flags,
                                    GSS_C_INDEFINITE,
                                    GSS_C_NO_CHANNEL_BINDINGS,
                                    &atok,
                                    NULL,
                                    &itok,
                                    NULL,
                                    NULL);
        if (GSS_ERROR(imaj)) {
            log_error("gss_init_sec_context()", imaj, minor);
            return false;
        }
        if (amaj == GSS_S_COMPLETE)
            break;

        (void)gss_release_buffer(&minor, &atok);
        amaj = gss_accept_sec_context(&minor,
                                      actx,
                                      acred,
                                      &itok,
                                      GSS_C_NO_CHANNEL_BINDINGS,
                                      src_name,
                                      amech,
                                      &atok,
                                      NULL,
                                      NULL,
                                      deleg_cred);
        if (GSS_ERROR(amaj)) {
            log_error("gss_accept_sec_context()", amaj, minor);
            return false;
        }
        (void)gss_release_buffer(&minor, &itok);
        if (imaj == GSS_S_COMPLETE) {
            break;
        }
    }

    if (imaj != GSS_S_COMPLETE || amaj != GSS_S_COMPLETE) {
        printf("One side wants to continue after the other is done");
        return false;
    }

    (void)gss_release_buffer(&minor, &itok);
    (void)gss_release_buffer(&minor, &atok);

    return true;
}

static bool
init_accept_sec_context(gss_cred_id_t claimant_cred_handle,
                        gss_cred_id_t verifier_cred_handle,
                        gss_cred_id_t *deleg_cred_handle)
{
    OM_uint32 maj, min, flags;
    gss_name_t source_name = GSS_C_NO_NAME, target_name = GSS_C_NO_NAME;
    gss_ctx_id_t initiator_context, acceptor_context;
    gss_OID mech = &mech_krb5;
    bool success = false;

    maj = gss_inquire_cred(
        &min, verifier_cred_handle, &target_name, NULL, NULL, NULL);
    if (GSS_ERROR(maj)) {
        log_error("gss_inquire_cred()", maj, min);
        goto done;
    }

    flags   = GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG;
    flags   = GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG;
    success = establish_contexts(mech,
                                 claimant_cred_handle,
                                 verifier_cred_handle,
                                 target_name,
                                 flags,
                                 &initiator_context,
                                 &acceptor_context,
                                 &source_name,
                                 &mech,
                                 deleg_cred_handle);
    if (success)
        enumerate_attributes(source_name);
done:
    if (source_name != GSS_C_NO_NAME)
        (void)gss_release_name(&min, &source_name);

    if (target_name != GSS_C_NO_NAME)
        (void)gss_release_name(&min, &target_name);

    if (initiator_context != NULL)
        (void)gss_delete_sec_context(&min, &initiator_context, NULL);

    if (acceptor_context != NULL)
        (void)gss_delete_sec_context(&min, &acceptor_context, NULL);

    return success;
}

static bool
init_creds(gss_cred_id_t *service_creds, gss_cred_usage_t intent)
{
    OM_uint32 maj, min;
    gss_key_value_element_desc keytab_elm = {"keytab", keytab_path};
    gss_key_value_set_desc store          = {1, &keytab_elm};

    maj = gss_acquire_cred_from(&min,
                                GSS_C_NO_NAME,
                                GSS_C_INDEFINITE,
                                GSS_C_NO_OID_SET,
                                intent,
                                (keytab_path != NULL) ? &store : NULL,
                                service_creds,
                                NULL,
                                NULL);
    if (GSS_ERROR(maj)) {
        log_error("gss_acquire_cred", maj, min);
        return false;
    }

    return true;
}

static bool
impersonate(const char *name)
{
    OM_uint32 maj, min;
    gss_name_t desired_principal  = GSS_C_NO_NAME;
    gss_cred_id_t client_creds    = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t service_creds   = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t delegated_creds = GSS_C_NO_CREDENTIAL;
    bool success                  = false;

    if (!init_creds(&service_creds, GSS_C_BOTH)) {
        goto done;
    }

    desired_principal = import_name(name);
    if (desired_principal == GSS_C_NO_NAME) {
        goto done;
    }

    maj = gss_acquire_cred_impersonate_name(&min,
                                            service_creds,
                                            desired_principal,
                                            GSS_C_INDEFINITE,
                                            GSS_C_NO_OID_SET,
                                            GSS_C_INITIATE,
                                            &client_creds,
                                            NULL,
                                            NULL);
    if (GSS_ERROR(maj)) {
        log_error("gss_acquire_cred_impersonate_name()", maj, min);
        goto done;
    }

    if (ccache_path != NULL) {
        if (!store_creds_into_cache(client_creds, ccache_path)) {
            fprintf(stderr, "Failed to store credentials in cache\n");
            goto done;
        }
    }

    fprintf(stderr, "Acquired credentials for %s\n", name);
    init_accept_sec_context(client_creds, service_creds, &delegated_creds);

    if (delegated_creds != GSS_C_NO_CREDENTIAL) {
        gss_buffer_set_t bufset = GSS_C_NO_BUFFER_SET;
        /* Inquire impersonator status. */
        maj = gss_inquire_cred_by_oid(
            &min, client_creds, GSS_KRB5_GET_CRED_IMPERSONATOR, &bufset);
        if (GSS_ERROR(maj)) {
            log_error("gss_inquire_cred_by_oid()", maj, min);
            goto done;
        }
        if (bufset->count == 0) {
            log_error("gss_inquire_cred_by_oid(user) returned NO impersonator", 0, 0);
            goto done;
        }
        (void)gss_release_buffer_set(&min, &bufset);

        maj = gss_inquire_cred_by_oid(
            &min, service_creds, GSS_KRB5_GET_CRED_IMPERSONATOR, &bufset);
        if (GSS_ERROR(maj)) {
            log_error("gss_inquire_cred_by_oid()", maj, min);
            goto done;
        }
        if (bufset->count != 0) {
            log_error("gss_inquire_cred_by_oid(svc) returned an impersonator", 0, 0);
            goto done;
        }
        (void)gss_release_buffer_set(&min, &bufset);
        success = true;
    }

done:

    if (desired_principal != GSS_C_NO_NAME)
        gss_release_name(&min, &desired_principal);

    if (client_creds != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&min, &client_creds);

    if (service_creds != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&min, &service_creds);

    if (delegated_creds != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&min, &delegated_creds);

    return success;
}

static bool
init_with_password(const char *name, const char *password)
{
    OM_uint32 maj, min;
    gss_name_t desired_principal = GSS_C_NO_NAME;
    gss_cred_id_t client_creds   = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t service_creds  = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc pwd_buf;
    bool success = false;

    if (!init_creds(&service_creds, GSS_C_ACCEPT)) {
        goto done;
    }

    desired_principal = import_name(name);
    if (desired_principal == GSS_C_NO_NAME) {
        goto done;
    }

    if (init_tgt && password != NULL) {
        pwd_buf.value  = (void *)password;
        pwd_buf.length = strlen(password);
        maj            = gss_acquire_cred_with_password(&min,
                                             desired_principal,
                                             &pwd_buf,
                                             GSS_C_INDEFINITE,
                                             GSS_C_NO_OID_SET,
                                             GSS_C_INITIATE,
                                             &client_creds,
                                             NULL,
                                             NULL);
        if (GSS_ERROR(maj)) {
            log_error("gss_acquire_cred_with_password()", maj, min);
            goto done;
        }
    }

    if ((ccache_path != NULL) && (client_creds != GSS_C_NO_CREDENTIAL)) {
        if (!store_creds_into_cache(client_creds, ccache_path)) {
            fprintf(stderr, "Failed to store credentials in cache\n");
            goto done;
        }
    }

    if (client_creds != GSS_C_NO_CREDENTIAL)
        fprintf(stderr, "Acquired credentials for %s\n", name);

    success = init_accept_sec_context(client_creds, service_creds, NULL);

done:
    if (service_creds != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&min, &client_creds);

    if (client_creds != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&min, &client_creds);

    if (desired_principal != GSS_C_NO_NAME)
        gss_release_name(&min, &desired_principal);

    return success;
}

struct poptOption popt_options[] = {
    {
        .longName  = "enterprise",
        .shortName = 'E',
        .argInfo   = POPT_ARG_NONE | POPT_ARGFLAG_OPTIONAL,
        .val       = 'E',
        .descrip   = "Treat the user principal as an enterprise name",
    },
    {
        .longName  = "ccache",
        .shortName = 'c',
        .argInfo   = POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL,
        .val       = 'c',
        .descrip   = "Credentials cache file to save acquired tickets to. "
                   "Tickets aren't saved by default",
        .argDescrip = "CCACHE-PATH",
    },
    {
        .longName  = "keytab",
        .shortName = 'k',
        .argInfo   = POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL,
        .val       = 'k',
        .descrip   = "Keytab for a service key to acquire service ticket for. "
                   "Default keytab is used if omitted",
        .argDescrip = "KEYTAB-PATH",
    },
    {
        .longName  = "reuse",
        .shortName = 'r',
        .argInfo   = POPT_ARG_NONE | POPT_ARGFLAG_OPTIONAL,
        .val       = 'r',
        .descrip   = "Re-use user principal's TGT from a default ccache",
    },
    {
        .longName  = "help",
        .shortName = 'h',
        .argInfo   = POPT_ARG_NONE | POPT_ARGFLAG_OPTIONAL,
        .val       = 'h',
        .descrip   = "Show this help message",
    },

    POPT_TABLEEND};

static void
print_help(poptContext pc, const char *name)
{
    const char *help = ""
                       "Usage: %s [options] {impersonate|ticket} user@realm\n\n"
                       "Print MS-PAC structure from a service ticket.\n\n"
                       "Operation 'impersonate':\n"
                       "\tExpects a TGT for a service in the default ccache and attempts to "
                       "obtain a service\n"
                       "\tticket to itself by performing a protocol transition for the specified "
                       "user (S4U2Self).\n\n"
                       "Operation 'ticket':\n"
                       "\tExpects a user password to be provided, acquires ticket granting ticket "
                       "and attempts to \n"
                       "\tobtain a service ticket to the specified service.\n\n"
                       "Resulting service ticket can be stored in the credential cache file "
                       "specified by '-c file' option.\n\n"
                       "Defaults to the host principal service name and the host keytab.\n\n";
    fprintf(stderr, help, name);
    poptPrintHelp(pc, stderr, 0);
}

static char *
ask_password(TALLOC_CTX *context, char *prompt1, char *prompt2, bool match)
{
    krb5_prompt ap_prompts[2];
    krb5_data k5d_pw0;
    krb5_data k5d_pw1;
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define PWD_BUFFER_SIZE MAX((IPAPWD_PASSWORD_MAX_LEN + 2), 1024)
    char pw0[PWD_BUFFER_SIZE];
    char pw1[PWD_BUFFER_SIZE];
    char *password;
    int num_prompts = match ? 2 : 1;

    k5d_pw0.length       = sizeof(pw0);
    k5d_pw0.data         = pw0;
    ap_prompts[0].prompt = prompt1;
    ap_prompts[0].hidden = 1;
    ap_prompts[0].reply  = &k5d_pw0;

    if (match) {
        k5d_pw1.length       = sizeof(pw1);
        k5d_pw1.data         = pw1;
        ap_prompts[1].prompt = prompt2;
        ap_prompts[1].hidden = 1;
        ap_prompts[1].reply  = &k5d_pw1;
    }

    /* krb5_prompter_posix does not use krb5_context internally */
    krb5_prompter_posix(NULL, NULL, NULL, NULL, num_prompts, ap_prompts);

    if (match && (strcmp(pw0, pw1))) {
        fprintf(stderr, "Passwords do not match!\n");
        return NULL;
    }

    if (k5d_pw0.length > IPAPWD_PASSWORD_MAX_LEN) {
        fprintf(stderr, "%s\n", "Password is too long!\n");
        return NULL;
    }

    password = talloc_strndup(context, pw0, k5d_pw0.length);
    if (!password)
        return NULL;
    return password;
}

int main(int argc, char *argv[])
{
    int ret = 0, c = 0;
    const char **argv_const = discard_const_p(const char *, argv);
    const char **args       = NULL;
    char *password          = NULL;
    poptContext pc;

    frame = talloc_init("printpac");
    pc    = poptGetContext(
        "printpac", argc, argv_const, popt_options, POPT_CONTEXT_KEEP_FIRST);
    while ((c = poptGetNextOpt(pc)) >= 0) {
        switch (c) {
        case 'c':
            ccache_path = talloc_strdup(frame, poptGetOptArg(pc));
            break;
        case 'E':
            import_name_oid = &GSS_KRB5_NT_ENTERPRISE_NAME;
            break;
        case 'k':
            keytab_path = talloc_strdup(frame, poptGetOptArg(pc));
            break;
        case 'r':
            init_tgt = false;
            break;
        case 'h':
            print_help(pc, argv[0]);
            ret = 0;
            goto done;
        }
    }
    if (c < -1) {
        fprintf(stderr,
                "%s: %s\n",
                poptBadOption(pc, POPT_BADOPTION_NOALIAS),
                poptStrerror(c));
        ret = 1;
        goto done;
    }
    args = poptGetArgs(pc);
    for (c = 0; args && args[c]; c++)
        ;

    if (c < 3) {
        print_help(pc, args[0]);
        ret = 1;
        goto done;
    }

    c -= 2;
    if (strncasecmp("ticket", args[1], strlen("ticket")) == 0) {
        operation = OP_SERVICE_TICKET;
        if (init_tgt) {
            switch (c) {
            case 1:
                password = ask_password(frame, "Password", NULL, false);
                break;
            case 2:
                password = talloc_strdup(frame, args[3]);
                break;
            default:
                fprintf(stderr,
                        "Service ticket needs user principal and password\n\n");
                print_help(pc, args[0]);
                ret = 1;
                goto done;
                break;
            }
        } else {
            if (c != 1) {
                fprintf(stderr, "Service ticket needs user principal and password\n\n");
                print_help(pc, args[0]);
                ret = 1;
                goto done;
            }
        }
    } else if (strncasecmp("impersonate", args[1], strlen("impersonate")) == 0) {
        operation = OP_IMPERSONATE;
        if (c != 1) {
            fprintf(stderr, "Impersonation ticket needs user principal\n\n");
            print_help(pc, args[0]);
            ret = 1;
            goto done;
        }
    } else {
        fprintf(stderr, "Wrong request type: %s\n\n", args[1]);
        print_help(pc, args[0]);
        ret = 1;
        goto done;
    }

    switch (operation) {
    case OP_IMPERSONATE:
        ret = impersonate(args[2]) != true;
        break;
    case OP_SERVICE_TICKET:
        ret = init_with_password(args[2], password) != true;
        break;
    }

done:
    poptFreeContext(pc);
    talloc_free(frame);
    return ret;
}
