/*
 * FreeIPA 2FA companion daemon
 *
 * Authors: Sumit Bose <sbose@redhat.com>
 *
 * Copyright (C) 2022  Sumit Bose, Red Hat
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

/*
 * This file contains various helper functions for the passkey feature.
 */

#define _GNU_SOURCE /* for asprintf() */
#include <stdio.h>
#include <fcntl.h>
#include <jansson.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include "internal.h"

struct passkey_data {
    int phase;
    char *state;
    union {
        struct passkey_challenge {
            char *domain;
            json_t *credential_id_list;
            int user_verification;
            unsigned char *cryptographic_challenge;
        } challenge;

        struct sss_passkey_reply {
            char *credential_id;
            char *cryptographic_challenge;
            char *authenticator_data;
            char *assertion_signature;
            char *user_id;
        } response;
    } data;
    json_t *jdata;
    json_t *jroot;
};

struct otpd_queue_item_passkey {
    char *domain;
    char *ipaRequireUserVerification;
    struct passkey_data *data_in;
    struct passkey_data *data_out;
    krb5_data state;
    char* ipapasskeyDebugLevelStr;
    krb5_boolean ipapasskeyDebugFido2;
};

static void free_passkey_data(struct passkey_data *p)
{
    if (p == NULL) {
        return;
    }

    if (p->phase == 1) {
        free(p->data.challenge.domain);
        free(p->data.challenge.cryptographic_challenge);
    }

    json_decref(p->jdata);
    json_decref(p->jroot);
    free(p);
}

void free_otpd_queue_item_passkey(struct otpd_queue_item *item)
{
    if (item == NULL || item->passkey == NULL) {
        return;
    }

    free(item->passkey->domain);
    free(item->passkey->ipaRequireUserVerification);

    free_passkey_data(item->passkey->data_in);
    free_passkey_data(item->passkey->data_out);

    free(item->passkey);
}

static struct otpd_queue_item_passkey *get_otpd_queue_item_passkey(void)
{
    struct otpd_queue_item_passkey *p;

    p = calloc(1, sizeof(struct otpd_queue_item_passkey));
    if (p == NULL) {
        return NULL;
    }

    p->data_in = calloc(1, sizeof(struct passkey_data));
    if (p->data_in == NULL) {
        free(p);
        return NULL;
    }

    p->data_out = calloc(1, sizeof(struct passkey_data));
    if (p->data_out == NULL) {
        free(p->data_in);
        free(p);
        return NULL;
    }

    p->data_in->phase = -1;
    p->data_out->phase = -1;

    return p;
}

#define PASSKEY_PREFIX "passkey "
#define ENV_PASSKEY_CHILD_DEBUG_LEVEL "passkey_child_debug_level"

/* Parse the passkey configuration */
const char *otpd_parse_passkey(LDAP *ldp, LDAPMessage *entry,
                               struct otpd_queue_item *item)
{
    int i;
    char **objectclasses = NULL;
    long dbg_lvl = 0;
    const char *dbg_env = NULL;
    char *endptr = NULL;

    if (item->passkey == NULL) {
        otpd_log_req(item->req,
                     "Missing passkey struct to store passkey configuration");
        return strerror(EINVAL);
    }

    while (entry != NULL) {
        i = get_string_array(ldp, entry, "objectclass", &objectclasses);
        if (i != 0) {
            return strerror(i);
        }

        if (auth_type_is(objectclasses, "ipapasskeyconfigobject")) {
            free(objectclasses);

            i = get_string(ldp, entry, "ipaRequireUserVerification",
                           &item->passkey->ipaRequireUserVerification);
            if ((i != 0) && (i != ENOENT)) {
                return strerror(i);
            }
        } else if (auth_type_is(objectclasses, "domainRelatedObject")) {
            free(objectclasses);

            i = get_string(ldp, entry, "associatedDomain",
                           &item->passkey->domain);
            if ((i != 0) && (i != ENOENT)) {
                return strerror(i);
            }
        }

        entry = ldap_next_entry(ldp, entry);
    };

    item->passkey->ipapasskeyDebugLevelStr = NULL;
    item->passkey->ipapasskeyDebugFido2 = FALSE;
    dbg_env = getenv(ENV_PASSKEY_CHILD_DEBUG_LEVEL);
    if (dbg_env != NULL && *dbg_env != '\0') {
        errno = 0;
        dbg_lvl = strtoul(dbg_env, &endptr, 10);
        if (errno == 0 && *endptr == '\0') {
            if (dbg_lvl < 0) {
                dbg_lvl = 0;
            } else if (dbg_lvl > 10) {
                dbg_lvl = 10;
            }
            if (asprintf(&item->passkey->ipapasskeyDebugLevelStr, "%ld",
                         dbg_lvl) != -1) {
                if (dbg_lvl > 5) {
                    item->passkey->ipapasskeyDebugFido2 = TRUE;
                }
            } else {
                otpd_log_req(item->req, "Failed to copy debug level");
            }
        } else {
            otpd_log_req(item->req,
                         "Cannot parse value [%s] from environment variable [%s]",
                         dbg_env, ENV_PASSKEY_CHILD_DEBUG_LEVEL);
        }
    }

    return NULL;
}

static int decode_json(const char *inp, size_t size, struct passkey_data *data)
{
    json_error_t jret;
    int ret;

    data->jroot = json_loadb(inp, size, 0, &jret);
    if (data->jroot == NULL) {
        return EINVAL;
    }
    data->jdata = NULL;
    data->phase = -1;

    ret = json_unpack(data->jroot, "{s:i, s?:s, s?:o}",
                     "phase", &data->phase,
                     "state", &data->state,
                     "data", &data->jdata);
    if (ret != 0) {
        ret = EINVAL;
        goto done;
    }

    switch (data->phase) {
    case 0: /* SSS_PASSKEY_PHASE_INIT */
        /* no data */
        if (data->jdata != NULL) {
            ret = EINVAL;
        } else {
            ret = 0;
        }
        break;
    case 2: /* SSS_PASSKEY_PHASE_REPLY */
        ret = json_unpack(data->jdata, "{s:s, s:s, s:s, s:s}",
                "credential_id", &data->data.response.credential_id,
                "cryptographic_challenge", &data->data.response.cryptographic_challenge,
                "authenticator_data", &data->data.response.authenticator_data,
                "assertion_signature", &data->data.response.assertion_signature,
                "user_id", &data->data.response.user_id);
        break;
    default:
        ret = EINVAL;
    }

done:
    if (ret != 0) {
        json_decref(data->jdata);
        data->jdata = NULL;
        json_decref(data->jroot);
        data->jroot = NULL;
    }

    return ret;
}

static int passkey_parse_data(const char *data, size_t size, struct otpd_queue_item *item)
{
    item->passkey = get_otpd_queue_item_passkey();
    if (item->passkey == NULL) {
        return ENOMEM;
    }

    return decode_json(data, size, item->passkey->data_in);
}

bool is_passkey(struct otpd_queue_item *item)
{
    const krb5_data *data_pwd;
    krb5_data data_state = { 0 };
    int ret;

    if (item->passkey != NULL) {
        return true;
    }

    data_pwd = krad_packet_get_attr(item->req,
                                    krad_attr_name2num("User-Password"), 0);
    ret = get_krad_attr_from_packet(item->req,
                                    krad_attr_name2num("Proxy-State"),
                                    &data_state);

    if (data_pwd == NULL && ret == 0
            && data_state.length > strlen(PASSKEY_PREFIX)
            && strncmp(data_state.data, PASSKEY_PREFIX,
                       strlen(PASSKEY_PREFIX)) == 0
            && (item->user.ipauserauthtypes == NULL
                    || item->user.ipauserauthtypes[0] == NULL 
                    || *(item->user.ipauserauthtypes[0]) == '\0'
                    || auth_type_is(item->user.ipauserauthtypes, "passkey"))) {

        ret = passkey_parse_data(data_state.data + strlen(PASSKEY_PREFIX),
                                 data_state.length - strlen(PASSKEY_PREFIX) - 1,
                                 item);
        krb5_free_data_contents(NULL, &data_state);
        if (ret != 0) {
            return false;
        }
        return true;
    }

    return false;
}


#define PK_PREF "passkey:"

static json_t *ipa_passkey_to_json_array(char **ipa_passkey)
{
    int ret;
    const char *sep;
    char *start;
    size_t c;
    json_t *ja = NULL;
    json_t *js;

    if (ipa_passkey == NULL || *ipa_passkey == NULL) {
        return NULL;
    }

    ja = json_array();
    if (ja == NULL) {
        return NULL;
    }

    for (c = 0; ipa_passkey[c] != NULL; c++) {
        if (strncmp(ipa_passkey[c], PK_PREF, strlen(PK_PREF)) != 0) {
            otpd_log_err(ret, "Missing prefix in [%s]", ipa_passkey[c]);
            continue;
        }
        start = ipa_passkey[c] + strlen(PK_PREF);
        sep = strchr(start, ',');
        if (sep == NULL || sep == start) {
            otpd_log_err(ret, "Missing seperator in [%s]", ipa_passkey[c]);
            continue;
        }

        js = json_stringn(start, sep - start);
        if (js == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = json_array_append_new(ja, js);
        if (ret != 0) {
            goto done;
        }
    }

done:
    if (ret != 0) {
        json_decref(ja);
        return NULL;
    }

    return ja;
}

/* passkey string:
 *     key_handle,public_key(,optional_user_id)
 */
static char *ipa_passkey_get_public_key(char **ipa_passkey, const char *key_id)
{
    char *sep;
    char *sep2;
    size_t c;
    char *start;

    if (ipa_passkey == NULL || *ipa_passkey == NULL
                            || key_id == NULL || *key_id == '\0') {
        return NULL;
    }

    for (c = 0; ipa_passkey[c] != NULL; c++) {
        if (strncmp(ipa_passkey[c], PK_PREF, strlen(PK_PREF)) != 0) {
            otpd_log_err(EINVAL, "Missing prefix in [%s]", ipa_passkey[c]);
            continue;
        }
        start = ipa_passkey[c] + strlen(PK_PREF);

        sep = strchr(start, ',');
        if (sep == NULL || sep == start) {
            otpd_log_err(EINVAL, "Missing seperator in [%s]", ipa_passkey[c]);
            continue;
        }

        if (strncmp(start, key_id, sep - start) == 0) {
            sep2 = strchrnul(sep + 1, ',');
            if (sep2 == sep + 1) {
                return NULL;
            }
            *sep2 = '\0';
            return (sep + 1);
        }
    }

    return NULL;
}

#define CHALLENGE_LENGTH 32
static unsigned char *get_b64_challenge(void)
{
    int ret;
    unsigned char buf[CHALLENGE_LENGTH];
    unsigned char *b64;

    ret = RAND_bytes(buf, CHALLENGE_LENGTH);
    if (ret != 1) {
        return NULL;
    }

    b64 = calloc(1, 2 * CHALLENGE_LENGTH);
    if (b64 == NULL) {
        return NULL;
    }

    ret = EVP_EncodeBlock(b64, buf, CHALLENGE_LENGTH);
    if (ret == 0) {
        free(b64);
        return NULL;
    }

    return b64;
}

static int prepare_rad_reply(struct otpd_queue_item *item)
{
    krad_attrset *attrset = NULL;
    int ret;
    json_t *jtmp = NULL;
    char *stmp = NULL;
    krb5_data data = { 0 };

    ret = krad_attrset_new(ctx.kctx, &attrset);
    if (ret != 0) {
        otpd_log_err(ret, "Failed to create radius attribute set");
        goto done;
    }

    jtmp = json_pack("{s:i, s:s, s:o}", "phase", item->passkey->data_out->phase,
                                        "state", item->passkey->data_out->state,
                                        "data", item->passkey->data_out->jdata);
    if (jtmp == NULL) {
        ret = EIO;
        otpd_log_err(ret, "Failed to pack JSON reply");
        goto done;
    }

    stmp = json_dumps(jtmp, JSON_COMPACT);
    if (stmp == NULL) {
        ret = EIO;
        otpd_log_err(ret, "Failed to dump JSON string");
        goto done;
    }

    ret = asprintf(&(data.data), "passkey %s", stmp);
    if (ret < 0) {
        ret = ENOMEM;
        otpd_log_err(ret, "Failed to generate reply string");
        goto done;
    }
    data.length = strlen(data.data);
    data.magic = 0;


    ret = add_krad_attr_to_set(item->req, attrset, &data,
                               krad_attr_name2num("Proxy-State"),
                               "Failed to serialize state to attribute set");
    if (ret != 0) {
        otpd_log_err(ret, "Failed to add Proxy-State");
        goto done;
    }

    ret = krad_packet_new_response(ctx.kctx, SECRET,
                                   krad_code_name2num("Access-Challenge"),
                                   attrset,
                                   item->req, &item->rsp);
    if (ret != 0) {
        otpd_log_err(ret, "Failed to create radius response");
        item->rsp = NULL;
    }

    ret = 0;

done:
    krad_attrset_free(attrset);
    free(stmp);
    json_decref(jtmp);

    if (ret != 0) {
        free(data.data);
    }

    return ret;
}

static int do_passkey_challenge(struct otpd_queue_item *item)
{
    unsigned char *challenge = NULL;
    int ret;
    struct passkey_data *d;

    d = item->passkey->data_out;

    d->data.challenge.credential_id_list = ipa_passkey_to_json_array(
                                                         item->user.ipaPassKey);
    if (d->data.challenge.credential_id_list == NULL) {
        return EINVAL;
    }

    /* Secure by default, assume user verification is enabled and disable it
     * only if the option is set to 'false'. */
    d->data.challenge.user_verification = 1;
    if (item->passkey->ipaRequireUserVerification != NULL
            && strcasecmp(item->passkey->ipaRequireUserVerification,
                          "false") == 0) {
        d->data.challenge.user_verification = 0;
    }

    d->data.challenge.cryptographic_challenge = get_b64_challenge();
    if (d->data.challenge.cryptographic_challenge == NULL) {
        ret = ENOMEM;
        goto done;
    }

    d->jdata = json_pack("{s:s, s:o, s:i, s:s}",
                                     "domain", item->passkey->domain,
                                     "credential_id_list",
                                     d->data.challenge.credential_id_list,
                                     "user_verification",
                                     d->data.challenge.user_verification,
                                     "cryptographic_challenge",
                                     d->data.challenge.cryptographic_challenge);
    if (d->jdata == NULL) {
        ret = EIO;
        goto done;
    }

    d->phase = 1; /* SSS_PASSKEY_PHASE_CHALLENGE */
    d->state = strdup("ipa_otpd state");

    ret = prepare_rad_reply(item);
    if (ret != 0) {
        otpd_log_err(ret, "prepare_rad_reply() failed.");
        goto done;
    }

    ret = 0;
done:
    free(challenge);

    otpd_queue_push(&ctx.stdio.responses, item);
    verto_set_flags(ctx.stdio.writer, VERTO_EV_FLAG_PERSIST |
                                      VERTO_EV_FLAG_IO_ERROR |
                                      VERTO_EV_FLAG_IO_READ |
                                      VERTO_EV_FLAG_IO_WRITE);

    return ret;
}

struct child_ctx {
    int read_from_child;
    int write_to_child;
    verto_ev *read_ev;
    verto_ev *write_ev;
    verto_ev *child_ev;
    struct otpd_queue_item *item;
};

static void passkey_on_child_writable(verto_ctx *vctx, verto_ev *ev)
{
    (void)vctx; /* Unused */

    /* no input needed */
    verto_del(ev);
    return;
}

static void passkey_on_child_readable(verto_ctx *vctx, verto_ev *ev)
{
    (void)vctx; /* Unused */

    /* no output expected */
    verto_del(ev);
    return;
}

static void passkey_on_child_exit(verto_ctx *vctx, verto_ev *ev)
{
    (void)vctx; /* Unused */
    int ret;
    verto_proc_status st;
    struct child_ctx *child_ctx = NULL;

    child_ctx = (struct child_ctx *) verto_get_private(ev);
    if (child_ctx == NULL) {
        otpd_log_err(EINVAL, "Lost child context");
        verto_del(ev);
        return;
    }

    /* Make sure ctx.stdio.responses will at least return an error */
    child_ctx->item->rsp = NULL;
    child_ctx->item->sent = 0;

    st = verto_get_proc_status(ev);

    if (!WIFEXITED(st)) {
        otpd_log_err(0, "Child didn't exit normally.");
        verto_del(ev);
        goto done;
    }

    /* The krad req might not be available at this stage anymore, so
     * otpd_log_err() is used. */
    otpd_log_err(0, "Child finished with status [%d].", WEXITSTATUS(st));

    verto_del(ev);

    if (WEXITSTATUS(st) != 0) {
        /* verification failed */
        goto done;
    }

    ret = krad_packet_new_response(ctx.kctx, SECRET,
                                   krad_code_name2num("Access-Accept"), NULL,
                                   child_ctx->item->req, &child_ctx->item->rsp);
    if (ret != 0) {
        otpd_log_err(ret, "Failed to create radius response");
        child_ctx->item->rsp = NULL;
    }

done:
    otpd_queue_push(&ctx.stdio.responses, child_ctx->item);
    verto_set_flags(ctx.stdio.writer, VERTO_EV_FLAG_PERSIST |
                                      VERTO_EV_FLAG_IO_ERROR |
                                      VERTO_EV_FLAG_IO_READ |
                                      VERTO_EV_FLAG_IO_WRITE);
}

static void free_child_ctx(verto_ctx *vctx, verto_ev *ev)
{
    (void)vctx; /* Unused */
    struct child_ctx *child_ctx;

    child_ctx = verto_get_private(ev);

    free(child_ctx);
}

static int set_fd_nonblocking(int fd)
{
    int flags;
    int ret;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        ret = errno;
        return ret;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        ret = errno;
        return ret;
    }

    return 0;
}

#ifndef PASSKEY_CHILD_PATH
#define PASSKEY_CHILD_PATH "/usr/libexec/sssd/passkey_child"
#endif

static int do_passkey_response(struct otpd_queue_item *item)
{
    int ret;
    pid_t child_pid;
    int pipefd_to_child[2] = { -1, -1};
    int pipefd_from_child[2] = { -1, -1};
    /* Up to 50 arguments to the helper supported. The amount of arguments
     * is controlled inside this function. Right now max used is below 20 */
    char *args[50] = {NULL};
    size_t args_idx = 0;
    struct child_ctx *child_ctx;
    char *pk = NULL;

    child_ctx = calloc(sizeof(struct child_ctx), 1);
    if (child_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }
    child_ctx->item = item;

    pk = ipa_passkey_get_public_key(item->user.ipaPassKey,
                           item->passkey->data_in->data.response.credential_id);
    if (pk == NULL) {
        ret = EINVAL;
        otpd_log_err(ret, "No matching public key found for [%s]",
                     item->passkey->data_in->data.response.credential_id);
        goto done;
    }

    args[args_idx++] = PASSKEY_CHILD_PATH;
    args[args_idx++] = "--verify-assert";
    args[args_idx++] = "--domain";
    args[args_idx++] = item->passkey->domain;
    args[args_idx++] = "--key-handle";
    args[args_idx++] = item->passkey->data_in->data.response.credential_id;
    args[args_idx++] = "--public-key";
    args[args_idx++] = pk;
    args[args_idx++] = "--cryptographic-challenge";
    args[args_idx++] = item->passkey->data_in->data.response.cryptographic_challenge;
    args[args_idx++] = "--auth-data";
    args[args_idx++] = item->passkey->data_in->data.response.authenticator_data;
    args[args_idx++] = "--signature";
    args[args_idx++] = item->passkey->data_in->data.response.assertion_signature;
    if (item->passkey->ipapasskeyDebugLevelStr != NULL) {
        args[args_idx++] = "--debug-level";
        args[args_idx++] = item->passkey->ipapasskeyDebugLevelStr;
    }
    if (item->passkey->ipapasskeyDebugFido2) {
        args[args_idx++] = "--debug-libfido2";
    }

    ret = pipe(pipefd_from_child);
    if (ret == -1) {
        ret = errno;
        goto done;
    }
    ret = pipe(pipefd_to_child);
    if (ret == -1) {
        ret = errno;
        goto done;
    }

    child_pid = fork();

    if (child_pid == 0) { /* child */
        close(pipefd_to_child[1]);
        ret = dup2(pipefd_to_child[0], STDIN_FILENO);
        if (ret == -1) {
            exit(EXIT_FAILURE);
        }

        close(pipefd_from_child[0]);
        ret = dup2(pipefd_from_child[1], STDOUT_FILENO);
        if (ret == -1) {
            exit(EXIT_FAILURE);
        }

        execv(args[0], args);
        exit(EXIT_FAILURE);
    } else if (child_pid > 0) { /* parent */
        close(pipefd_to_child[0]);
        set_fd_nonblocking(pipefd_to_child[1]);
        child_ctx->write_to_child = pipefd_to_child[1];

        close(pipefd_from_child[1]);
        set_fd_nonblocking(pipefd_from_child[0]);
        child_ctx->read_from_child = pipefd_from_child[0];

        child_ctx->write_ev = verto_add_io(ctx.vctx, VERTO_EV_FLAG_PERSIST |
                                                     VERTO_EV_FLAG_IO_CLOSE_FD |
                                                     VERTO_EV_FLAG_IO_ERROR |
                                                     VERTO_EV_FLAG_IO_WRITE,
                                                     passkey_on_child_writable,
                                                     child_ctx->write_to_child);
        if (child_ctx->write_ev == NULL) {
            ret = ENOMEM;
            otpd_log_err(ret, "Unable to initialize passkey writer event");
            goto done;
        }
        verto_set_private(child_ctx->write_ev, child_ctx, NULL);

        child_ctx->read_ev = verto_add_io(ctx.vctx, VERTO_EV_FLAG_PERSIST |
                                                    VERTO_EV_FLAG_IO_CLOSE_FD |
                                                    VERTO_EV_FLAG_IO_ERROR |
                                                    VERTO_EV_FLAG_IO_READ,
                                                    passkey_on_child_readable,
                                                    child_ctx->read_from_child);
        if (child_ctx->read_ev == NULL) {
            ret = ENOMEM;
            otpd_log_err(ret, "Unable to initialize passkey reader event");
            goto done;
        }
        verto_set_private(child_ctx->read_ev, child_ctx, NULL);

        child_ctx->child_ev = verto_add_child(ctx.vctx, VERTO_EV_FLAG_NONE,
                                              passkey_on_child_exit, child_pid);
        verto_set_private(child_ctx->child_ev, child_ctx, free_child_ctx);

    } else { /* error */
        ret = errno;
        otpd_log_err(ret, "Failed to fork passkey_child");
        goto done;
    }

    ret = 0;

done:
    if (ret != 0) {
        free(child_ctx);
    }

    return ret;
}

int do_passkey(struct otpd_queue_item *item)
{
    if (item == NULL || item->passkey == NULL
            || item->passkey->data_in == NULL) {
        return EINVAL;
    }

    switch (item->passkey->data_in->phase) {
    case 0: /* SSS_PASSKEY_PHASE_INIT */
        return do_passkey_challenge(item);
    case 2: /* SSS_PASSKEY_PHASE_REPLY */
        return do_passkey_response(item);
    default:
        return EINVAL;
    }

}
