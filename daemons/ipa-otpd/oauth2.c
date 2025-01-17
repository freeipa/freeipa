/*
 * FreeIPA 2FA companion daemon
 *
 * Authors: Sumit Bose <sbose@redhat.com>
 *
 * Copyright (C) 2021 Red Hat
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
 * This file reaches out to a third-party IdP to handle an OAuth2
 * authentication request (stdio.c/query.c) if the user is configured
 * accordingly. The result is placed in the stdout queue (stdio.c).
 */

#include <krb5/krb5.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/uio.h>

#include "internal.h"

#define OIDC_CHILD_PATH "/usr/libexec/sssd/oidc_child"

struct child_ctx {
    int read_from_child;
    int write_to_child;
    verto_ev *read_ev;
    verto_ev *write_ev;
    verto_ev *child_ev;
    struct otpd_queue_item *item;
    struct otpd_queue_item *saved_item;
    enum oauth2_state oauth2_state;
};

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

static void free_child_ctx(verto_ctx *vctx, verto_ev *ev)
{
    (void)vctx; /* Unused */
    struct child_ctx *child_ctx;

    child_ctx = verto_get_private(ev);

    free(child_ctx);
}

static void oauth2_on_child_exit(verto_ctx *vctx, verto_ev *ev)
{
    (void)vctx; /* Unused */
    verto_proc_status st;

    st = verto_get_proc_status(ev);

    /* The krad req might not be available at this stage anymore, so
     * otpd_log_err() is used. */
    otpd_log_err(0, "Child finished with status [%d].", WEXITSTATUS(st));
}

static void oauth2_on_child_writable(verto_ctx *vctx, verto_ev *ev)
{
    (void)vctx; /* Unused */
    ssize_t io;
    struct child_ctx *child_ctx;
    struct iovec iov[3];

    child_ctx = verto_get_private(ev);
    if (child_ctx == NULL) {
        otpd_log_err(EINVAL, "Lost child context");
        verto_del(ev);
        return;
    }

    if (child_ctx->oauth2_state == OAUTH2_GET_DEVICE_CODE) {
        if (child_ctx->item->idp.ipaidpClientSecret != NULL) {
            io = write(verto_get_fd(ev), child_ctx->item->idp.ipaidpClientSecret,
                       strlen(child_ctx->item->idp.ipaidpClientSecret));
        } else {
            io = 0;
        }
    } else {
        int idx = 0;
        if (child_ctx->item->idp.ipaidpClientSecret != NULL) {
            iov[idx].iov_base = child_ctx->item->idp.ipaidpClientSecret;
            iov[idx].iov_len = strlen(child_ctx->item->idp.ipaidpClientSecret);
	    idx++;
            iov[idx].iov_base = "\n";
            iov[idx].iov_len = 1;
	    idx++;
        }
        iov[idx].iov_base = child_ctx->saved_item->oauth2.device_code_reply;
        iov[idx].iov_len = strlen(child_ctx->saved_item->oauth2.device_code_reply);
        idx++;
        io = writev(verto_get_fd(ev), iov, idx);
    }
    otpd_queue_item_free(child_ctx->saved_item);

    if (io < 0) {
        switch (errno) {
#if defined(EWOULDBLOCK) && (!defined(EAGAIN) || EAGAIN - EWOULDBLOCK != 0)
        case EWOULDBLOCK:
#endif
#if defined(EAGAIN)
        case EAGAIN:
#endif
        case ENOBUFS:
        case EINTR:
            /* In this case, we just need to try again. */
            return;
        default:
            /* Unrecoverable. */
            break;
        }
        otpd_log_err(errno, "Failed to send to child");
    }

    verto_del(ev);
}

/* oidc_child will return two lines.
 * The first is a JSON formatted string containing the device code and other
 * data needed to get the access token in the second round. This will be
 * returned to the caller as Radius Proxy-State so that the caller will send
 * it back in the next round.
 * The second line is the string expected by the krb5 oauth2 pre-auth plugin
 * and will be send to the caller as Radius Reply-Message.
 */
static int handle_device_code_reply(struct child_ctx *child_ctx,
                                    const char *dc_reply, char *rad_reply)
{
    krad_attrset *attrset = NULL;
    int ret;
    krb5_data data = { 0 };
    struct otpd_queue_item *state_item = NULL;

    ret = otpd_queue_item_new(NULL, &state_item);
    if (ret != 0) {
        otpd_log_req(child_ctx->item->req, "Failed to allocate state item");
        goto done;
    }

    state_item->oauth2.device_code_reply = strdup(dc_reply);
    if (state_item->oauth2.device_code_reply == NULL) {
        otpd_log_req(child_ctx->item->req, "Failed to copy device code reply.");
        goto done;
    }

    ret = krad_attrset_new(ctx.kctx, &attrset);
    if (ret != 0) {
        otpd_log_req(child_ctx->item->req,
                     "Failed to create radius attribute set");
        goto done;
    }

    state_item->oauth2.state.magic = 0;

    state_item->oauth2.state.data = strdup(dc_reply);
    if (state_item->oauth2.state.data == NULL) {
        otpd_log_req(child_ctx->item->req,
                     "Failed to copy device code reply to krad.");
        goto done;
    }
    state_item->oauth2.state.length = strlen(dc_reply);

    ret = add_krad_attr_to_set(child_ctx->item->req,
                               attrset, &(state_item->oauth2.state),
                               krad_attr_name2num("Proxy-State"),
                               "Failed to serialize state to attribute set");
    if (ret != 0) {
        goto done;
    }

    data.magic = 0;
    data.data = rad_reply;
    data.length = strlen(rad_reply);
    ret = add_krad_attr_to_set(child_ctx->item->req, attrset, &data,
                               krad_attr_name2num("Reply-Message"),
                               "Failed to serialize reply to attribute set");
    if (ret != 0) {
        goto done;
    }

    ret = krad_packet_new_response(ctx.kctx, SECRET,
                                   krad_code_name2num("Access-Challenge"),
                                   attrset,
                                   child_ctx->item->req, &child_ctx->item->rsp);
    if (ret != 0) {
        otpd_log_err(ret, "Failed to create radius response");
        child_ctx->item->rsp = NULL;
    }

    otpd_queue_push(&ctx.oauth2_state.states, state_item);

    ret = 0;
done:
    krad_attrset_free(attrset);
    if (ret != 0) {
        if (state_item != NULL) {
            free(state_item->oauth2.state.data);
            free(state_item->oauth2.device_code_reply);
            free(state_item);
        }
    }

    return ret;
}

static int check_access_token_reply(struct child_ctx *child_ctx,
                                    const char *buf, size_t len)
{
    int ret;

    if (strlen(child_ctx->item->user.ipaidpSub) != len
            || memcmp(child_ctx->item->user.ipaidpSub, buf, len) != 0) {
        return EPERM;
    }

    ret = krad_packet_new_response(ctx.kctx, SECRET,
                                   krad_code_name2num("Access-Accept"), NULL,
                                   child_ctx->item->req, &child_ctx->item->rsp);
    if (ret != 0) {
        otpd_log_err(ret, "Failed to create radius response");
        child_ctx->item->rsp = NULL;
    }

    return ret;
}

static void oauth2_on_child_readable(verto_ctx *vctx, verto_ev *ev)
{
    static char buf[10240];
    ssize_t io = 0;
    struct child_ctx *child_ctx = NULL;
    int ret;
    char *rad_reply;
    char *end;

    (void) vctx; /* Unused */

    child_ctx = (struct child_ctx *) verto_get_private(ev);
    if (child_ctx == NULL) {
        otpd_log_err(EINVAL, "Lost child context");
        verto_del(ev);
        return;
    }
    /* Make sure ctx.stdio.responses will at least return an error */
    child_ctx->item->rsp = NULL;
    child_ctx->item->sent = 0;

    io = read(verto_get_fd(ev), buf, 10240);
    if (io < 0) {
        otpd_log_err(errno, "Failed to read from child");
        goto done;
    }

    if (io >= 0) {
        buf[io] = '\0';
        otpd_log_req(child_ctx->item->req, "Received: [%s]", buf);
    }

    verto_del(ev);

    if (child_ctx->oauth2_state == OAUTH2_GET_DEVICE_CODE) {
        /* expect 2 lines of output. First the orginal JSON string return by
         * the IdP from the devicecode request which will be used as input to
         * the child process in the second run. Second the JSON string returned
         * in the radius reply. */

        rad_reply = memchr(buf, '\n', io);
        if (rad_reply != NULL) {
            *rad_reply = '\0';
            rad_reply++;
            end = memchr(rad_reply, '\n', io - (rad_reply - 1 - buf));
            if (end == NULL) {
                otpd_log_req(child_ctx->item->req, "Missing second new-line.");
                goto done;
            }
            *end = '\0';

            ret = handle_device_code_reply(child_ctx, buf, rad_reply);
            if (ret != 0) {
                otpd_log_req(child_ctx->item->req,
                             "Failed to handle device code reply.");
            }
        }
    } else if (child_ctx->oauth2_state == OAUTH2_GET_ACCESS_TOKEN) {
        ret = check_access_token_reply(child_ctx, buf, (size_t) io);
        if (ret != 0) {
                otpd_log_req(child_ctx->item->req,
                             "Failed to check access token reply.");
        }
    } else {
        /* error */
        otpd_log_req(child_ctx->item->req, "Unexpected state [%d].",
                                           child_ctx->oauth2_state);
    }

done:
    otpd_queue_push(&ctx.stdio.responses, child_ctx->item);
    verto_set_flags(ctx.stdio.writer, VERTO_EV_FLAG_PERSIST |
                                      VERTO_EV_FLAG_IO_ERROR |
                                      VERTO_EV_FLAG_IO_READ |
                                      VERTO_EV_FLAG_IO_WRITE);
}

static const char *oauth2_state_to_str(enum oauth2_state oauth2_state)
{
    switch (oauth2_state) {
    case OAUTH2_NO:
        return "OAuth2 not available";
        break;
    case OAUTH2_GET_ISSUER:
        return "Get issuer from LDAP";
        break;
    case OAUTH2_GET_DEVICE_CODE:
        return "Get device code";
        break;
    case OAUTH2_GET_ACCESS_TOKEN:
        return "Get access token";
        break;
    default:
        return "Unknown OAuth2 state";
    }
}

int oauth2(struct otpd_queue_item **item, enum oauth2_state oauth2_state)
{
    int ret;
    pid_t child_pid;
    int pipefd_to_child[2] = { -1, -1};
    int pipefd_from_child[2] = { -1, -1};
    struct child_ctx *child_ctx;
    /* Up to 50 arguments to the helper supported. The amount of arguments
     * is controlled inside this function. Right now max used is below 20 */
    char *args[50] = {NULL};
    size_t args_idx = 0;
    krb5_data data_state = {0};
    struct otpd_queue_item *saved_item = NULL;

    if (oauth2_state != OAUTH2_GET_DEVICE_CODE
                && oauth2_state != OAUTH2_GET_ACCESS_TOKEN) {
        otpd_log_req((*item)->req, "Unexpected OAuth2 state [%d][%s]",
                     oauth2_state, oauth2_state_to_str(oauth2_state));
        return EINVAL;
    }

    if (oauth2_state == OAUTH2_GET_ACCESS_TOKEN) {
        ret = get_krad_attr_from_packet((*item)->req,
                                               krad_attr_name2num("Proxy-State"),
                                               &data_state);
        if ((ret != 0) || (data_state.length == 0)) {
            otpd_log_req((*item)->req, "Missing Radius Proxy-State attribute");
            return EINVAL;
        }

        saved_item = calloc(sizeof(struct otpd_queue_item), 1);
        if (saved_item == NULL) {
            otpd_log_req((*item)->req, "No matching saved state found");
            return EINVAL;
        }
        saved_item->oauth2.device_code_reply = strndup(data_state.data,
                                                       data_state.length);
        if (saved_item->oauth2.device_code_reply == NULL) {
            otpd_log_req((*item)->req, "Failed to copy device code reply");
            return EINVAL;
        }
        krb5_free_data_contents(NULL, &data_state);
    }

    child_ctx = calloc(sizeof(struct child_ctx), 1);
    if (child_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }
    child_ctx->item = (*item);
    child_ctx->saved_item = saved_item;
    child_ctx->oauth2_state = oauth2_state;

    otpd_log_req((*item)->req, "oauth2 start: %s",
                               oauth2_state_to_str(oauth2_state));

    args[args_idx++] = OIDC_CHILD_PATH;

    if (oauth2_state == OAUTH2_GET_DEVICE_CODE) {
        args[args_idx++] = "--get-device-code";
    } else {
        args[args_idx++] = "--get-access-token";
    }

    if ((*item)->idp.ipaidpIssuerURL != NULL) {
        args[args_idx++] = "--issuer-url";
        args[args_idx++] = (*item)->idp.ipaidpIssuerURL;
    } else {
        args[args_idx++] = "--device-auth-endpoint";
        args[args_idx++] = (*item)->idp.ipaidpDevAuthEndpoint;

        args[args_idx++] = "--token-endpoint";
        args[args_idx++] = (*item)->idp.ipaidpTokenEndpoint;

        args[args_idx++] = "--userinfo-endpoint";
        args[args_idx++] = (*item)->idp.ipaidpUserInfoEndpoint;

        if ((*item)->idp.ipaidpKeysEndpoint) {
            args[args_idx++] = "--jwks-uri";
            args[args_idx++] = (*item)->idp.ipaidpKeysEndpoint;
        }

    }

    args[args_idx++] = "--client-id";
    args[args_idx++] = (*item)->idp.ipaidpClientID;

    if ((*item)->idp.ipaidpClientSecret) {
        args[args_idx++] = "--client-secret-stdin";
    }

    if ((*item)->idp.ipaidpScope) {
        args[args_idx++] = "--scope";
        args[args_idx++] = (*item)->idp.ipaidpScope;
    }

    if ((*item)->idp.ipaidpSub) {
        args[args_idx++] = "--user-identifier-attribute";
        args[args_idx++] = (*item)->idp.ipaidpSub;
    }

    if ((*item)->idp.ipaidpDebugLevelStr != NULL) {
        args[args_idx++] = "--debug-level";
        args[args_idx++] = (*item)->idp.ipaidpDebugLevelStr;
    }

    if ((*item)->idp.ipaidpDebugCurl) {
        args[args_idx++] = "--libcurl-debug";
    }

#if 0
    for (int i; args[i]; i++) {
        otpd_log_req((*item)->req, "oidc_child exec: %s", args[i]);
    }
#endif

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

        execv(OIDC_CHILD_PATH, args);
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
                                                     oauth2_on_child_writable,
                                                     child_ctx->write_to_child);
        if (child_ctx->write_ev == NULL) {
            ret = ENOMEM;
            otpd_log_err(ret, "Unable to initialize oauth2 writer event");
            goto done;
        }
        verto_set_private(child_ctx->write_ev, child_ctx, NULL);

        child_ctx->read_ev = verto_add_io(ctx.vctx, VERTO_EV_FLAG_PERSIST |
                                                    VERTO_EV_FLAG_IO_CLOSE_FD |
                                                    VERTO_EV_FLAG_IO_ERROR |
                                                    VERTO_EV_FLAG_IO_READ,
                                                    oauth2_on_child_readable,
                                                    child_ctx->read_from_child);
        if (child_ctx->read_ev == NULL) {
            ret = ENOMEM;
            otpd_log_err(ret, "Unable to initialize oauth2 writer event");
            goto done;
        }
        verto_set_private(child_ctx->read_ev, child_ctx, NULL);

        child_ctx->child_ev = verto_add_child(ctx.vctx, VERTO_EV_FLAG_NONE,
                                              oauth2_on_child_exit, child_pid);
        verto_set_private(child_ctx->child_ev, child_ctx, free_child_ctx);

    } else { /* error */
        ret = errno;
        otpd_log_err(ret, "Failed to fork oidc_child");
        goto done;
    }

    ret = 0;
done:
    if (ret == 0) {
        *item = NULL;
    }

    return ret;
}
