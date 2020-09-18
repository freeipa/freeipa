
/*
 * Copyright (C) 2020  FreeIPA Contributors see COPYING for license
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ipa_hostname.h"

static int
_get_fqdn(char *fqdn)
{
    char hostname[IPA_HOST_FQDN_LEN];
    char *canonname = NULL;
    struct addrinfo hints;
    struct addrinfo *ai = NULL;
    int r;

    r = gethostname(hostname, IPA_HOST_FQDN_LEN - 1);
    if (r != 0) {
        goto error;
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    /* use IPv4 or IPv6 */
    hints.ai_family = AF_UNSPEC;
    /* optimize, RAW and STREAM return same kind of information */
    hints.ai_socktype = SOCK_DGRAM;
    /* any protocol */
    hints.ai_protocol = 0;
    /* get canonical name
     * only use IPv4/6 when at least one interface for proto is configured */
    hints.ai_flags = AI_CANONNAME | AI_ADDRCONFIG;

    r = getaddrinfo(hostname, NULL, &hints, &ai);
    if (r != 0) {
        /* getaddrinfo() for gethostname() should never fail. The
         * nss-myhostname provider should always add a positive match. */
        errno = ENOENT;
        goto error;
    }

    /* only the first addrinfo struct holds a canonical name value */
    canonname = ai->ai_canonname;

    /* check that canon name is filled and not too long */
    if (!canonname) {
        errno = ENOENT;
        goto error;
    }
    if (strlen(canonname) > (IPA_HOST_FQDN_LEN - 1)) {
        errno = ENAMETOOLONG;
        goto error;
    }
#if 0
    /* refuse non-qualified short names and localhost */
    if ((strchr(canonname, '.') == NULL) ||
            (strcasecmp(canonname, "localhost.localdomain") == 0)) {
        errno = EINVAL;
        goto error;
    }
#endif

    strncpy(fqdn, canonname, IPA_HOST_FQDN_LEN);
    /* Make double sure it is terminated */
    fqdn[IPA_HOST_FQDN_LEN - 1] = '\0';
    freeaddrinfo(ai);
    return 0;

  error:
    if (ai != NULL) {
        freeaddrinfo(ai);
    }
    return -1;
}


const char* ipa_gethostfqdn()
{
    static char cached_fqdn[IPA_HOST_FQDN_LEN] = {0};

    if (*cached_fqdn == '\0') {
        int res = _get_fqdn(cached_fqdn);
        if (res != 0) {
            return NULL;
        }
    }
    return (const char*)cached_fqdn;
}
