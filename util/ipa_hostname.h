/*
 * Copyright (C) 2020  FreeIPA Contributors see COPYING for license
 */

#include <limits.h>
#include <unistd.h>

/*
 * host name length including NULL byte
 *
 * NOTE: length hardcoded in kernel
 */
#define IPA_HOST_NAME_LEN (HOST_NAME_MAX + 1)

int
ipa_gethostname(char *name);

int
ipa_gethostfqdn(char *name);
