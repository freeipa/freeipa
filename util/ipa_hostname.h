/*
 * Copyright (C) 2020  FreeIPA Contributors see COPYING for license
 */

/* FQDN host name length including trailing NULL byte
 *
 * This may be longer than HOST_NAME_MAX. The hostname (effectively uname()'s
 * node name) is limited to 64 characters on Linux. ipa_gethostfqdn() returns
 * a FQDN from NSS which can be up to 255 octets including NULL byte.
 * Effectively the FQDN is 253 ASCII characters.
 */
#define IPA_HOST_FQDN_LEN 255

/* Get the host FQDN.
 *
 * Returns a null-terminated static char[].  The string length is
 * at most IPA_HOST_FQDN_LEN - 1.  The caller MUST NOT modify this
 * buffer.  If modification could occur, the caller MUST copy
 * the string.
 */
const char*
ipa_gethostfqdn(void);
