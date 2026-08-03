/*
 * Copyright (C) 2026  FreeIPA Contributors
 * see file 'COPYING' for use and warranty information
 */

#ifndef IPA_OTPD_PASSKEY_STATE_H_
#define IPA_OTPD_PASSKEY_STATE_H_

#include <stddef.h>

#ifndef PASSKEY_STATE_DIR
#define PASSKEY_STATE_DIR "/run/ipa/otpd-passkey"
#endif

#define PASSKEY_STATE_TTL 300

int passkey_state_issue(const char *state_dir,
                        const void *principal, size_t principal_len,
                        const char *challenge, char **state);
int passkey_state_consume(const char *state_dir, const char *state,
                          const void *principal, size_t principal_len,
                          const char *challenge);
void passkey_state_discard(const char *state_dir, const char *state);

#endif /* IPA_OTPD_PASSKEY_STATE_H_ */
