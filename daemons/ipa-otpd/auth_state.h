/*
 * Copyright (C) 2026  FreeIPA Contributors
 * see file 'COPYING' for use and warranty information
 */

#ifndef IPA_OTPD_AUTH_STATE_H_
#define IPA_OTPD_AUTH_STATE_H_

#include <stddef.h>
#include <stdint.h>

#ifndef AUTH_STATE_DIR
#define AUTH_STATE_DIR "/run/ipa/otpd-state"
#endif

#define AUTH_STATE_TTL_MAX UINT32_MAX
#define AUTH_STATE_SHARD_MAX 16
#define AUTH_STATE_TOTAL_MAX (256 * AUTH_STATE_SHARD_MAX)

int auth_state_issue(const char *state_dir, const char *method,
                     const void *principal, size_t principal_len,
                     const void *payload, size_t payload_len,
                     unsigned int ttl,
                     char **state);
int auth_state_consume(const char *state_dir, const char *state,
                       const char *method,
                       const void *principal, size_t principal_len,
                       void **payload, size_t *payload_len);
void auth_state_discard(const char *state_dir, const char *state);
void auth_state_free(void *payload, size_t payload_len);

#endif /* IPA_OTPD_AUTH_STATE_H_ */
