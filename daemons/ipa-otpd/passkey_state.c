/*
 * FreeIPA 2FA companion daemon
 *
 * Copyright (C) 2026  FreeIPA Contributors
 * see file 'COPYING' for use and warranty information
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "passkey_state.h"

#define PASSKEY_STATE_BYTES 32
#define PASSKEY_STATE_HEX_LENGTH (PASSKEY_STATE_BYTES * 2)
#define PASSKEY_STATE_VALUE_MAX 4096

static const unsigned char state_magic[] = {
    'I', 'P', 'A', 'P', 'K', 'S', 'T', 1
};

struct state_header {
    unsigned char magic[sizeof(state_magic)];
    uint32_t challenge_len;
    uint32_t principal_len;
};

static int write_full(int fd, const void *data, size_t len)
{
    const unsigned char *p = data;

    while (len > 0) {
        ssize_t written = write(fd, p, len);

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return errno;
        }
        if (written == 0) {
            return EIO;
        }
        p += written;
        len -= written;
    }

    return 0;
}

static int read_full(int fd, void *data, size_t len)
{
    unsigned char *p = data;

    while (len > 0) {
        ssize_t count = read(fd, p, len);

        if (count == 0) {
            return EINVAL;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return errno;
        }
        p += count;
        len -= count;
    }

    return 0;
}

static int open_state_dir(const char *state_dir)
{
    struct stat st;
    int fd;

    if (state_dir == NULL || state_dir[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    fd = open(state_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &st) != 0 || st.st_uid != geteuid() ||
        (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        close(fd);
        errno = EACCES;
        return -1;
    }

    return fd;
}

static int make_state_token(char token[PASSKEY_STATE_HEX_LENGTH + 1])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char random[PASSKEY_STATE_BYTES];
    size_t i;

    if (RAND_bytes(random, sizeof(random)) != 1) {
        return EIO;
    }

    for (i = 0; i < sizeof(random); i++) {
        token[i * 2] = hex[random[i] >> 4];
        token[i * 2 + 1] = hex[random[i] & 0x0f];
    }
    token[PASSKEY_STATE_HEX_LENGTH] = '\0';

    OPENSSL_cleanse(random, sizeof(random));
    return 0;
}

static int valid_state_token(const char *state)
{
    size_t i;

    if (state == NULL || strlen(state) != PASSKEY_STATE_HEX_LENGTH) {
        return 0;
    }

    for (i = 0; i < PASSKEY_STATE_HEX_LENGTH; i++) {
        if (!((state[i] >= '0' && state[i] <= '9') ||
              (state[i] >= 'a' && state[i] <= 'f'))) {
            return 0;
        }
    }

    return 1;
}

int passkey_state_issue(const char *state_dir,
                        const void *principal, size_t principal_len,
                        const char *challenge, char **state)
{
    struct state_header header;
    char token[PASSKEY_STATE_HEX_LENGTH + 1];
    size_t challenge_len;
    int dirfd = -1;
    int fd = -1;
    int ret;
    int attempt;

    if (principal == NULL || principal_len == 0 ||
        principal_len > PASSKEY_STATE_VALUE_MAX || challenge == NULL ||
        state == NULL) {
        return EINVAL;
    }

    challenge_len = strlen(challenge);
    if (challenge_len == 0 || challenge_len > PASSKEY_STATE_VALUE_MAX) {
        return EINVAL;
    }

    *state = NULL;
    dirfd = open_state_dir(state_dir);
    if (dirfd < 0) {
        return errno;
    }

    for (attempt = 0; attempt < 3; attempt++) {
        ret = make_state_token(token);
        if (ret != 0) {
            goto done;
        }

        fd = openat(dirfd, token,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    S_IRUSR | S_IWUSR);
        if (fd >= 0) {
            break;
        }
        if (errno != EEXIST) {
            ret = errno;
            goto done;
        }
    }
    if (fd < 0) {
        ret = EEXIST;
        goto done;
    }

    memcpy(header.magic, state_magic, sizeof(header.magic));
    header.challenge_len = (uint32_t)challenge_len;
    header.principal_len = (uint32_t)principal_len;

    ret = write_full(fd, &header, sizeof(header));
    if (ret == 0) {
        ret = write_full(fd, challenge, challenge_len);
    }
    if (ret == 0) {
        ret = write_full(fd, principal, principal_len);
    }
    if (ret != 0) {
        unlinkat(dirfd, token, 0);
        goto done;
    }

    *state = strdup(token);
    if (*state == NULL) {
        ret = ENOMEM;
        unlinkat(dirfd, token, 0);
        goto done;
    }

    ret = 0;

done:
    if (fd >= 0) {
        close(fd);
    }
    if (dirfd >= 0) {
        close(dirfd);
    }
    return ret;
}

int passkey_state_consume(const char *state_dir, const char *state,
                          const void *principal, size_t principal_len,
                          const char *challenge)
{
    struct state_header header;
    struct stat st;
    unsigned char *record = NULL;
    size_t challenge_len;
    size_t record_len;
    time_t now;
    int dirfd = -1;
    int fd = -1;
    int ret = EACCES;
    int remove_record = 0;
    unsigned char trailing;

    if (!valid_state_token(state) || principal == NULL || principal_len == 0 ||
        principal_len > PASSKEY_STATE_VALUE_MAX || challenge == NULL) {
        return EINVAL;
    }

    challenge_len = strlen(challenge);
    if (challenge_len == 0 || challenge_len > PASSKEY_STATE_VALUE_MAX) {
        return EINVAL;
    }

    dirfd = open_state_dir(state_dir);
    if (dirfd < 0) {
        return errno;
    }

    fd = openat(dirfd, state, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        ret = errno;
        goto done;
    }
    if (flock(fd, LOCK_EX) != 0) {
        ret = errno;
        goto done;
    }
    if (fstat(fd, &st) != 0) {
        ret = errno;
        goto done;
    }

    if (!S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_uid != geteuid() ||
        (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        remove_record = 1;
        goto done;
    }

    now = time(NULL);
    if (now == (time_t)-1 || st.st_mtime > now + PASSKEY_STATE_TTL ||
        (now >= st.st_mtime && now - st.st_mtime > PASSKEY_STATE_TTL)) {
        remove_record = 1;
        goto done;
    }

    ret = read_full(fd, &header, sizeof(header));
    if (ret != 0 || memcmp(header.magic, state_magic, sizeof(state_magic)) != 0 ||
        header.challenge_len == 0 ||
        header.challenge_len > PASSKEY_STATE_VALUE_MAX ||
        header.principal_len == 0 ||
        header.principal_len > PASSKEY_STATE_VALUE_MAX) {
        ret = EACCES;
        remove_record = 1;
        goto done;
    }

    record_len = (size_t)header.challenge_len + header.principal_len;
    record = malloc(record_len);
    if (record == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = read_full(fd, record, record_len);
    if (ret != 0) {
        ret = EACCES;
        remove_record = 1;
        goto done;
    }
    if (read(fd, &trailing, 1) != 0) {
        ret = EACCES;
        remove_record = 1;
        goto done;
    }

    if (header.challenge_len != challenge_len ||
        header.principal_len != principal_len ||
        CRYPTO_memcmp(record, challenge, challenge_len) != 0 ||
        CRYPTO_memcmp(record + header.challenge_len,
                      principal, principal_len) != 0) {
        ret = EACCES;
        goto done;
    }

    remove_record = 1;
    ret = 0;

done:
    if (remove_record && dirfd >= 0 && fd >= 0) {
        if (unlinkat(dirfd, state, 0) != 0 && ret == 0) {
            ret = errno;
        }
    }
    free(record);
    if (fd >= 0) {
        close(fd);
    }
    if (dirfd >= 0) {
        close(dirfd);
    }
    return ret;
}

void passkey_state_discard(const char *state_dir, const char *state)
{
    int dirfd;

    if (!valid_state_token(state)) {
        return;
    }

    dirfd = open_state_dir(state_dir);
    if (dirfd < 0) {
        return;
    }

    unlinkat(dirfd, state, 0);
    close(dirfd);
}
