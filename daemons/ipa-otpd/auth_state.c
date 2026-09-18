/*
 * FreeIPA 2FA companion daemon
 *
 * Copyright (C) 2026  FreeIPA Contributors
 * see file 'COPYING' for use and warranty information
 */

#include <dirent.h>
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

#include "auth_state.h"

#define AUTH_STATE_BYTES 32
#define AUTH_STATE_HEX_LENGTH (AUTH_STATE_BYTES * 2)
#define AUTH_STATE_METHOD_MAX 64
#define AUTH_STATE_PRINCIPAL_MAX 1024
#define AUTH_STATE_PAYLOAD_MAX 16384
static const unsigned char state_magic[] = {
    'I', 'P', 'A', 'A', 'U', 'T', 'H', 2
};

struct state_header {
    unsigned char magic[sizeof(state_magic)];
    uint32_t method_len;
    uint32_t principal_len;
    uint32_t payload_len;
    uint32_t ttl;
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

static int secure_directory_fd(int fd)
{
    struct stat st;

    if (fstat(fd, &st) != 0) {
        return errno;
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        return EACCES;
    }
    return 0;
}

static int open_state_dir(const char *state_dir)
{
    int fd;
    int ret;

    if (state_dir == NULL || state_dir[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    fd = open(state_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    ret = secure_directory_fd(fd);
    if (ret != 0) {
        close(fd);
        errno = ret;
        return -1;
    }
    return fd;
}

static int open_state_shard(int dirfd, const char *state, int create)
{
    char shard[3] = { state[0], state[1], '\0' };
    int fd;
    int ret;

    if (create && mkdirat(dirfd, shard, S_IRWXU) != 0 && errno != EEXIST) {
        return -1;
    }
    fd = openat(dirfd, shard,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    ret = secure_directory_fd(fd);
    if (ret != 0) {
        close(fd);
        errno = ret;
        return -1;
    }
    return fd;
}

static int make_state_token(char token[AUTH_STATE_HEX_LENGTH + 1])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char random[AUTH_STATE_BYTES];
    size_t i;

    if (RAND_bytes(random, sizeof(random)) != 1) {
        return EIO;
    }
    for (i = 0; i < sizeof(random); i++) {
        token[i * 2] = hex[random[i] >> 4];
        token[i * 2 + 1] = hex[random[i] & 0x0f];
    }
    token[AUTH_STATE_HEX_LENGTH] = '\0';
    OPENSSL_cleanse(random, sizeof(random));
    return 0;
}

static int valid_state_token(const char *state)
{
    size_t i;

    if (state == NULL || strlen(state) != AUTH_STATE_HEX_LENGTH) {
        return 0;
    }
    for (i = 0; i < AUTH_STATE_HEX_LENGTH; i++) {
        if (!((state[i] >= '0' && state[i] <= '9') ||
              (state[i] >= 'a' && state[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int valid_header(const struct state_header *header)
{
    return memcmp(header->magic, state_magic, sizeof(state_magic)) == 0 &&
           header->method_len > 0 &&
           header->method_len <= AUTH_STATE_METHOD_MAX &&
           header->principal_len > 0 &&
           header->principal_len <= AUTH_STATE_PRINCIPAL_MAX &&
           header->payload_len > 0 &&
           header->payload_len <= AUTH_STATE_PAYLOAD_MAX &&
           header->ttl > 0;
}

static int state_expired(time_t mtime, uint32_t ttl, time_t now)
{
    if (mtime > now) {
        return (uintmax_t)(mtime - now) > ttl;
    }
    return (uintmax_t)(now - mtime) > ttl;
}

static int remove_state(int shardfd, const char *state)
{
    if (unlinkat(shardfd, state, 0) != 0 && errno != ENOENT) {
        return errno;
    }
    return 0;
}

static int prune_shard(int shardfd, time_t now, size_t *active)
{
    struct state_header header;
    struct dirent *entry;
    struct stat st;
    DIR *stream = NULL;
    int scanfd = -1;
    int fd = -1;
    int ret = 0;

    *active = 0;
    scanfd = dup(shardfd);
    if (scanfd < 0) {
        return errno;
    }
    stream = fdopendir(scanfd);
    if (stream == NULL) {
        ret = errno;
        close(scanfd);
        return ret;
    }

    errno = 0;
    while ((entry = readdir(stream)) != NULL) {
        if (!valid_state_token(entry->d_name)) {
            continue;
        }
        fd = openat(shardfd, entry->d_name,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) {
            if (errno == ENOENT) {
                errno = 0;
                continue;
            }
            ret = errno;
            break;
        }
        if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                (*active)++;
                close(fd);
                fd = -1;
                errno = 0;
                continue;
            }
            ret = errno;
            break;
        }
        if (fstat(fd, &st) != 0) {
            ret = errno;
            break;
        }
        if (!S_ISREG(st.st_mode) || st.st_nlink != 1 ||
            st.st_uid != geteuid() ||
            (st.st_mode & (S_IRWXG | S_IRWXO)) != 0 ||
            read_full(fd, &header, sizeof(header)) != 0 ||
            !valid_header(&header) || state_expired(st.st_mtime,
                                                    header.ttl, now)) {
            ret = remove_state(shardfd, entry->d_name);
            if (ret != 0) {
                break;
            }
        } else {
            (*active)++;
        }
        close(fd);
        fd = -1;
        errno = 0;
    }
    if (ret == 0 && errno != 0) {
        ret = errno;
    }
    if (fd >= 0) {
        close(fd);
    }
    closedir(stream);
    return ret;
}

int auth_state_issue(const char *state_dir, const char *method,
                     const void *principal, size_t principal_len,
                     const void *payload, size_t payload_len,
                     unsigned int ttl, char **state)
{
    struct state_header header = { 0 };
    char token[AUTH_STATE_HEX_LENGTH + 1];
    size_t active;
    size_t method_len;
    time_t now;
    int dirfd = -1;
    int shardfd = -1;
    int fd = -1;
    int ret = ENOSPC;
    int attempt;

    if (state == NULL) {
        return EINVAL;
    }
    *state = NULL;
    if (method == NULL || principal == NULL || principal_len == 0 ||
        principal_len > AUTH_STATE_PRINCIPAL_MAX || payload == NULL ||
        payload_len == 0 || payload_len > AUTH_STATE_PAYLOAD_MAX || ttl == 0) {
        return EINVAL;
    }
    method_len = strlen(method);
    if (method_len == 0 || method_len > AUTH_STATE_METHOD_MAX) {
        return EINVAL;
    }
    now = time(NULL);
    if (now == (time_t)-1) {
        return EIO;
    }
    dirfd = open_state_dir(state_dir);
    if (dirfd < 0) {
        return errno;
    }

    for (attempt = 0; attempt < 64; attempt++) {
        ret = make_state_token(token);
        if (ret != 0) {
            goto done;
        }
        shardfd = open_state_shard(dirfd, token, 1);
        if (shardfd < 0) {
            ret = errno;
            goto done;
        }
        if (flock(shardfd, LOCK_EX) != 0) {
            ret = errno;
            goto done;
        }
        ret = prune_shard(shardfd, now, &active);
        if (ret != 0) {
            goto done;
        }
        if (active >= AUTH_STATE_SHARD_MAX) {
            close(shardfd);
            shardfd = -1;
            ret = ENOSPC;
            continue;
        }
        fd = openat(shardfd, token,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    S_IRUSR | S_IWUSR);
        if (fd >= 0) {
            break;
        }
        ret = errno;
        close(shardfd);
        shardfd = -1;
        if (ret != EEXIST) {
            goto done;
        }
    }
    if (fd < 0) {
        goto done;
    }

    memcpy(header.magic, state_magic, sizeof(header.magic));
    header.method_len = (uint32_t)method_len;
    header.principal_len = (uint32_t)principal_len;
    header.payload_len = (uint32_t)payload_len;
    header.ttl = ttl;

    ret = write_full(fd, &header, sizeof(header));
    if (ret == 0) {
        ret = write_full(fd, method, method_len);
    }
    if (ret == 0) {
        ret = write_full(fd, principal, principal_len);
    }
    if (ret == 0) {
        ret = write_full(fd, payload, payload_len);
    }
    if (ret != 0) {
        remove_state(shardfd, token);
        goto done;
    }
    *state = strdup(token);
    if (*state == NULL) {
        ret = ENOMEM;
        remove_state(shardfd, token);
        goto done;
    }
    ret = 0;

done:
    if (fd >= 0) {
        close(fd);
    }
    if (shardfd >= 0) {
        close(shardfd);
    }
    if (dirfd >= 0) {
        close(dirfd);
    }
    return ret;
}

int auth_state_consume(const char *state_dir, const char *state,
                       const char *method,
                       const void *principal, size_t principal_len,
                       void **payload, size_t *payload_len)
{
    struct state_header header;
    struct stat st;
    unsigned char *record = NULL;
    unsigned char trailing;
    size_t method_len;
    size_t record_len = 0;
    time_t now;
    int dirfd = -1;
    int shardfd = -1;
    int fd = -1;
    int ret = EACCES;
    int remove_record = 0;
    ssize_t count;

    if (payload == NULL || payload_len == NULL) {
        return EINVAL;
    }
    *payload = NULL;
    *payload_len = 0;
    if (!valid_state_token(state) || method == NULL || principal == NULL ||
        principal_len == 0 || principal_len > AUTH_STATE_PRINCIPAL_MAX) {
        return EINVAL;
    }
    method_len = strlen(method);
    if (method_len == 0 || method_len > AUTH_STATE_METHOD_MAX) {
        return EINVAL;
    }
    dirfd = open_state_dir(state_dir);
    if (dirfd < 0) {
        return errno;
    }
    shardfd = open_state_shard(dirfd, state, 0);
    if (shardfd < 0) {
        ret = errno;
        goto done;
    }
    fd = openat(shardfd, state, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
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
    ret = read_full(fd, &header, sizeof(header));
    if (ret != 0 || !valid_header(&header)) {
        ret = EACCES;
        remove_record = 1;
        goto done;
    }
    now = time(NULL);
    if (now == (time_t)-1 || state_expired(st.st_mtime, header.ttl, now)) {
        ret = EACCES;
        remove_record = 1;
        goto done;
    }
    record_len = (size_t)header.method_len + header.principal_len +
                 header.payload_len;
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
    do {
        count = read(fd, &trailing, 1);
    } while (count < 0 && errno == EINTR);
    if (count != 0) {
        ret = EACCES;
        remove_record = 1;
        goto done;
    }
    if (header.method_len != method_len ||
        header.principal_len != principal_len ||
        CRYPTO_memcmp(record, method, method_len) != 0 ||
        CRYPTO_memcmp(record + header.method_len,
                      principal, principal_len) != 0) {
        ret = EACCES;
        goto done;
    }
    *payload = malloc((size_t)header.payload_len + 1);
    if (*payload == NULL) {
        ret = ENOMEM;
        goto done;
    }
    memcpy(*payload, record + header.method_len + header.principal_len,
           header.payload_len);
    ((unsigned char *)*payload)[header.payload_len] = '\0';
    *payload_len = header.payload_len;
    remove_record = 1;
    ret = 0;

done:
    if (remove_record && shardfd >= 0 && fd >= 0) {
        int unlink_ret = remove_state(shardfd, state);
        if (unlink_ret != 0 && ret == 0) {
            ret = unlink_ret;
        }
    }
    if (record != NULL) {
        OPENSSL_cleanse(record, record_len);
        free(record);
    }
    if (ret != 0 && *payload != NULL) {
        auth_state_free(*payload, *payload_len);
        *payload = NULL;
        *payload_len = 0;
    }
    if (fd >= 0) {
        close(fd);
    }
    if (shardfd >= 0) {
        close(shardfd);
    }
    if (dirfd >= 0) {
        close(dirfd);
    }
    return ret;
}

void auth_state_discard(const char *state_dir, const char *state)
{
    int dirfd;
    int shardfd;

    if (!valid_state_token(state)) {
        return;
    }
    dirfd = open_state_dir(state_dir);
    if (dirfd < 0) {
        return;
    }
    shardfd = open_state_shard(dirfd, state, 0);
    if (shardfd >= 0) {
        remove_state(shardfd, state);
        close(shardfd);
    }
    close(dirfd);
}

void auth_state_free(void *payload, size_t payload_len)
{
    if (payload != NULL) {
        OPENSSL_cleanse(payload, payload_len);
        free(payload);
    }
}
