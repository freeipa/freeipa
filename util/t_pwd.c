/*
 * Copyright (C) 2020  FreeIPA Contributors see COPYING for license
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ipa_pwd.h"

#define RES(algo, ...) { algo, (uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__}) }

static const struct {
    char *algo;
    uint8_t *res;
    size_t res_size;
} hash_tests[] = {
        /* {SSHA} */
        RES("{SSHA}", 30, 226, 112, 72, 241, 233, 125, 4, 27, 158, 228, 238, 180, 21, 179, 121, 48, 59, 100, 3, 0, 1, 2,
            3, 4, 5, 6, 7),
        /* {SHA256} */
        RES("{SHA256}", 162, 175, 215, 45, 209, 245, 101, 173, 242, 116, 208, 128, 28, 159, 206, 241, 255, 65, 245, 82,
            218, 244, 27, 99, 57, 215, 96, 93, 7, 176, 195, 175, 0, 1, 2, 3, 4, 5, 6, 7),
        /* {SHA384} */
        RES("{SHA384}", 214, 104, 216, 118, 234, 225, 221, 104, 228, 82, 156, 86, 230, 47, 185, 170, 119, 35, 153, 160,
            142, 153, 141, 101, 74, 17, 150, 219, 9, 243, 170, 242, 225, 128, 173, 102, 198, 231, 121, 124, 86, 210, 19,
            11, 237, 150, 157, 176, 0, 1, 2, 3, 4, 5, 6, 7),
        /* {SHA512} */
        RES("{SHA512}", 157, 177, 112, 19, 84, 152, 211, 233, 139, 237, 240, 235, 207, 79, 232, 252, 123, 150, 114, 169,
            206, 95, 196, 141, 31, 58, 195, 220, 212, 168, 98, 67, 1, 255, 211, 129, 67, 181, 114, 214, 243, 236, 41,
            247, 118, 167, 139, 70, 192, 172, 128, 94, 9, 225, 208, 98, 23, 148, 182, 202, 28, 130, 22, 30, 0, 1, 2, 3,
            4, 5, 6, 7)
};

int main(int argc, const char *argv[]) {
    (void) argc;
    (void) argv;

    char pw[] = "test";
    uint8_t salt[8] = {0, 1, 2, 3, 4, 5, 6, 7};

    unsigned char *hash;
    unsigned int hash_length;

    for (long unsigned int i = 0; i < sizeof(hash_tests) / sizeof(*hash_tests); i++) {
        if (ipapwd_hash_password(pw, hash_tests[i].algo, salt, &hash, &hash_length) == 0) {
            assert(memcmp(hash, hash_tests[i].res, hash_tests[i].res_size) == 0);
        } else {
            assert(false);
        }

        fprintf(stderr, "Algo: %s OK, length: %i\n", hash_tests[i].algo, hash_length);
        free(hash);
    }

    return 0;
}
