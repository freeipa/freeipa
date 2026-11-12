/*
 * Copyright (C) 2026 FreeIPA Contributors see COPYING for license
 */

#include <assert.h>
#include <limits.h>
#include <string.h>

#include "INTEGER.h"

static const struct {
    long value;
    unsigned char bytes[2];
    size_t size;
} cases[] = {
    { 0, { 0x00 }, 1 },
    { 1, { 0x01 }, 1 },
    { -1, { 0xff }, 1 },
    { 127, { 0x7f }, 1 },
    { 128, { 0x00, 0x80 }, 2 },
    { 255, { 0x00, 0xff }, 2 },
    { 256, { 0x01, 0x00 }, 2 },
    { -128, { 0x80 }, 1 },
    { -129, { 0xff, 0x7f }, 2 },
    { -256, { 0xff, 0x00 }, 2 },
};

int main(void)
{
    INTEGER_t integer = { 0 };
    const long limits[] = { LONG_MIN, LONG_MAX };
    long decoded;
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        assert(asn_long2INTEGER(&integer, cases[i].value) == 0);
        assert(integer.size == cases[i].size);
        assert(memcmp(integer.buf, cases[i].bytes, cases[i].size) == 0);
        assert(asn_INTEGER2long(&integer, &decoded) == 0);
        assert(decoded == cases[i].value);
    }

    for (i = 0; i < sizeof(limits) / sizeof(limits[0]); i++) {
        assert(asn_long2INTEGER(&integer, limits[i]) == 0);
        assert(integer.size == sizeof(long));
        assert(asn_INTEGER2long(&integer, &decoded) == 0);
        assert(decoded == limits[i]);
    }

    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &integer);
    return 0;
}
