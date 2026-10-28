/** BEGIN COPYRIGHT BLOCK
 * This program is free software; you can redistribute it and/or modify
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
 *
 * Additional permission under GPLv3 section 7:
 *
 * In the following paragraph, "GPL" means the GNU General Public
 * License, version 3 or any later version, and "Non-GPL Code" means
 * code that is governed neither by the GPL nor a license
 * compatible with the GPL.
 *
 * You may link the code of this Program with Non-GPL Code and convey
 * linked combinations including the two, provided that such Non-GPL
 * Code only links to the code of this Program through those well
 * defined interfaces identified in the file named EXCEPTION found in
 * the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline
 * functions from the Approved Interfaces without causing the resulting
 * work to be covered by the GPL. Only the copyright holders of this
 * Program may make changes or additions to the list of Approved
 * Interfaces.
 *
 * Authors:
 * Nathaniel McCallum <npmccallum@redhat.com>
 *
 * Copyright (C) 2014 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include "berval.h"

#include <slapi-plugin.h>

#include <limits.h>

struct berval *
berval_new_longlong(long long value)
{
    struct berval *bv;

    bv = (struct berval*) slapi_ch_malloc(sizeof(struct berval));
    bv->bv_val = slapi_ch_smprintf("%lld", value);
    bv->bv_len = strlen(bv->bv_val);

    return bv;
}

void
berval_free(struct berval **bv)
{
    if (*bv == NULL)
        return;

    slapi_ch_free((void **) &(*bv)->bv_val);
    slapi_ch_free((void **) bv);
}

long long
berval_to_longlong(const struct berval *bv)
{
    char buf[bv->bv_len + 1];
    memcpy(buf, bv->bv_val, bv->bv_len);
    buf[sizeof(buf)-1] = '\0';

    return strtoll(buf, NULL, 10);
}

struct berval **
bervals_new_longlong(long long value)
{
    struct berval **bvs;

    bvs = (struct berval**) slapi_ch_calloc(2, sizeof(struct berval*));
    bvs[0] = berval_new_longlong(value);

    return bvs;
}

void
bervals_free(struct berval ***bvals)
{
    for (struct berval **itr = *bvals; *itr != NULL; itr++)
        berval_free(itr);

    slapi_ch_free((void**) bvals);
}
