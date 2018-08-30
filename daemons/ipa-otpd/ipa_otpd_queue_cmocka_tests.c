/*
 * FreeIPA 2FA companion daemon - internal queue tests
 *
 * Author: Robbie Harwood <rharwood@redhat.com>
 *
 * Copyright (C) 2018  Robbie Harwood, Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <cmocka.h>

#include "internal.h"

/* Bypass otpd queue allocation/freeing to avoid calling into LDAP and
 * krad.  No effort is made to make the types match. */
static struct otpd_queue_item *new_elt(int id)
{
    krb5_error_code ret;
    struct otpd_queue_item *e = NULL;

    ret = otpd_queue_item_new(NULL, &e);
    assert_int_equal(ret, 0);
    assert_ptr_not_equal(e, NULL);

    e->msgid = id;
    return e;
}
static void free_elt(struct otpd_queue_item **e)
{
    assert_ptr_not_equal(e, NULL);
    free(*e);
    *e = NULL;
}
static void free_elts(struct otpd_queue *q)
{
    assert_ptr_not_equal(q, NULL);
    for (struct otpd_queue_item *e = otpd_queue_pop(q); e != NULL;
         e = otpd_queue_pop(q))
        free_elt(&e);
}
#define otpd_queue_item_new new_elt
#define otpd_queue_item_free free_elt
#define otpd_queue_free_items free_elts

static void assert_elt_equal(struct otpd_queue_item *e1,
                             struct otpd_queue_item *e2)
{
    if (e1 == NULL && e2 == NULL)
        return;
    assert_ptr_not_equal(e1, NULL);
    assert_ptr_not_equal(e2, NULL);
    assert_int_equal(e1->msgid, e2->msgid);
}

static void test_single_insert()
{
    struct otpd_queue q = { NULL };
    struct otpd_queue_item *ein, *eout;

    ein = new_elt(0);
    otpd_queue_push(&q, ein);

    eout = otpd_queue_peek(&q);
    assert_elt_equal(ein, eout);

    eout = otpd_queue_pop(&q);
    assert_elt_equal(ein, eout);
    free_elt(&eout);

    eout = otpd_queue_pop(&q);
    assert_ptr_equal(eout, NULL);

    free_elts(&q);
}

static void test_jump_insert()
{
    struct otpd_queue q = { NULL };
    struct otpd_queue_item *echeck;

    for (int i = 0; i < 3; i++) {
        struct otpd_queue_item *e = new_elt(i);
        otpd_queue_push_head(&q, e);

        echeck = otpd_queue_peek(&q);
        assert_elt_equal(e, echeck);
    }

    free_elts(&q);
}

static void test_garbage_insert()
{
    struct otpd_queue q = { NULL };
    struct otpd_queue_item *e, *g;

    g = new_elt(0);
    g->next = g;
    otpd_queue_push(&q, g);

    e = otpd_queue_peek(&q);
    assert_ptr_equal(e->next, NULL);

    free_elts(&q);
}

static void test_removal()
{
    struct otpd_queue q = { NULL };

    for (int i = 0; i < 3; i++) {
        struct otpd_queue_item *e = new_elt(i);
        otpd_queue_push(&q, e);
    }
    for (int i = 0; i < 3; i++) {
        struct otpd_queue_item *e = otpd_queue_pop(&q);
        assert_ptr_not_equal(e, NULL);
        assert_ptr_equal(e->next, NULL);
        assert_int_equal(e->msgid, i);
        free_elt(&e);
    }
}

static void pick_id(struct otpd_queue *q, int msgid)
{
    struct otpd_queue_item *e;

    e = otpd_queue_pop_msgid(q, msgid);
    assert_int_equal(e->msgid, msgid);
    assert_ptr_equal(e->next, NULL);
    free_elt(&e);
    e = otpd_queue_pop_msgid(q, msgid);
    assert_ptr_equal(e, NULL);
}
static void test_pick_removal()
{
    struct otpd_queue q = { NULL };

    for (int i = 0; i < 4; i++) {
        struct otpd_queue_item *e = new_elt(i);
        otpd_queue_push(&q, e);
    }

    pick_id(&q, 0); /* first */
    pick_id(&q, 2); /* middle */
    pick_id(&q, 3); /* last */
    pick_id(&q, 1); /* singleton */

    free_elts(&q);
}

static void test_iter()
{
    krb5_error_code ret;
    struct otpd_queue q = { NULL };
    const struct otpd_queue *queues[3];
    struct otpd_queue_iter *iter = NULL;
    const krad_packet *p = NULL;

    for (ptrdiff_t i = 1; i <= 3; i++) {
        struct otpd_queue_item *e = new_elt(i);
        e->req = (void *)i;
        otpd_queue_push(&q, e);
    }

    queues[0] = &q;
    queues[1] = &q;
    queues[2] = NULL;
    ret = otpd_queue_iter_new(queues, &iter);
    assert_int_equal(ret, 0);
    assert_ptr_not_equal(iter, NULL);

    for (ptrdiff_t i = 0; i < 6; i++) {
        p = otpd_queue_iter_func(iter, FALSE);
        assert_ptr_equal(p, (void *) (i % 3 + 1));
    }
    p = otpd_queue_iter_func(iter, FALSE);
    assert_ptr_equal(p, NULL);

    free_elts(&q);
}

int main(int argc, char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_single_insert),
        cmocka_unit_test(test_jump_insert),
        cmocka_unit_test(test_garbage_insert),
        cmocka_unit_test(test_removal),
        cmocka_unit_test(test_pick_removal),
        cmocka_unit_test(test_iter),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
