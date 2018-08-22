/*
 * FreeIPA 2FA companion daemon
 *
 * Authors: Nathaniel McCallum <npmccallum@redhat.com>
 *
 * Copyright (C) 2013  Nathaniel McCallum, Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software you can redistribute it and/or modify
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
 */

/*
 * This file contains an implementation of a queue of request/response items.
 */

#include "internal.h"

struct otpd_queue_iter {
    struct otpd_queue_item *next;
    unsigned int qindx;
    const struct otpd_queue * const *queues;
};

krb5_error_code otpd_queue_item_new(krad_packet *req,
                                    struct otpd_queue_item **item)
{
    *item = calloc(1, sizeof(struct otpd_queue_item));
    if (*item == NULL)
        return ENOMEM;

    (*item)->req = req;
    (*item)->msgid = -1;
    return 0;
}

void otpd_queue_item_free(struct otpd_queue_item *item)
{
    if (item == NULL)
        return;

    ldap_memfree(item->user.dn);
    free(item->user.uid);
    free(item->user.ipatokenRadiusUserName);
    free(item->user.ipatokenRadiusConfigLink);
    free(item->user.other);
    free(item->radius.ipatokenRadiusServer);
    free(item->radius.ipatokenRadiusSecret);
    free(item->radius.ipatokenUserMapAttribute);
    free(item->error);
    krad_packet_free(item->req);
    krad_packet_free(item->rsp);
    free(item);
}

krb5_error_code otpd_queue_iter_new(const struct otpd_queue * const *queues,
                                    struct otpd_queue_iter **iter)
{
    *iter = calloc(1, sizeof(struct otpd_queue_iter));
    if (*iter == NULL)
        return ENOMEM;

    (*iter)->queues = queues;
    return 0;
}

/* This iterator function is used by krad to loop over all outstanding requests
 * to check for duplicates. Hence, we have to iterate over all the queues to
 * return all the outstanding requests as a flat list. */
const krad_packet *otpd_queue_iter_func(void *data, krb5_boolean cancel)
{
    struct otpd_queue_iter *iter = data;
    const struct otpd_queue *q;

    if (cancel) {
        free(iter);
        return NULL;
    }

    if (iter->next != NULL) {
        struct otpd_queue_item *tmp;
        tmp = iter->next;
        iter->next = tmp->next;
        return tmp->req;
    }

    q = iter->queues[iter->qindx++];
    if (q == NULL)
        return otpd_queue_iter_func(data, TRUE);

    iter->next = q->head;
    return otpd_queue_iter_func(data, FALSE);
}

void otpd_queue_push(struct otpd_queue *q, struct otpd_queue_item *item)
{
    if (item == NULL)
        return;

    if (q->tail == NULL)
        q->head = q->tail = item;
    else
        q->tail = q->tail->next = item;

    item->next = NULL;
}

void otpd_queue_push_head(struct otpd_queue *q, struct otpd_queue_item *item)
{
    if (item == NULL)
        return;

    item->next = NULL;

    if (q->head == NULL)
        q->tail = q->head = item;
    else {
        item->next = q->head;
        q->head = item;
    }
}

struct otpd_queue_item *otpd_queue_peek(struct otpd_queue *q)
{
    return q->head;
}

struct otpd_queue_item *otpd_queue_pop(struct otpd_queue *q)
{
    struct otpd_queue_item *item;

    if (q == NULL)
        return NULL;

    item = q->head;
    if (item != NULL)
        q->head = item->next;

    if (q->head == NULL)
        q->tail = NULL;

    if (item != NULL)
        item->next = NULL;
    return item;
}

/* Remove and return an item from the queue with the given msgid. */
struct otpd_queue_item *otpd_queue_pop_msgid(struct otpd_queue *q, int msgid)
{
    struct otpd_queue_item *item, **prev;

    for (item = q->head, prev = &q->head;
         item != NULL;
         prev = &item->next, item = item->next) {
        if (item->msgid == msgid) {
            *prev = item->next;
            if (q->head == NULL)
                q->tail = NULL;
            item->next = NULL;
            return item;
        }
    }

    return NULL;
}

void otpd_queue_free_items(struct otpd_queue *q)
{
    struct otpd_queue_item *item, *next;

    next = q->head;
    while (next != NULL) {
        item = next;
        next = next->next;
        otpd_queue_item_free(item);
    }

    q->head = NULL;
    q->tail = NULL;
}
