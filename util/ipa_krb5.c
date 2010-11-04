#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "ipa_krb5.h"

void
ipa_krb5_free_ktypes(krb5_context context, krb5_enctype *val)
{
    free(val);
}

/*
 * Convert a krb5_principal into the default salt for that principal.
 */
krb5_error_code
ipa_krb5_principal2salt_norealm(krb5_context context, krb5_const_principal pr, krb5_data *ret)
{
    unsigned int size = 0, offset=0;
    krb5_int32 nelem;
    register int i;

    if (pr == NULL) {
        ret->length = 0;
        ret->data = NULL;
        return 0;
    }

    nelem = krb5_princ_size(context, pr);

    for (i = 0; i < (int) nelem; i++)
        size += krb5_princ_component(context, pr, i)->length;

    ret->length = size;
    if (!(ret->data = malloc (size)))
        return ENOMEM;

    for (i = 0; i < (int) nelem; i++) {
        memcpy(&ret->data[offset], krb5_princ_component(context, pr, i)->data,
               krb5_princ_component(context, pr, i)->length);
        offset += krb5_princ_component(context, pr, i)->length;
    }
    return 0;
}
