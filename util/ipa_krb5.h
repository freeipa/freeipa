#ifndef __IPA_KRB5_H_
#define __IPA_KRB5_H_

#include <krb5.h>

void
ipa_krb5_free_ktypes(krb5_context context, krb5_enctype *val);

krb5_error_code
ipa_krb5_principal2salt_norealm(krb5_context context, krb5_const_principal pr, krb5_data *ret);

#endif /* __IPA_KRB5_H_ */
