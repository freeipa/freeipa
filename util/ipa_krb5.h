#ifndef __IPA_KRB5_H_
#define __IPA_KRB5_H_

#include <krb5/krb5.h>
#include <kdb.h>

void
ipa_krb5_free_ktypes(krb5_context context, krb5_enctype *val);

krb5_error_code ipa_krb5_principal2salt_norealm(krb5_context context,
                                                krb5_const_principal pr,
                                                krb5_data *ret);

krb5_error_code ipa_krb5_generate_key_data(krb5_context krbctx,
                                           krb5_principal principal,
                                           krb5_data pwd, int kvno,
                                           krb5_keyblock *kmkey,
                                           int num_encsalts,
                                           krb5_key_salt_tuple *encsalts,
                                           int *_num_keys,
                                           krb5_key_data **_keys);

void ipa_krb5_free_key_data(krb5_key_data *keys, int num_keys);

#endif /* __IPA_KRB5_H_ */
