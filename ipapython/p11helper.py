#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

import _ipap11helper
import random

def generate_master_key(p11, keylabel=u"dnssec-master", key_length=16,
                        disable_old_keys=True):
    assert isinstance(p11, _ipap11helper.P11_Helper)

    key_id = None
    while True:
        # check if key with this ID exist in LDAP or softHSM
        # id is 16 Bytes long
        key_id = "".join(chr(random.randint(0, 255)) for _ in xrange(0, 16))
        keys = p11.find_keys(_ipap11helper.KEY_CLASS_SECRET_KEY,
                             label=keylabel,
                             id=key_id)
        if not keys:
            break  # we found unique id

    p11.generate_master_key(keylabel,
                            key_id,
                            key_length=key_length,
                            cka_wrap=True,
                            cka_unwrap=True)

    if disable_old_keys:
        # set CKA_WRAP=False for old master keys
        master_keys = p11.find_keys(_ipap11helper.KEY_CLASS_SECRET_KEY,
                                    label=keylabel,
                                    cka_wrap=True)

        for handle in master_keys:
            # don't disable wrapping for new key
            # compare IDs not handle
            if key_id != p11.get_attribute(handle, _ipap11helper.CKA_ID):
                p11.set_attribute(handle, _ipap11helper.CKA_WRAP, False)
