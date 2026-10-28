#include <stdbool.h>
#include <sys/types.h>
#include "ipa_asn1.h"
#include "GetKeytabControl.h"

static bool encode_GetKeytabControl(GetKeytabControl_t *gkctrl,
                                    void **buf, size_t *len)
{
    asn_enc_rval_t rval;
    char *buffer = NULL;
    size_t buflen;
    bool ret = false;

    /* dry run to compute the size */
    rval = der_encode(&asn_DEF_GetKeytabControl, gkctrl, NULL, NULL);
    if (rval.encoded == -1) goto done;

    buflen = rval.encoded;
    buffer = malloc(buflen);
    if (!buffer) goto done;

    /* now for real */
    rval = der_encode_to_buffer(&asn_DEF_GetKeytabControl,
                                gkctrl, buffer, buflen);
    if (rval.encoded == -1) goto done;

    *buf = buffer;
    *len = buflen;
    ret = true;

done:
    if (!ret) {
        free(buffer);
    }
    return ret;
}

bool ipaasn1_enc_getkt(bool newkt, const char *princ, const char *pwd,
                       long *etypes, int numtypes, void **buf, size_t *len)
{
    GetKeytabControl_t gkctrl = { 0 };
    bool ret = false;

    if (newkt) {
        gkctrl.present = GetKeytabControl_PR_newkeys;
        if (OCTET_STRING_fromString(&gkctrl.choice.newkeys.serviceIdentity,
                                    princ) != 0) goto done;

        for (int i = 0; i < numtypes; i++) {
            long *tmp;
            tmp = malloc(sizeof(long));
            if (!tmp) goto done;
            *tmp = etypes[i];
            ASN_SEQUENCE_ADD(&gkctrl.choice.newkeys.enctypes.list, tmp);
        }

        if (pwd) {
            gkctrl.choice.newkeys.password =
                OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, pwd, -1);
            if (!gkctrl.choice.newkeys.password) goto done;
        }
    } else {
        gkctrl.present = GetKeytabControl_PR_curkeys;
        if (OCTET_STRING_fromString(&gkctrl.choice.curkeys.serviceIdentity,
                                    princ) != 0) goto done;
    }

    ret = encode_GetKeytabControl(&gkctrl, buf, len);

done:
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_GetKeytabControl, &gkctrl);
    return ret;
}

bool ipaasn1_enc_getktreply(int kvno, struct keys_container *keys,
                            void **buf, size_t *len)
{
    GetKeytabControl_t gkctrl = { 0 };
    bool ret = false;
    KrbKey_t *KK;

    gkctrl.present = GetKeytabControl_PR_reply;
    gkctrl.choice.reply.newkvno = kvno;

    for (int i = 0; i < keys->nkeys; i++) {
        KK = calloc(1, sizeof(KrbKey_t));
        if (!KK) goto done;
        KK->key.type = keys->ksdata[i].key.enctype;
        KK->key.value.buf = malloc(keys->ksdata[i].key.length);
        if (!KK->key.value.buf) goto done;
        memcpy(KK->key.value.buf,
               keys->ksdata[i].key.contents, keys->ksdata[i].key.length);
        KK->key.value.size = keys->ksdata[i].key.length;

        if (keys->ksdata[i].salt.data != NULL) {
            KK->salt = calloc(1, sizeof(TypeValuePair_t));
            if (!KK->salt) goto done;
            KK->salt->type = keys->ksdata[i].salttype;
            KK->salt->value.buf = malloc(keys->ksdata[i].salt.length);
            if (!KK->salt->value.buf) goto done;
            memcpy(KK->salt->value.buf,
                   keys->ksdata[i].salt.data, keys->ksdata[i].salt.length);
            KK->salt->value.size = keys->ksdata[i].salt.length;
        }

        /* KK->key.s2kparams not used for now */

        ASN_SEQUENCE_ADD(&gkctrl.choice.reply.keys.list, KK);
    }

    ret = encode_GetKeytabControl(&gkctrl, buf, len);
    KK = NULL;

done:
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_GetKeytabControl, &gkctrl);
    if (KK) {
        free(KK->key.value.buf);
        if (KK->salt) {
            free(KK->salt->value.buf);
            free(KK->salt);
        }
        free(KK);
    }
    return ret;
}

static GetKeytabControl_t *decode_GetKeytabControl(void *buf, size_t len)
{
    GetKeytabControl_t *gkctrl = NULL;
    asn_dec_rval_t rval;

    rval = ber_decode(NULL, &asn_DEF_GetKeytabControl,
                      (void **)&gkctrl, buf, len);
    if (rval.code == RC_OK) {
        return gkctrl;
    }
    return NULL;
}

bool ipaasn1_dec_getkt(void *buf, size_t len, bool *newkt,
                       char **princ, char **pwd, long **etypes, int *numtypes)
{
    GetKeytabControl_t *gkctrl;
    bool ret = false;
    int num;

    gkctrl = decode_GetKeytabControl(buf, len);
    if (!gkctrl) return false;

    switch (gkctrl->present) {
    case GetKeytabControl_PR_newkeys:
        *newkt = true;
        *princ = strndup((char *)gkctrl->choice.newkeys.serviceIdentity.buf,
                         gkctrl->choice.newkeys.serviceIdentity.size);
        if (!*princ) goto done;

        num = gkctrl->choice.newkeys.enctypes.list.count;
        *etypes = malloc(num * sizeof(long));
        *numtypes = 0;
        if (!*etypes) goto done;
        for (int i = 0; i < num; i++) {
            (*etypes)[i] = *gkctrl->choice.newkeys.enctypes.list.array[i];
            (*numtypes)++;
        }

        if (gkctrl->choice.newkeys.password) {
            *pwd = strndup((char *)gkctrl->choice.newkeys.password->buf,
                           gkctrl->choice.newkeys.password->size);
            if (!*pwd) goto done;
        }
        break;
    case GetKeytabControl_PR_curkeys:
        *newkt = false;
        *princ = strndup((char *)gkctrl->choice.curkeys.serviceIdentity.buf,
                         gkctrl->choice.curkeys.serviceIdentity.size);
        if (!*princ) goto done;
        break;
    default:
        goto done;
    }

    ret = true;

done:
    ASN_STRUCT_FREE(asn_DEF_GetKeytabControl, gkctrl);
    return ret;
}

bool ipaasn1_dec_getktreply(void *buf, size_t len,
                            int *kvno, struct keys_container *keys)
{
    GetKeytabControl_t *gkctrl;
    struct KrbKey *KK;
    bool ret = false;
    int nkeys;

    gkctrl = decode_GetKeytabControl(buf, len);
    if (!gkctrl) return false;

    if (gkctrl->present != GetKeytabControl_PR_reply) goto done;

    *kvno = gkctrl->choice.reply.newkvno;

    nkeys = gkctrl->choice.reply.keys.list.count;

    keys->nkeys = 0;
    keys->ksdata = calloc(nkeys, sizeof(struct krb_key_salt));
    if (!keys->ksdata) goto done;

    for (int i = 0; i < nkeys; i++) {
        KK = gkctrl->choice.reply.keys.list.array[i];
        keys->ksdata[i].enctype = KK->key.type;
        keys->ksdata[i].key.enctype = KK->key.type;
        keys->ksdata[i].key.contents = malloc(KK->key.value.size);
        if (!keys->ksdata[i].key.contents) goto done;
        memcpy(keys->ksdata[i].key.contents,
               KK->key.value.buf, KK->key.value.size);
        keys->ksdata[i].key.length = KK->key.value.size;

        if (KK->salt) {
            keys->ksdata[i].salttype = KK->salt->type;
            keys->ksdata[i].salt.data = malloc(KK->salt->value.size);
            if (!keys->ksdata[i].salt.data) goto done;
            memcpy(keys->ksdata[i].salt.data,
                   KK->salt->value.buf, KK->salt->value.size);
            keys->ksdata[i].salt.length = KK->salt->value.size;
        }

        /* KK->s2kparams is ignored for now */
        keys->nkeys++;
    }

    ret = true;

done:
    ASN_STRUCT_FREE(asn_DEF_GetKeytabControl, gkctrl);
    return ret;
}
