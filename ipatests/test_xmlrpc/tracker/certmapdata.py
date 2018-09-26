#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#
import base64

from cryptography import x509
from cryptography.hazmat.backends import default_backend
import pytest

from ipalib.errors import MutuallyExclusiveError, RequirementError
from ipapython.dn import DN
from ipatests.util import assert_deepequal


class CertmapdataMixin:
    certmapdata_options = {u'issuer', u'subject', u'certificate',
                           u'ipacertmapdata'}

    def _data_from_options(self, **options):
        issuer = None
        subject = None

        if not self.certmapdata_options & set(options):
            raise RequirementError(name=u'certmapdata')

        if ({u'issuer', u'subject'} & set(options) and
                {u'ipacertmapdata', u'certificate'} & set(options)):
            raise MutuallyExclusiveError(reason=u'Mutually exclusive options '
                                                u'provided at the same time.')

        if u'issuer' in options and u'subject' not in options:
            raise RequirementError(name=u'subject')

        if u'subject' in options and u'issuer' not in options:
            raise RequirementError(name=u'issuer')

        if {u'ipacertmapdata', u'certificate'} & set(options):
            try:
                data = options[u'ipacertmapdata']
            except KeyError:
                data = []
            else:
                if not isinstance(data, list):
                    data = [data]

            try:
                certs = options[u'certificate']
            except KeyError:
                certs = []
            else:
                if not isinstance(certs, list):
                    certs = [certs]

            for cert in certs:
                cert = x509.load_der_x509_certificate(
                    base64.b64decode(cert),
                    backend=default_backend()
                )
                issuer = DN(cert.issuer).x500_text()
                subject = DN(cert.subject).x500_text()

                data.append(
                    u'X509:<I>{i}<S>{s}'.format(i=issuer, s=subject)
                )
        else:
            issuer = DN(options[u'issuer']).x500_text()
            subject = DN(options[u'subject']).x500_text()

            data = [u'X509:<I>{i}<S>{s}'.format(i=issuer, s=subject)]

        return set(data)

    def _make_add_certmap(self):
        raise NotImplementedError("_make_add_certmap method must be "
                                  "implemented in instance.")

    def _make_remove_certmap(self):
        raise NotImplementedError("_make_remove_certmap method must be "
                                  "implemented in instance.")

    def add_certmap(self, **kwargs):
        cmd = self._make_add_certmap()

        try:
            expected_certmapdata = self._data_from_options(**kwargs)
        except Exception as e:
            with pytest.raises(type(e)):
                cmd(**kwargs)
        else:
            result = cmd(**kwargs)
            self.attrs.setdefault(u'ipacertmapdata', []).extend(
                expected_certmapdata)

            expected = dict(
                summary=(u'Added certificate mappings to user '
                         u'"{}"'.format(self.name)),
                value=self.name,
                result=dict(
                    uid=(self.name,),
                ),
            )

            if self.attrs[u'ipacertmapdata']:
                expected[u'result'][u'ipacertmapdata'] = (
                    self.attrs[u'ipacertmapdata'])

            assert_deepequal(expected, result)

    def remove_certmap(self, **kwargs):
        cmd = self._make_remove_certmap()

        try:
            expected_certmapdata = self._data_from_options(**kwargs)
        except Exception as e:
            with pytest.raises(type(e)):
                cmd(**kwargs)
        else:
            result = cmd(**kwargs)

            for data in expected_certmapdata:
                self.attrs[u'ipacertmapdata'].remove(data)

            expected = dict(
                summary=(u'Removed certificate mappings from user '
                         u'"{}"'.format(self.name)),
                value=self.name,
                result=dict(
                    uid=(self.name,),
                ),
            )
            if self.attrs[u'ipacertmapdata']:
                expected[u'result'][u'ipacertmapdata'] = (
                    self.attrs[u'ipacertmapdata'])

            assert_deepequal(expected, result)
