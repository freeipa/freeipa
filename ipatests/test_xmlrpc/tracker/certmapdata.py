#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from nose.tools import assert_raises

from ipalib.errors import MutuallyExclusiveError, RequirementError
from ipapython.dn import DN
from ipatests.util import assert_deepequal


class CertmapdataMixin(object):
    certmapdata_options = {u'issuer', u'subject', u'usercertificate',
                           u'ipacertmapdata'}

    def _data_from_options(self, **options):
        issuer = None
        subject = None

        def any_in(keys, mapping):
            return any([(key in mapping) for key in keys])

        if not any_in(self.certmapdata_options, options):
            raise RequirementError(name=u'certmapdata')

        if (
            any_in((u'ipacertmapdata', u'usercertificate',), options) and
            any_in((u'issuer', u'subject',), options)
        ):
            raise MutuallyExclusiveError(reason=u'Mutually exclusive options '
                                                u'provided at the same time.')

        try:
            data = options[u'ipacertmapdata']
        except KeyError:
            pass
        else:
            if not isinstance(data, list):
                data = [data]
            return data

        try:
            certs = options[u'usercertificate']
        except KeyError:
            pass
        else:
            if not isinstance(certs, list):
                certs = [certs]

            certmapdata = []

            for cert in certs:
                cert = x509.load_pem_x509_certificate(
                    (b'-----BEGIN CERTIFICATE-----\n'
                     b'{}-----END CERTIFICATE-----\n'
                     .format(cert)),
                    default_backend()
                )
                issuer = DN(cert.issuer).x500_text()
                subject = DN(cert.subject).x500_text()

                certmapdata.append(
                    u'X509:<I>{i}<S>{s}'.format(i=issuer, s=subject)
                )

            return certmapdata

        try:
            issuer = DN(options[u'issuer']).x500_text()
        except KeyError:
            pass

        try:
            subject = DN(options[u'subject']).x500_text()
        except KeyError:
            pass

        data = u'X509:'
        if issuer:
            data += u'<I>{i}'.format(i=issuer)
        if subject:
            data += u'<S>{s}'.format(s=subject)

        return [data]

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
            with assert_raises(type(e)):
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
            with assert_raises(type(e)):
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
