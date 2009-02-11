#!/usr/bin/python

from base64 import b64encode, b64decode
from ipalib import api

# certificate with serial number 17
cert = b64decode("""
MIIC3zCCAcegAwIBAgIBETANBgkqhkiG9w0BAQUFADA7MRkwFwYDVQQKExBTamNSZWRoYXQgRG9tYW
luMR4wHAYDVQQDExVDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMDkwMTIyMjMzODA2WhcNMDkwNzIx
MjMzODA2WjAUMRIwEAYKCZImiZPyLGQBARMCbGwwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAM
id6i9ri9ldyAXaH4MJSPdUDjdc9+E10hwxw7crFE1K0uvr8YT2e1YotNqv7Q+Bk7KVRrLH6Y5UPlWY
uSAP8G9t8yjn5Uo3iXU5AqsrRek+pxerD/WocwedF6yjJ/zlQyYyg93h0njJr1lStyVLTyp+VVqtk3
FSDIwLCWQHOTejAgMBAAGjgZgwgZUwHwYDVR0jBBgwFoAUlz9JZxqVabh4QQOEkxyWt80pIQkwQwYI
KwYBBQUHAQEENzA1MDMGCCsGAQUFBzABhidodHRwOi8vYS1mOC5zamMucmVkaGF0LmNvbTo5MTgwL2
NhL29jc3AwDgYDVR0PAQH/BAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDANBgkq
hkiG9w0BAQUFAAOCAQEAhU+oqPh+rlYFPm0D8HAJ0RIWw9gkNctHUfVGi+NeYTaUAEGWUOpXjLSQgP
gq1fNBHd+IRLhycwp4uUsFCPE1n3eStmn/D6o9u1eNnTFPj74MLZVQQTXPE8+LBYeHgTUwFuKp2WyW
9J/BDZ3pDWKYWWMawhD7ext7UhZkpIJODFEaDxiXCfB8GsAEbmfoYFk21znuGQQu3Wu1s6licyunLh
/W3sxCFGIT9DHxS0GZKimm7M02IPGxK/0TZr0kVcLQx6XGKqiK1464rvl4u60mQjwJwfhawshs84YT
xFnXZKkvsT3GjfIe/k687TMG3paTFtKkis+u7z0v6355uJzLpQ==
""")

csr = 'MIIBlDCB/gIBADBVMR0wGwYDVQQKExRVc2Vyc3lzUmVkaGF0LURvbWFpbjEQMA4GA1UECxMHcGtpLWlwYTEiMCAGA1UEAxMZSVBBLVN1YnN5c3RlbS1DZXJ0aWZpY2F0ZTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA3Qmpr81WxbnISmyyhc2ShiPzUvWIrCg5FgJ1QrBl7CRe62Wl/YYiV/DbuMoex1ec7zKfgfSFVFU9/2iwj7Du0sZdXYJNQPdj9yLdPk2tyxdgJuHLdxI0SNgaEFyvmIMP/X9vQN9H5w0/PyrJQscOxc6tbTcYL0ZSSylLQ+diaQECAwEAA'

api.bootstrap(in_server=True, debug=True)
api.finalize()
ra = api.Backend.ra

def assert_equal(*vals):
    val0 = vals[0]
    for val in vals[1:]:
        assert val == val0, '%r != %r' % (val, val0)


api.log.info('******** Testing ra.check_request_status() ********')
assert_equal(
    ra.check_request_status('35'),
    dict(
        status='0',
        serial_number='17',
        request_status='complete',
        request_id='35',
    )
)

api.log.info('******** Testing ra.get_certificate() ********')
assert_equal(
    ra.get_certificate('17'),
    dict(
        status='0',
        certificate=b64encode(cert),
    )
)

api.log.info('******** Testing ra.request_certificate() ********')
assert_equal(
    ra.request_certificate(csr),
    dict(
        status='1',
    )
)

api.log.info('******** Testing ra.revoke_certificate() ********')
assert_equal(
    ra.revoke_certificate('17', revocation_reason=6),  # Put on hold
    dict(
        status='0',
        revoked=True,
    )
)

api.log.info('******** Testing ra.take_certificate_off_hold() ********')
assert_equal(
    ra.take_certificate_off_hold('17'),
    dict(
        taken_off_hold=True,
    )
)
