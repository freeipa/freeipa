
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

BAD_IP_MSG = "Not a valid IP address"
BAD_HOSTNAME_MSG = "only letters, numbers, '-' are allowed"
BAS_HOSTNAME_SPACE_MSG = "Leading and trailing spaces are not allowed"

empty_hostname = {
    'pkey': 'empty_hostname',
    'add': [
        ('textbox', 'hostname', ''),
    ],
}

empty_domain = {
    'pkey': 'empty_domain',
    'add': [
        ('textbox', 'hostname', 'itest-empty-domain'),
        ('textbox', 'dnszone', ''),
    ],
}

hostname_tilde = {
    'pkey': 'tilde_hostname',
    'add': [
        ('textbox', 'hostname', '~tilde'),
    ],
}

hostname_dash = {
    'pkey': 'dash_hostname',
    'add': [
        ('textbox', 'hostname', '-dash'),
    ],
}

hostname_leading_space = {
    'pkey': 'leading_space',
    'add': [
        ('textbox', 'hostname', ' leading_space'),
    ],
}

hostname_trailing_space = {
    'pkey': 'trailing_space',
    'add': [
        ('textbox', 'hostname', 'trailing_space '),
    ],
}

ip_alpha = {
    'pkey': 'ip_alpha',
    'add': [
        ('textbox', 'hostname', 'ip-field-test'),
        ('textbox', 'ip_address', 'abc.10.12.14'),
    ],
}

ip_many_oct = {
    'pkey': 'ip_many',
    'add': [
        ('textbox', 'hostname', 'ip-field-test'),
        ('textbox', 'ip_address', '10.10.10.1.10'),
    ],
}

ip_bad_oct = {
    'pkey': 'ip_bad_octal',
    'add': [
        ('textbox', 'hostname', 'ip-field-test'),
        ('textbox', 'ip_address', '10.0.378.1'),
    ],
}

ip_special_char = {
    'pkey': 'ip_special',
    'add': [
        ('textbox', 'hostname', 'ip-field-test'),
        ('textbox', 'ip_address', '10.0.##.1'),
    ],
}

mod_desc = [
    ('textarea', 'description', 'description in details'),
]

mod_desc_m = [
    ('textarea', 'description', 'description never appear'),
]

mod_locality = [
    ('textbox', 'l', 'Brno Office'),
]

mod_location = [
    ('textbox', 'nshostlocation', 'Brno Office'),
]

mod_platform = [
    ('textbox', 'nshardwareplatform', 'x86_64'),
]

mod_os = [
    ('textbox', 'nsosversion', 'FEDORA RHEL 277'),
]

otp_alpha = [
    ('password', 'userpassword', 'alpha'),
    ('password', 'password2', 'alpha'),
]

otp_num = [
    ('password', 'userpassword', '1234'),
    ('password', 'password2', '1234'),
]

otp_alphanum = [
    ('password', 'userpassword', 'abc123'),
    ('password', 'password2', 'abc123'),
]

otp_special = [
    ('password', 'userpassword', '@#$'),
    ('password', 'password2', '@#$'),
]

otp_mixed = [
    ('password', 'userpassword', 'AbC12D'),
    ('password', 'password2', 'AbC12D'),
]

ssh_nomod_error = "no modifications to be performed"
ssh_invalid_error = "invalid SSH public key"
ssh_rsa = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCnAOLat' + \
          'ncsaDxF+ldDhjNdPRDWXKsiZUz6Y49LjPnEr9p4Th24dZ' + \
          '7ZuvOVjhXDSkivh6MRunWZC+MXxRo1lDZgkCSyQfkMq0E' + \
          'u6xkubPg3tYAdrFBZIcIl5CUNerqYMdTz2hyTq6HAR/qs' + \
          '6oRbtzUemwHLPo3duqDRLWQoojP+tI8I2IEXnOO2N5oxq' + \
          'YGWAUe7bGXS/O2ukGfclt8/BfVw9e6eqHqlc7tKGqEctn' + \
          'imlsbG291ctNgco8FsvCnV5EOti/O0rLdkTmm66j7WCFj' + \
          'D9gJncfkAzxc+itWE4eUg/0B5ICIeRrFl5obD8Vu3LzTQ' + \
          '4yKiwaUnY5ngXgWBoFq9 root@sshkey.testipa.ipa'
ssh_dsa = 'ssh-dss AAAAB3NzaC1kc3MAAACBAO3OqwC1eNedXVJ57' + \
          '/a+Q/BfVcbZiJcTxhVP6TnIIQXmI+YSu685gLXEHWEAX1' + \
          '9+8eQuvUSmgWViuskErCXliE1c4PVyrwkf/2UMsH+hFaj' + \
          '0jlAM4APzizSvHC59hjpr5ktPyrv1arBXGYRuWyZNphJZ' + \
          'OFbqK2DHZbz1jvhD4uz5AAAAFQDasuSv8Dkn2Khqek0U3' + \
          'EAHUaUL2wAAAIB5Wr4r7z4ZyaSoaxfiUvvKg49FCeGjrY' + \
          'jRbYN/PazAn/X0rPcGqpaF3u5FmxXP7vhvlvECZvveK7T' + \
          'FIJVz1DSKHMRu8886akKLegF1zhhjrnjN7Q4vHbwkhsCI' + \
          'aV+4rlJa7B32girkSltlooP/qWMnRde0aJIf20Zhq/IF9' + \
          'oj49AAAAIBsKrdE+nxubD13+BdX07Sq6wAPVa9RVCISqE' + \
          'simlCvopStg8vNuNfGi9swmyFyNjSMiZEgoxH2cLRME4+' + \
          'xzn7THVrmE6OQ/Duz/mQAnDvt1N0Qw4jNxv0WqoT0kz7X' + \
          '21L5Dmg5qy4qdEvlcOkVI9gMrIrXhwGb+Vj8XEGtWcNmJ' + \
          'w== root@sshkey.testipa.ipa'
ssh_empty = ''
ssh_invalid = 'ff99cc1234dec invalid'

csr_invalid_error = 'Base64 decoding failed'
csr_invalid = 'invalid cert'
csr_other_host_error = 'Base64 decoding failed'
csr_other_host = '''-----BEGIN NEW CERTIFICATE REQUEST-----
MIICpjCCAY4CAQAwMDEQMA4GA1UEChMHSVBBLklQQTEcMBoGA1UEAxMTYW5vdGhl
cmhvc3QuaXBhLmlwYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM5Z
xiBOxo0W107maJt84m4BrkOFErCi0Mk4UQABMAfg/Sbj/+nYL19CA/IgSy4NoCnt
0RK1IZcFvSzHNhJmwpyRcmaOIbEsjes35rYYA2LKV3QVBp14284tJN5xRHztuL9B
0NDaSuZOG4JERHJl7JBGOzs4mj3FkI+Ci92d/zi+vpI+T0b26BGejcpU98zkVKxE
ktXNHqZp/QV7EHsqaZDdIPGTORZokZnU3VFsbUnCLDyghg3+75t+Wq4sJvwL1Y9j
btO5cQLWTJiOotk1Ies2A5nrp89CpMP45ERtZmoe+G3WeWgW9Nqr182kF5NjlC/O
sHKz4bP9hT9Z6bk4J3ECAwEAAaAxMC8GCSqGSIb3DQEJDjEiMCAwHgYDVR0RBBcw
FYITYW5vdGhlcmhvc3QuaXBhLmlwYTANBgkqhkiG9w0BAQsFAAOCAQEAoEQNqnts
Ob5fTPZRQQo8ygoKa+4GXMjM/Ue2SYs2zOa1/aYeI6JVzWzWH9xHFNvhOkdhu154
9fefKPtFKeyRTRz60KjSGcHyawDmoWyVYMPgFwmWp1lceFDEy0SlCnB58iXuxYEU
mwlXmODQR1hQxLuo5Ow3Hy0Djyml7gh7DA/iHP7WrOJH3PwTegxAFFixIj7K6DYK
3Kaeng72Ht8vQeTEh0Fq4rcfIdlW6tjWywLqLqCjtwhNkak4tJna6M9/3yjeyEnk
/w7Ya8CyOwlTaCvN8cjnBTxXWVVh+lIaPhujxG4UVtOMqaI30EkMIMHrocCUNnRd
2e8CMvHPLREqJw==
-----END NEW CERTIFICATE REQUEST-----'''

krb_enrolled = 'Kerberos Key Present, Host Provisioned'
krb_not_enrolled = 'Kerberos Key Not Present'
