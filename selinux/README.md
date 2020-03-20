# IPA SELinux policy

The ``ipa`` SELinux policy is used by IPA client and server. The
policy was forked off from [Fedora upstream policy](https://github.com/fedora-selinux/selinux-policy-contrib)
at commit ``b1751347f4af99de8c88630e2f8d0a352d7f5937``.

Some file locations are owned by other policies:

* ``/var/lib/ipa/pki-ca/publish(/.*)?`` is owned by Dogtag PKI policy
* ``/usr/lib/ipa/certmonger(/.*)?`` is owned by certmonger policy
* ``/var/lib/ipa-client(/.*)?`` is owned by realmd policy
