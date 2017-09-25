from __future__ import print_function
import sys

print(
    "ipalib.pkcs10 module is deprecated and will be removed in FreeIPA 4.6. "
    "To load CSRs, please, use python-cryptography instead.",
    file=sys.stderr
)
