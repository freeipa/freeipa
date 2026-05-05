from __future__ import print_function
import sys

print(
    "ipalib.pkcs10 module is deprecated and will be removed in IPA 4.6. "
    "To load CSRs, please use the synta library instead.",
    file=sys.stderr
)
