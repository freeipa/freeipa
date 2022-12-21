#
# Copyright (C) 2022  FreeIPA Contributors see COPYING for license
#

'''
This module contains Nixos specific platform files.
'''
import sys
import warnings

NAME = 'nixos'

if sys.version_info < (3, 6):
    warnings.warn(
        "Support for Python 2.7 and 3.5 is deprecated. Python version "
        "3.6 or newer will be required in the next major release.",
        category=DeprecationWarning
    )
