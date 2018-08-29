#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#
"""ipaplatform namespace package

In the presence of a namespace package, any code in this module will be
ignore.
"""
__import__('pkg_resources').declare_namespace(__name__)

NAME = None  # initialized by ipaplatform.osinfo
