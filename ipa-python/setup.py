#!/usr/bin/env python
"""FreeIPA python support library

FreeIPA is a server for identity, policy, and audit.
"""

DOCLINES = __doc__.split("\n")

import os
import sys
import distutils.sysconfig

CLASSIFIERS = """\
Development Status :: 4 - Beta
Intended Audience :: System Environment/Base
License :: GPL
Programming Language :: Python
Operating System :: POSIX
Operating System :: Unix
"""

# BEFORE importing distutils, remove MANIFEST. distutils doesn't properly
# update it when the contents of directories change.
if os.path.exists('MANIFEST'): os.remove('MANIFEST')

def setup_package():

    from distutils.core import setup

    old_path = os.getcwd()
    local_path = os.path.dirname(os.path.abspath(sys.argv[0]))
    os.chdir(local_path)
    sys.path.insert(0,local_path)

    try:
        setup(
            name = "freeipa-python",
            version = "0.5.0",
            license = "GPL",
            author = "Karl MacMillan, et.al.",
            author_email = "kmacmillan@redhat.com",
            maintainer = "freeIPA Developers",
            maintainer_email = "freeipa-devel@redhat.com",
            url = "http://www.freeipa.org/",
            description = DOCLINES[0],
            long_description = "\n".join(DOCLINES[2:]),
            download_url = "http://www.freeipa.org/page/Downloads",
            classifiers=filter(None, CLASSIFIERS.split('\n')),
            platforms = ["Linux", "Solaris", "Unix"],
            package_dir = {'ipa': ''},
            packages = [ "ipa" ],
            data_files = [('/etc/ipa', ['ipa.conf'])]
        )
    finally:
        del sys.path[0]
        os.chdir(old_path)
    return

if __name__ == '__main__':
    setup_package()
