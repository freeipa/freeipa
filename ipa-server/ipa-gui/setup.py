# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
 
from setuptools import setup, find_packages
from turbogears.finddata import find_package_data

import os
execfile(os.path.join("ipagui", "release.py"))

setup(
    name="ipa-gui",
    version=version,
    
    # uncomment the following lines if you fill them out in release.py
    #description=description,
    #author=author,
    #author_email=email,
    #url=url,
    #download_url=download_url,
    #license=license,
    
    install_requires = [
        "TurboGears >= 1.0.2.2",
    ],
    zip_safe=False,
    packages=find_packages(),
    package_data = find_package_data(where='ipagui',
                                     package='ipagui'),
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Framework :: TurboGears',
        # if this is an application that you'll distribute through
        # the Cheeseshop, uncomment the next line
        # 'Framework :: TurboGears :: Applications',
        
        # if this is a package that includes widgets that you'll distribute
        # through the Cheeseshop, uncomment the next line
        # 'Framework :: TurboGears :: Widgets',
    ],
    test_suite = 'nose.collector',
    entry_points = """
    [turbogears.identity.provider]
    proxyprovider = ipagui.proxyprovider:ProxyIdentityProvider
    [turbogears.visit.manager]
    proxyvisit = ipagui.proxyvisit:ProxyVisitManager
    """,
    )
    
