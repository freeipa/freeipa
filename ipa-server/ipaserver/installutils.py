# Authors: Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 or later
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import logging
import socket
import errno
import getpass
import os
import re
import fileinput
import sys
import time

from ipa import ipautil

def get_fqdn():
    fqdn = ""
    try:
        fqdn = socket.getfqdn()
    except:
        try:
            fqdn = socket.gethostname()
        except:
            fqdn = ""
    return fqdn
   
def verify_fqdn(host_name):
    if len(host_name.split(".")) < 2 or host_name == "localhost.localdomain":
        raise RuntimeError("Invalid hostname: " + host_name)

def port_available(port):
    """Try to bind to a port on the wildcard host
       Return 1 if the port is available
       Return 0 if the port is in use
    """
    rv = 1

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', port))
        s.shutdown(0)
        s.close()
    except socket.error, e:
        if e[0] == errno.EADDRINUSE:
            rv = 0

    if rv:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('', port))
            s.shutdown(0)
            s.close()
        except socket.error, e:
            if e[0] == errno.EADDRINUSE:
                rv = 0

    return rv

def standard_logging_setup(log_filename, debug=False):
    # Always log everything (i.e., DEBUG) to the log
    # file.
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s %(message)s',
                        filename=log_filename,
                        filemode='w')

    console = logging.StreamHandler()
    # If the debug option is set, also log debug messages to the console
    if debug:
        console.setLevel(logging.DEBUG)
    else:
        # Otherwise, log critical and error messages
        console.setLevel(logging.ERROR)
    formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

def read_password(user):
    correct = False
    pwd = ""
    while not correct:
        pwd = getpass.getpass(user + " password: ")
        if not pwd:
            continue
        if len(pwd) < 8:
            print "Password must be at least 8 characters long"
            continue
        pwd_confirm = getpass.getpass("Password (confirm): ")
        if pwd != pwd_confirm:
            print "Password mismatch!"
            print ""
        else:
            correct = True
    print ""
    return pwd

def update_file(filename, orig, subst):
    if os.path.exists(filename):
        pattern = "%s" % re.escape(orig)
        p = re.compile(pattern)
        for line in fileinput.input(filename, inplace=1):
            if not p.search(line):
                sys.stdout.write(line)
            else:
                sys.stdout.write(p.sub(subst, line))
        fileinput.close()
        return 0
    else:
        print "File %s doesn't exist." % filename
        return 1

def kadmin(command):
    ipautil.run(["/usr/kerberos/sbin/kadmin.local", "-q", command])

def kadmin_addprinc(principal):
    kadmin("addprinc -randkey " + principal)

def kadmin_modprinc(principal, options):
    kadmin("modprinc " + options + " " + principal)

def create_keytab(path, principal):
    try:
        if ipautil.file_exists(path):
            os.remove(path)
    except os.error:
        logging.critical("Failed to remove %s." % path)

    kadmin("ktadd -k " + path + " " + principal)

