# Authors: Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
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
import struct
import fcntl

from ipa import ipautil
from ipa import dnsclient

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

    try:
        hostaddr = socket.getaddrinfo(host_name, None)
    except:
        raise RuntimeError("Unable to resolve host name, check /etc/hosts or DNS name resolution")

    if len(hostaddr) == 0:
        raise RuntimeError("Unable to resolve host name, check /etc/hosts or DNS name resolution")

    for a in hostaddr:
        if a[4][0] == '127.0.0.1' or a[4][0] == '::1':
            raise RuntimeError("The IPA Server hostname cannot resolve to localhost (%s). A routable IP address must be used. Check /etc/hosts to see if %s is an alias for %s" % (a[4][0], host_name, a[4][0]))
        try:
            revname = socket.gethostbyaddr(a[4][0])[0]
        except:
            raise RuntimeError("Unable to resolve the reverse ip address, check /etc/hosts or DNS name resolution")
        if revname != host_name:
            raise RuntimeError("The host name %s does not match the reverse lookup %s" % (host_name, revname))

    # Verify this is NOT a CNAME
    rs = dnsclient.query(host_name+".", dnsclient.DNS_C_IN, dnsclient.DNS_T_CNAME)
    if len(rs) != 0:
        for rsn in rs:
            if rsn.dns_type == dnsclient.DNS_T_CNAME:
                raise RuntimeError("The IPA Server Hostname cannot be a CNAME, only A names are allowed.")

    # Verify that it is a DNS A record
    rs = dnsclient.query(host_name+".", dnsclient.DNS_C_IN, dnsclient.DNS_T_A)
    if len(rs) == 0:
        print "Warning: Hostname (%s) not found in DNS" % host_name
        return

    rec = None
    for rsn in rs:
        if rsn.dns_type == dnsclient.DNS_T_A:
            rec = rsn
            break

    if rec == None:
        print "Warning: Hostname (%s) not found in DNS" % host_name
        return

    # Compare the forward and reverse
    forward = rec.dns_name

    addr = socket.inet_ntoa(struct.pack('<L',rec.rdata.address))
    ipaddr = socket.inet_ntoa(struct.pack('!L',rec.rdata.address))

    addr = addr + ".in-addr.arpa."
    rs = dnsclient.query(addr, dnsclient.DNS_C_IN, dnsclient.DNS_T_PTR)
    if len(rs) == 0:
        raise RuntimeError("Cannot find Reverse Address for %s (%s)" % (host_name, addr))

    rev = None
    for rsn in rs:
        if rsn.dns_type == dnsclient.DNS_T_PTR:
            rev = rsn
            break

    if rev == None:
        raise RuntimeError("Cannot find Reverse Address for %s (%s)" % (host_name, addr))

    reverse = rev.rdata.ptrdname

    if forward != reverse:
        raise RuntimeError("The DNS forward record %s does not match the reverse address %s" % (forward, reverse))

def port_available(port):
    """Try to bind to a port on the wildcard host
       Return 1 if the port is available
       Return 0 if the port is in use
    """
    rv = 1

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        fcntl.fcntl(s, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        s.bind(('', port))
        s.close()
    except socket.error, e:
        if e[0] == errno.EADDRINUSE:
            rv = 0

    if rv:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            fcntl.fcntl(s, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
            s.bind(('', port))
            s.close()
        except socket.error, e:
            if e[0] == errno.EADDRINUSE:
                rv = 0

    return rv

def standard_logging_setup(log_filename, debug=False):
    old_umask = os.umask(077)
    # Always log everything (i.e., DEBUG) to the log
    # file.
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s %(message)s',
                        filename=log_filename,
                        filemode='w')
    os.umask(old_umask)

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

def read_password(user, confirm=True, validate=True):
    correct = False
    pwd = ""
    while not correct:
        pwd = getpass.getpass(user + " password: ")
        if not pwd:
            continue
        if validate and len(pwd) < 8:
            print "Password must be at least 8 characters long"
            continue
        if not confirm:
            correct = True
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

def set_directive(filename, directive, value):
    """Set a name/value pair directive in a configuration file.

       This has only been tested with nss.conf
    """
    fd = open(filename)
    file = []
    for line in fd:
        if directive in line:
            file.append('%s "%s"\n' % (directive, value))
        else:
            file.append(line)
    fd.close()

    fd = open(filename, "w")
    fd.write("".join(file))
    fd.close()

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

