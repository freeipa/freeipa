# Authors: Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import logging
import socket
import errno
import getpass
import os
import re
import fileinput
import sys
import struct
import fcntl
import netaddr

from ipapython import ipautil
from ipapython import dnsclient

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

def verify_dns_records(host_name, responses, resaddr, family):
    familykw = { 'ipv4' : {
                             'dns_type' : dnsclient.DNS_T_A,
                             'socket_family' : socket.AF_INET,
                          },
                 'ipv6' : {
                             'dns_type' : dnsclient.DNS_T_AAAA,
                             'socket_family' : socket.AF_INET6,
                          },
               }

    family = family.lower()
    if family not in familykw.keys():
        raise RuntimeError("Unknown faimily %s\n" % family)

    rec = None
    for rsn in responses:
        if rsn.dns_type == familykw[family]['dns_type']:
            rec = rsn
            break

    if rec == None:
        raise IOError(errno.ENOENT,
                      "Warning: Hostname (%s) not found in DNS" % host_name)

    if family == 'ipv4':
        familykw[family]['address'] = socket.inet_ntop(socket.AF_INET,
                                                       struct.pack('!L',rec.rdata.address))
    else:
        familykw[family]['address'] = socket.inet_ntop(socket.AF_INET6,
                                                       struct.pack('!16B', *rec.rdata.address))

    # Check that DNS address is the same is address returned via standard glibc calls
    dns_addr = netaddr.IPAddress(familykw[family]['address'])
    if dns_addr.format() != resaddr:
        raise RuntimeError("The network address %s does not match the DNS lookup %s. Check /etc/hosts and ensure that %s is the IP address for %s" % (dns_addr.format(), resaddr, dns_addr.format(), host_name))

    rs = dnsclient.query(dns_addr.reverse_dns, dnsclient.DNS_C_IN, dnsclient.DNS_T_PTR)
    if len(rs) == 0:
        raise RuntimeError("Cannot find Reverse Address for %s (%s)" % (host_name, dns_addr.format()))

    rev = None
    for rsn in rs:
        if rsn.dns_type == dnsclient.DNS_T_PTR:
            rev = rsn
            break

    if rev == None:
        raise RuntimeError("Cannot find Reverse Address for %s (%s)" % (host_name, dns_addr.format()))

    if rec.dns_name != rev.rdata.ptrdname:
        raise RuntimeError("The DNS forward record %s does not match the reverse address %s" % (rec.dns_name, rev.rdata.ptrdname))


def verify_fqdn(host_name,no_host_dns=False):
    if len(host_name.split(".")) < 2 or host_name == "localhost.localdomain":
        raise RuntimeError("Invalid hostname '%s', must be fully-qualified." % host_name)

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
            resaddr = a[4][0]
            revname = socket.gethostbyaddr(a[4][0])[0]
        except:
            raise RuntimeError("Unable to resolve the reverse ip address, check /etc/hosts or DNS name resolution")
        if revname != host_name:
            raise RuntimeError("The host name %s does not match the reverse lookup %s" % (host_name, revname))

    if no_host_dns:
        print "Warning: skipping DNS resolution of host", host_name
        return

    # Verify this is NOT a CNAME
    rs = dnsclient.query(host_name+".", dnsclient.DNS_C_IN, dnsclient.DNS_T_CNAME)
    if len(rs) != 0:
        for rsn in rs:
            if rsn.dns_type == dnsclient.DNS_T_CNAME:
                raise RuntimeError("The IPA Server Hostname cannot be a CNAME, only A and AAAA names are allowed.")

    # Verify that it is a DNS A or AAAA record
    rs = dnsclient.query(host_name+".", dnsclient.DNS_C_IN, dnsclient.DNS_T_A)
    if len(rs) > 0:
        verify_dns_records(host_name, rs, resaddr, 'ipv4')
        return

    rs = dnsclient.query(host_name+".", dnsclient.DNS_C_IN, dnsclient.DNS_T_AAAA)
    if len(rs) > 0:
        verify_dns_records(host_name, rs, resaddr, 'ipv6')
        return
    else:
        print "Warning: Hostname (%s) not found in DNS" % host_name

def verify_ip_address(ip):
    is_ok = True
    try:
        socket.inet_pton(socket.AF_INET, ip)
    except:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
        except:
            print "Unable to verify IP address"
            is_ok = False
    return is_ok

def read_ip_address(host_name, fstore):
    while True:
        ip = ipautil.user_input("Please provide the IP address to be used for this host name", allow_empty = False)

        if ip == "127.0.0.1" or ip == "::1":
            print "The IPA Server can't use localhost as a valid IP"
            continue

        if verify_ip_address(ip):
            break

    print "Adding ["+ip+" "+host_name+"] to your /etc/hosts file"
    fstore.backup_file("/etc/hosts")
    hosts_fd = open('/etc/hosts', 'r+')
    hosts_fd.seek(0, 2)
    hosts_fd.write(ip+'\t'+host_name+' '+host_name.split('.')[0]+'\n')
    hosts_fd.close()

    return ip

def read_dns_forwarders():
    addrs = []
    if ipautil.user_input("Do you want to configure DNS forwarders?", True):
        print "Enter the IP address of DNS forwarder to use, or press Enter to finish."

        while True:
            ip = ipautil.user_input("Enter IP address for a DNS forwarder",
                                    allow_empty=True)
            if not ip:
                break
            if ip == "127.0.0.1" or ip == "::1":
                print "You cannot use localhost as a DNS forwarder"
                continue
            if not verify_ip_address(ip):
                print "DNS forwarder %s not added" % ip
                continue

            print "DNS forwarder %s added" % ip
            addrs.append(ip)

    if not addrs:
        print "No DNS forwarders configured"

    return addrs

def port_available(port):
    """Try to bind to a port on the wildcard host
       Return 1 if the port is available
       Return 0 if the port is in use
    """
    rv = 1

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        fcntl.fcntl(s, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        s.bind(('', port))
        s.close()
    except socket.error, e:
        if e[0] == errno.EADDRINUSE:
            rv = 0

    if rv:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            fcntl.fcntl(s, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
            s.bind(('', port))
            s.close()
        except socket.error, e:
            if e[0] == errno.EADDRINUSE:
                rv = 0

    return rv

def standard_logging_setup(log_filename, debug=False, filemode='w'):
    old_umask = os.umask(077)
    # Always log everything (i.e., DEBUG) to the log
    # file.
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s %(message)s',
                        filename=log_filename,
                        filemode=filemode)
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

def get_password(prompt):
    if os.isatty(sys.stdin.fileno()):
        return getpass.getpass(prompt)
    else:
        return sys.stdin.readline().rstrip()

def read_password(user, confirm=True, validate=True):
    correct = False
    pwd = ""
    while not correct:
        pwd = get_password(user + " password: ")
        if not pwd:
            continue
        if validate and len(pwd) < 8:
            print "Password must be at least 8 characters long"
            continue
        if not confirm:
            correct = True
            continue
        pwd_confirm = get_password("Password (confirm): ")
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

def set_directive(filename, directive, value, quotes=True, separator=' '):
    """Set a name/value pair directive in a configuration file.

       This has only been tested with nss.conf
    """
    valueset = False
    fd = open(filename)
    newfile = []
    for line in fd:
        if directive in line:
            valueset = True
            if quotes:
                newfile.append('%s%s"%s"\n' % (directive, separator, value))
            else:
                newfile.append('%s%s%s\n' % (directive, separator, value))
        else:
            newfile.append(line)
    fd.close()
    if not valueset:
        if quotes:
            newfile.append('%s%s"%s"\n' % (directive, separator, value))
        else:
            newfile.append('%s%s%s\n' % (directive, separator, value))

    fd = open(filename, "w")
    fd.write("".join(newfile))
    fd.close()

def get_directive(filename, directive, separator=' '):
    """
    A rather inefficient way to get a configuration directive.
    """
    fd = open(filename, "r")
    for line in fd:
        if directive in line:
            line = line.strip()
            result = line.split(separator, 1)[1]
            result = result.strip('"')
            result = result.strip(' ')
            fd.close()
            return result
    fd.close()
    return None

def kadmin(command):
    ipautil.run(["kadmin.local", "-q", command])

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

