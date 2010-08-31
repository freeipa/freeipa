# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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

# Some certmonger functions, mostly around updating the request file.
# This is used so we can add tracking to the Apache and 389-ds
# server certificates created during the IPA server installation.

import os
import re
import time
from ipapython import ipautil

REQUEST_DIR='/var/lib/certmonger/requests/'

def find_request_value(filename, directive):
    """
    Return a value from a certmonger request file for the requested directive

    It tries to do this a number of times because sometimes there is a delay
    when ipa-getcert returns and the file is fully updated, particularly
    when doing a request. Genrerating a CSR is fast but not instantaneous.
    """
    tries = 1
    value = None
    found = False
    while value is None and tries <= 5:
        tries=tries + 1
        time.sleep(1)
        fp = open(filename, 'r')
        lines = fp.readlines()
        fp.close()

        for line in lines:
            if found:
                # A value can span multiple lines. If it does then it has a
                # leading space.
                if not line.startswith(' '):
                    # We hit the next directive, return now
                    return value
                else:
                    value = value + line[1:]
            else:
                if line.startswith(directive + '='):
                    found = True
                    value = line[len(directive)+1:]

    return value

def get_request_value(request_id, directive):
    """
    There is no guarantee that the request_id will match the filename
    in the certmonger requests directory, so open each one to find the
    request_id.
    """
    fileList=os.listdir(REQUEST_DIR)
    for file in fileList:
        value = find_request_value('%s/%s' % (REQUEST_DIR, file), 'id')
        if value is not None and value.rstrip() == request_id:
            return find_request_value('%s/%s' % (REQUEST_DIR, file), directive)

    return None

def get_request_id(criteria):
    """
    If you don't know the certmonger request_id then try to find it by looking
    through all the request files. An alternative would be to parse the
    ipa-getcert list output but this seems cleaner.

    criteria is a tuple of key/value pairs to search for. The more specific
    the better. An error is raised if multiple request_ids are returned for
    the same criteria.

    None is returned if none of the criteria match.
    """
    assert type(criteria) is tuple

    reqid=None
    fileList=os.listdir(REQUEST_DIR)
    for file in fileList:
        match = True
        for (key, value) in criteria:
            rv = find_request_value('%s/%s' % (REQUEST_DIR, file), key)
            if rv is None or rv.rstrip() != value:
                match = False
                break
        if match and reqid is not None:
            raise RuntimeError('multiple certmonger requests match the criteria')
        if match:
            reqid = find_request_value('%s/%s' % (REQUEST_DIR, file), 'id').rstrip()

    return reqid

def add_request_value(request_id, directive, value):
    """
    Add a new directive to a certmonger request file.

    The certmonger service MUST be stopped in order for this to work.
    """
    fileList=os.listdir(REQUEST_DIR)
    for file in fileList:
        id = find_request_value('%s/%s' % (REQUEST_DIR, file), 'id')
        if id is not None and id.rstrip() == request_id:
            current_value = find_request_value('%s/%s' % (REQUEST_DIR, file), directive)
            if not current_value:
                fp = open('%s/%s' % (REQUEST_DIR, file), 'a')
                fp.write('%s=%s\n' % (directive, value))
                fp.close()

    return

def add_principal(request_id, principal):
    """
    In order for a certmonger request to be renwable it needs a principal.

    When an existing certificate is added via start-tracking it won't have
    a principal.
    """
    return add_request_value(request_id, 'template_principal', principal)

def add_subject(request_id, subject):
    """
    In order for a certmonger request to be renwable it needs the subject
    set in the request file.

    When an existing certificate is added via start-tracking it won't have
    a subject_template set.
    """
    return add_request_value(request_id, 'template_subject', subject)

def request_cert(nssdb, nickname, subject, principal, passwd_fname=None):
    """
    Execute certmonger to request a server certificate
    """
    args = ['/usr/bin/ipa-getcert',
            'request',
            '-d', nssdb,
            '-n', nickname,
            '-N', subject,
            '-K', principal,
    ]
    if passwd_fname:
        args.append('-p')
        args.append(passwd_fname)
    (stdout, stderr, returncode) = ipautil.run(args)
    # FIXME: should be some error handling around this
    m = re.match('New signing request "(\d+)" added', stdout)
    request_id = m.group(1)
    return request_id

def cert_exists(nickname, secdir):
    """
    See if a nickname exists in an NSS database.

    Returns True/False

    This isn't very sophisticated in that it doesn't differentiate between
    a database that doesn't exist and a nickname that doesn't exist within
    the database.
    """
    args = ["/usr/bin/certutil", "-L",
           "-d", secdir,
           "-n", nickname
          ]
    (stdout, stderr, rc) = ipautil.run(args, raiseonerr=False)
    if rc == 0:
        return True
    else:
        return False

def start_tracking(nickname, secdir, password_file=None):
    """
    Tell certmonger to track the given certificate nickname in NSS
    database in secdir protected by optional password file password_file.

    Returns the stdout, stderr and returncode from running ipa-getcert

    This assumes that certmonger is already running.
    """
    if not cert_exists(nickname, secdir):
        raise RuntimeError('Nickname "%s" doesn\'t exist in NSS database "%s"' % (nickname, secdir))
    args = ["/usr/bin/ipa-getcert", "start-tracking",
            "-d", secdir,
            "-n", nickname]
    if password_file:
        args.append("-p")
        args.append(password_file)

    (stdout, stderr, returncode) = ipautil.run(args)

    return (stdout, stderr, returncode)

def stop_tracking(secdir, request_id=None, nickname=None):
    """
    Stop tracking the current request using either the request_id or nickname.

    This assumes that the certmonger service is running.
    """
    if request_id is None and nickname is None:
        raise RuntimeError('Both request_id and nickname are missing.')
    if nickname:
        # Using the nickname find the certmonger request_id
        criteria = (('cert_storage_location','%s' % secdir),('cert_nickname', '%s' % nickname))
        try:
            request_id = get_request_id(criteria)
            if request_id is None:
                return ('', '', 0)
        except RuntimeError:
            # This means that multiple requests matched, skip it for now
            # Fall back to trying to stop tracking using nickname
            pass

    args = ['/usr/bin/ipa-getcert',
            'stop-tracking',
    ]
    if request_id:
        args.append('-i')
        args.append(request_id)
    else:
        args.append('-n')
        args.append(nickname)
        args.append('-d')
        args.append(secdir)

    (stdout, stderr, returncode) = ipautil.run(args)

    return (stdout, stderr, returncode)

if __name__ == '__main__':
    request_id = request_cert("/etc/httpd/alias", "Test", "cn=tiger.example.com,O=IPA", "HTTP/tiger.example.com@EXAMPLE.COM")
    csr = get_request_value(request_id, 'csr')
    print csr
    stop_tracking(request_id)
