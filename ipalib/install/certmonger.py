# Authors: Rob Crittenden <rcritten@redhat.com>
#          David Kupka <dkupka@redhat.com>
#
# Copyright (C) 2010  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# Some certmonger functions, mostly around updating the request file.
# This is used so we can add tracking to the Apache and 389-ds
# server certificates created during the IPA server installation.

from __future__ import print_function, absolute_import

import logging
import os
import time
import dbus
import shlex
import subprocess
import tempfile
from ipalib import api
from ipalib.constants import CA_DBUS_TIMEOUT
from ipapython.dn import DN
from ipaplatform.paths import paths
from ipaplatform import services

logger = logging.getLogger(__name__)

DBUS_CM_PATH = '/org/fedorahosted/certmonger'
DBUS_CM_IF = 'org.fedorahosted.certmonger'
DBUS_CM_NAME = 'org.fedorahosted.certmonger'
DBUS_CM_REQUEST_IF = 'org.fedorahosted.certmonger.request'
DBUS_CM_CA_IF = 'org.fedorahosted.certmonger.ca'
DBUS_PROPERTY_IF = 'org.freedesktop.DBus.Properties'


class _cm_dbus_object(object):
    """
    Auxiliary class for convenient DBus object handling.
    """
    def __init__(self, bus, parent, object_path, object_dbus_interface,
                 parent_dbus_interface=None, property_interface=False):
        """
        bus - DBus bus object, result of dbus.SystemBus() or dbus.SessionBus()
              Object is accesible over this DBus bus instance.
        object_path - path to requested object on DBus bus
        object_dbus_interface
        parent_dbus_interface
        property_interface - create DBus property interface? True or False
        """
        if bus is None or object_path is None or object_dbus_interface is None:
            raise RuntimeError(
                "bus, object_path and dbus_interface must not be None.")
        if parent_dbus_interface is None:
            parent_dbus_interface = object_dbus_interface
        self.bus = bus
        self.parent = parent
        self.path = object_path
        self.obj_dbus_if = object_dbus_interface
        self.parent_dbus_if = parent_dbus_interface
        self.obj = bus.get_object(parent_dbus_interface, object_path)
        self.obj_if = dbus.Interface(self.obj, object_dbus_interface)
        if property_interface:
            self.prop_if = dbus.Interface(self.obj, DBUS_PROPERTY_IF)


class _certmonger(_cm_dbus_object):
    """
    Create a connection to certmonger.
    By default use SystemBus. When not available use private connection
    over Unix socket.
    This solution is really ugly and should be removed as soon as DBus
    SystemBus is available at system install time.
    """
    timeout = 300

    def _start_private_conn(self):
        sock_filename = os.path.join(tempfile.mkdtemp(), 'certmonger')
        self._proc = subprocess.Popen([paths.CERTMONGER, '-n', '-L', '-P',
                                       sock_filename])
        for _t in range(0, self.timeout, 5):
            if os.path.exists(sock_filename):
                return "unix:path=%s" % sock_filename
            time.sleep(5)
        self._stop_private_conn()
        raise RuntimeError("Failed to start certmonger: Timed out")

    def _stop_private_conn(self):
        if self._proc:
            retcode = self._proc.poll()
            if retcode is not None:
                return
            self._proc.terminate()
            for _t in range(0, self.timeout, 5):
                retcode = self._proc.poll()
                if retcode is not None:
                    return
                time.sleep(5)
            logger.error("Failed to stop certmonger.")

    def __del__(self):
        self._stop_private_conn()

    def __init__(self):
        self._proc = None
        self._bus = None
        try:
            self._bus = dbus.SystemBus()
        except dbus.DBusException as e:
            err_name = e.get_dbus_name()
            if err_name not in ['org.freedesktop.DBus.Error.NoServer',
                                'org.freedesktop.DBus.Error.FileNotFound']:
                logger.error("Failed to connect to certmonger over "
                             "SystemBus: %s", e)
                raise
            try:
                self._private_sock = self._start_private_conn()
                self._bus = dbus.connection.Connection(self._private_sock)
            except dbus.DBusException as e:
                logger.error("Failed to connect to certmonger over "
                             "private socket: %s", e)
                raise
        else:
            try:
                self._bus.get_name_owner(DBUS_CM_NAME)
            except dbus.DBusException:
                try:
                    services.knownservices.certmonger.start()
                except Exception as e:
                    logger.error("Failed to start certmonger: %s", e)
                    raise

                for _t in range(0, self.timeout, 5):
                    try:
                        self._bus.get_name_owner(DBUS_CM_NAME)
                        break
                    except dbus.DBusException:
                        pass
                    time.sleep(5)
                    raise RuntimeError('Failed to start certmonger')

        super(_certmonger, self).__init__(self._bus, None, DBUS_CM_PATH,
                                          DBUS_CM_IF)


def _get_requests(criteria=dict()):
    """
    Get all requests that matches the provided criteria.
    """
    if not isinstance(criteria, dict):
        raise TypeError('"criteria" must be dict.')

    cm = _certmonger()
    requests = []
    requests_paths = []
    if 'nickname' in criteria:
        request_path = cm.obj_if.find_request_by_nickname(criteria['nickname'])
        if request_path:
            requests_paths = [request_path]
    else:
        requests_paths = cm.obj_if.get_requests()

    for request_path in requests_paths:
        request = _cm_dbus_object(cm.bus, cm, request_path, DBUS_CM_REQUEST_IF,
                                  DBUS_CM_IF, True)
        for criterion in criteria:
            if criterion == 'ca-name':
                ca_path = request.obj_if.get_ca()
                ca = _cm_dbus_object(cm.bus, cm, ca_path, DBUS_CM_CA_IF,
                                     DBUS_CM_IF)
                value = ca.obj_if.get_nickname()
            else:
                value = request.prop_if.Get(DBUS_CM_REQUEST_IF, criterion)
            if value != criteria[criterion]:
                break
        else:
            requests.append(request)

    return requests


def _get_request(criteria):
    """
    Find request that matches criteria.
    If 'nickname' is specified other criteria are ignored because 'nickname'
    uniquely identify single request.
    When multiple or none request matches specified criteria RuntimeError is
    raised.
    """
    requests = _get_requests(criteria)
    if len(requests) == 0:
        return None
    elif len(requests) == 1:
        return requests[0]
    else:
        raise RuntimeError("Criteria expected to be met by 1 request, got %s."
                           % len(requests))


def get_request_value(request_id, directive):
    """
    Get property of request.
    """
    try:
        request = _get_request(dict(nickname=request_id))
    except RuntimeError as e:
        logger.error('Failed to get request: %s', e)
        raise
    if request:
        if directive == 'ca-name':
            ca_path = request.obj_if.get_ca()
            ca = _cm_dbus_object(request.bus, request, ca_path, DBUS_CM_CA_IF,
                                 DBUS_CM_IF)
            return ca.obj_if.get_nickname()
        else:
            return request.prop_if.Get(DBUS_CM_REQUEST_IF, directive)
    else:
        return None


def get_request_id(criteria):
    """
    If you don't know the certmonger request_id then try to find it by looking
    through all the requests.

    criteria is a tuple of key/value to search for. The more specific
    the better. An error is raised if multiple request_ids are returned for
    the same criteria.

    None is returned if none of the criteria match.
    """
    try:
        request = _get_request(criteria)
    except RuntimeError as e:
        logger.error('Failed to get request: %s', e)
        raise
    if request:
        return request.prop_if.Get(DBUS_CM_REQUEST_IF, 'nickname')
    else:
        return None


def get_requests_for_dir(dir):
    """
    Return a list containing the request ids for a given NSS database
    directory.
    """
    reqid = []
    criteria = {'cert-storage': 'NSSDB', 'key-storage': 'NSSDB',
                'cert-database': dir, 'key-database': dir, }
    requests = _get_requests(criteria)
    for request in requests:
        reqid.append(request.prop_if.Get(DBUS_CM_REQUEST_IF, 'nickname'))

    return reqid


def add_request_value(request_id, directive, value):
    """
    Add a new directive to a certmonger request file.
    """
    try:
        request = _get_request({'nickname': request_id})
    except RuntimeError as e:
        logger.error('Failed to get request: %s', e)
        raise
    if request:
        request.obj_if.modify({directive: value})


def add_principal(request_id, principal):
    """
    In order for a certmonger request to be renewable it needs a principal.

    When an existing certificate is added via start-tracking it won't have
    a principal.
    """
    add_request_value(request_id, 'template-principal', [principal])


def add_subject(request_id, subject):
    """
    In order for a certmonger request to be renwable it needs the subject
    set in the request file.

    When an existing certificate is added via start-tracking it won't have
    a subject_template set.
    """
    add_request_value(request_id, 'template-subject', subject)


def request_and_wait_for_cert(
        certpath, subject, principal, nickname=None, passwd_fname=None,
        dns=None, ca='IPA', profile=None,
        pre_command=None, post_command=None, storage='NSSDB', perms=None,
        resubmit_timeout=0):
    """Request certificate, wait and possibly resubmit failing requests

    Submit a cert request to certmonger and wait until the request has
    finished.

    With timeout, a failed request is resubmitted. During parallel replica
    installation, a request sometimes fails with CA_REJECTED or
    CA_UNREACHABLE. The error occurs when the master is either busy or some
    information haven't been replicated yet. Even a stuck request can be
    recovered, e.g. when permission and group information have been
    replicated.
    """
    req_id = request_cert(
        certpath, subject, principal, nickname, passwd_fname, dns, ca,
        profile, pre_command, post_command, storage, perms
    )

    deadline = time.time() + resubmit_timeout
    while True:  # until success, timeout, or error
        state = wait_for_request(req_id, api.env.replication_wait_timeout)
        ca_error = get_request_value(req_id, 'ca-error')
        if state == 'MONITORING' and ca_error is None:
            # we got a winner, exiting
            logger.debug("Cert request %s was successful", req_id)
            return req_id

        logger.debug(
            "Cert request %s failed: %s (%s)", req_id, state, ca_error
        )
        if state not in {'CA_REJECTED', 'CA_UNREACHABLE'}:
            # probably unrecoverable error
            logger.debug("Giving up on cert request %s", req_id)
            break
        elif not resubmit_timeout:
            # no resubmit
            break
        elif time.time() > deadline:
            logger.debug("Request %s reached resubmit dead line", req_id)
            break
        else:
            # sleep and resubmit
            logger.debug("Sleep and resubmit cert request %s", req_id)
            time.sleep(10)
            resubmit_request(req_id)

    raise RuntimeError(
        "Certificate issuance failed ({}: {})".format(state, ca_error)
    )


def request_cert(
        certpath, subject, principal, nickname=None, passwd_fname=None,
        dns=None, ca='IPA', profile=None,
        pre_command=None, post_command=None, storage='NSSDB', perms=None):
    """
    Execute certmonger to request a server certificate.

    ``dns``
        A sequence of DNS names to appear in SAN request extension.
    ``perms``
        A tuple of (cert, key) permissions in e.g., (0644,0660)
    """
    if storage == 'FILE':
        certfile, keyfile = certpath
        # This is a workaround for certmonger having different Subject
        # representation with NSS and OpenSSL
        # https://pagure.io/certmonger/issue/62
        subject = str(DN(*reversed(DN(subject))))
    else:
        certfile = certpath
        keyfile = certpath

    cm = _certmonger()
    ca_path = cm.obj_if.find_ca_by_nickname(ca)
    if not ca_path:
        raise RuntimeError('{} CA not found'.format(ca))
    request_parameters = dict(KEY_STORAGE=storage, CERT_STORAGE=storage,
                              CERT_LOCATION=certfile, KEY_LOCATION=keyfile,
                              SUBJECT=subject, CA=ca_path)
    if nickname:
        request_parameters["CERT_NICKNAME"] = nickname
        request_parameters["KEY_NICKNAME"] = nickname
    if principal:
        request_parameters['PRINCIPAL'] = [principal]
    if dns is not None and len(dns) > 0:
        request_parameters['DNS'] = dns
    if passwd_fname:
        request_parameters['KEY_PIN_FILE'] = passwd_fname
    if profile:
        request_parameters['ca-profile'] = profile

    certmonger_cmd_template = paths.CERTMONGER_COMMAND_TEMPLATE
    if pre_command:
        if not os.path.isabs(pre_command):
            pre_command = certmonger_cmd_template % (pre_command)
        request_parameters['cert-presave-command'] = pre_command
    if post_command:
        if not os.path.isabs(post_command):
            post_command = certmonger_cmd_template % (post_command)
        request_parameters['cert-postsave-command'] = post_command

    if perms:
        request_parameters['cert-perms'] = perms[0]
        request_parameters['key-perms'] = perms[1]

    result = cm.obj_if.add_request(request_parameters)
    try:
        if result[0]:
            request = _cm_dbus_object(cm.bus, cm, result[1], DBUS_CM_REQUEST_IF,
                                      DBUS_CM_IF, True)
        else:
            raise RuntimeError('add_request() returned False')
    except Exception as e:
        logger.error('Failed to create a new request: %s', e)
        raise
    return request.obj_if.get_nickname()


def start_tracking(
        certpath, ca='IPA', nickname=None, pin=None, pinfile=None,
        pre_command=None, post_command=None, profile=None, storage="NSSDB"):
    """
    Tell certmonger to track the given certificate in either a file or an NSS
    database. The certificate access can be protected by a password_file.

    This uses the generic certmonger command getcert so we can specify
    a different helper.

    :param certpath:
        The path to an NSS database or a tuple (PEM certificate, private key).
    :param ca:
        Nickanme of the CA for which the given certificate should be tracked.
    :param nickname:
        Nickname of the NSS certificate in ``certpath`` to be tracked.
    :param pin:
        The passphrase for either NSS database containing ``nickname`` or
        for the encrypted key in the ``certpath`` tuple.
    :param pinfile:
        Similar to ``pin`` parameter except this is a path to a file containing
        the required passphrase.
    :param pre_command:
        Specifies a command for certmonger to run before it renews a
        certificate. This command must reside in /usr/lib/ipa/certmonger
        to work with SELinux.
    :param post_command:
        Specifies a command for certmonger to run after it has renewed a
        certificate. This command must reside in /usr/lib/ipa/certmonger
        to work with SELinux.
    :param storage:
        One of "NSSDB" or "FILE", describes whether certmonger should use
        NSS or OpenSSL backend to track the certificate in ``certpath``
    :param profile:
        Which certificate profile should be used.
    :returns: certificate tracking nickname.
    """
    if storage == 'FILE':
        certfile, keyfile = certpath
    else:
        certfile = certpath
        keyfile = certpath

    cm = _certmonger()
    certmonger_cmd_template = paths.CERTMONGER_COMMAND_TEMPLATE

    ca_path = cm.obj_if.find_ca_by_nickname(ca)
    if not ca_path:
        raise RuntimeError('{} CA not found'.format(ca))

    params = {
        'TRACK': True,
        'CERT_STORAGE': storage,
        'KEY_STORAGE': storage,
        'CERT_LOCATION': certfile,
        'KEY_LOCATION': keyfile,
        'CA': ca_path
    }
    if nickname:
        params['CERT_NICKNAME'] = nickname
        params['KEY_NICKNAME'] = nickname
    if pin:
        params['KEY_PIN'] = pin
    if pinfile:
        params['KEY_PIN_FILE'] = os.path.abspath(pinfile)
    if pre_command:
        if not os.path.isabs(pre_command):
            pre_command = certmonger_cmd_template % (pre_command)
        params['cert-presave-command'] = pre_command
    if post_command:
        if not os.path.isabs(post_command):
            post_command = certmonger_cmd_template % (post_command)
        params['cert-postsave-command'] = post_command
    if profile:
        params['ca-profile'] = profile

    result = cm.obj_if.add_request(params)
    try:
        if result[0]:
            request = _cm_dbus_object(cm.bus, cm, result[1], DBUS_CM_REQUEST_IF,
                                      DBUS_CM_IF, True)
        else:
            raise RuntimeError('add_request() returned False')
    except Exception as e:
        logger.error('Failed to add new request: %s', e)
        raise
    return request.prop_if.Get(DBUS_CM_REQUEST_IF, 'nickname')


def stop_tracking(secdir=None, request_id=None, nickname=None, certfile=None):
    """
    Stop tracking the current request using either the request_id or nickname.

    Returns True or False
    """
    if request_id is None and nickname is None and certfile is None:
        raise RuntimeError('One of request_id, nickname and certfile is'
                           ' required.')
    if secdir is not None and certfile is not None:
        raise RuntimeError("Can't specify both secdir and certfile.")

    criteria = dict()
    if secdir:
        criteria['cert-database'] = secdir
    if request_id:
        criteria['nickname'] = request_id
    if nickname:
        criteria['cert-nickname'] = nickname
    if certfile:
        criteria['cert-file'] = certfile
    try:
        request = _get_request(criteria)
    except RuntimeError as e:
        logger.error('Failed to get request: %s', e)
        raise
    if request:
        request.parent.obj_if.remove_request(request.path)


def modify(request_id, ca=None, profile=None, template_v2=None):
    update = {}
    if ca is not None:
        cm = _certmonger()
        update['CA'] = cm.obj_if.find_ca_by_nickname(ca)
    if profile is not None:
        update['template-profile'] = profile
    if template_v2 is not None:
        update['template-ms-certificate-template'] = template_v2

    if len(update) > 0:
        request = _get_request({'nickname': request_id})
        request.obj_if.modify(update)


def resubmit_request(
        request_id,
        ca=None,
        profile=None,
        template_v2=None,
        is_ca=False):
    """
    :param request_id: the certmonger numeric request ID
    :param ca: the nickname for the certmonger CA, e.g. IPA or SelfSign
    :param profile: the profile to use, e.g. SubCA.  For requests using the
                    Dogtag CA, this is the profile to use.  This also causes
                    the Microsoft certificate tempalte name extension to the
                    CSR (for telling AD CS what template to use).
    :param template_v2: Microsoft V2 template specifier extension value.
                        Format: <oid>:<major-version>[:<minor-version>]
    :param is_ca: boolean that if True adds the CA basic constraint
    """
    request = _get_request({'nickname': request_id})
    if request:
        update = {}
        if ca is not None:
            cm = _certmonger()
            update['CA'] = cm.obj_if.find_ca_by_nickname(ca)
        if profile is not None:
            update['template-profile'] = profile
        if template_v2 is not None:
            update['template-ms-certificate-template'] = template_v2
        if is_ca:
            update['template-is-ca'] = True
            update['template-ca-path-length'] = -1  # no path length

        if len(update) > 0:
            request.obj_if.modify(update)
        request.obj_if.resubmit()


def _find_IPA_ca():
    """
    Look through all the certmonger CA files to find the one that
    has id=IPA

    We can use find_request_value because the ca files have the
    same file format.
    """
    cm = _certmonger()
    ca_path = cm.obj_if.find_ca_by_nickname('IPA')
    return _cm_dbus_object(cm.bus, cm, ca_path, DBUS_CM_CA_IF, DBUS_CM_IF, True)


def add_principal_to_cas(principal):
    """
    If the hostname we were passed to use in ipa-client-install doesn't
    match the value of gethostname() then we need to append
    -k host/HOSTNAME@REALM to the ca helper defined for
    /usr/libexec/certmonger/ipa-submit.

    We also need to restore this on uninstall.
    """
    ca = _find_IPA_ca()
    if ca:
        ext_helper = ca.prop_if.Get(DBUS_CM_CA_IF, 'external-helper')
        if ext_helper and '-k' not in shlex.split(ext_helper):
            ext_helper = '%s -k %s' % (ext_helper.strip(), principal)
            ca.prop_if.Set(DBUS_CM_CA_IF, 'external-helper', ext_helper)


def remove_principal_from_cas():
    """
    Remove any -k principal options from the ipa_submit helper.
    """
    ca = _find_IPA_ca()
    if ca:
        ext_helper = ca.prop_if.Get(DBUS_CM_CA_IF, 'external-helper')
        if ext_helper and '-k' in shlex.split(ext_helper):
            ext_helper = shlex.split(ext_helper)[0]
            ca.prop_if.Set(DBUS_CM_CA_IF, 'external-helper', ext_helper)


def modify_ca_helper(ca_name, helper):
    """
    Modify certmonger CA helper.

    Applies the new helper and return the previous configuration.
    """
    bus = dbus.SystemBus()
    obj = bus.get_object('org.fedorahosted.certmonger',
                         '/org/fedorahosted/certmonger')
    iface = dbus.Interface(obj, 'org.fedorahosted.certmonger')
    path = iface.find_ca_by_nickname(ca_name)
    if not path:
        raise RuntimeError("{} is not configured".format(ca_name))
    else:
        ca_obj = bus.get_object('org.fedorahosted.certmonger', path)
        ca_iface = dbus.Interface(ca_obj,
                                  'org.freedesktop.DBus.Properties')
        old_helper = ca_iface.Get('org.fedorahosted.certmonger.ca',
                                  'external-helper')
        ca_iface.Set('org.fedorahosted.certmonger.ca',
                     'external-helper', helper,
                     # Give dogtag extra time to generate cert
                     timeout=CA_DBUS_TIMEOUT)
        return old_helper


def get_pin(token):
    """
    Dogtag stores its NSS pin in a file formatted as token:PIN.

    The caller is expected to handle any exceptions raised.
    """
    with open(paths.PKI_TOMCAT_PASSWORD_CONF, 'r') as f:
        for line in f:
            (tok, pin) = line.split('=', 1)
            if token == tok:
                return pin.strip()
    return None


def check_state(dirs):
    """
    Given a set of directories and nicknames verify that we are no longer
    tracking certificates.

    dirs is a list of directories to test for. We will return a tuple
    of nicknames for any tracked certificates found.

    This can only check for NSS-based certificates.
    """
    reqids = []
    for dir in dirs:
        reqids.extend(get_requests_for_dir(dir))

    return reqids


def wait_for_request(request_id, timeout=120):
    for _i in range(0, timeout, 5):
        state = get_request_value(request_id, 'status')
        logger.debug("certmonger request is in state %r", state)
        if state in ('CA_REJECTED', 'CA_UNREACHABLE', 'CA_UNCONFIGURED',
                     'NEED_GUIDANCE', 'NEED_CA', 'MONITORING'):
            break
        time.sleep(5)
    else:
        raise RuntimeError("request timed out")

    return state
