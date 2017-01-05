#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
Implements a base class to track changes to an LDAP object.
"""
from __future__ import print_function

import functools

from ipalib import api, errors
from ipapython.dn import DN
from ipapython.version import API_VERSION
from ipatests.util import Fuzzy

import subprocess
import os
import re
import pytest
from ipalib.cli import to_cli


class Tracker(object):
    """Wraps and tracks modifications to a plugin LDAP entry object

    Stores a copy of state of a plugin entry object and allows checking that
    the state in the database is the same as expected.
    This allows creating independent tests: the individual tests check
    that the relevant changes have been made. At the same time
    the entry doesn't need to be recreated and cleaned up for each test.

    Two attributes are used for tracking: ``exists`` (true if the entry is
    supposed to exist) and ``attrs`` (a dict of LDAP attributes that are
    expected to be returned from IPA commands).

    For commonly used operations, there is a helper method, e.g.
    ``create``, ``update``, or ``find``, that does these steps:

    * ensure the entry exists (or does not exist, for "create")
    * store the expected modifications
    * get the IPA command to run, and run it
    * check that the result matches the expected state

    Tests that require customization of these steps are expected to do them
    manually, using lower-level methods.
    Especially the first step (ensure the entry exists) is important for
    achieving independent tests.

    The Tracker object also stores information about the entry, e.g.
    ``dn``, ``rdn`` and ``name`` which is derived from DN property.

    To use this class, the programer must subclass it and provide the
    implementation of following methods:

     * make_*_command   -- implementing the API call for particular plugin
                           and operation (add, delete, ...)
                           These methods should use the make_command method
     * check_* commands -- an assertion for a plugin command (CRUD)
     * track_create     -- to make an internal representation of the
                           entry

    Apart from overriding these methods, the subclass must provide the
    distinguished name of the entry in `self.dn` property.

    It is also required to override the class variables defining the sets
    of ldap attributes/keys for these operations specific to the plugin
    being implemented. Take the host plugin test for an example.

    The implementation of these methods is not strictly enforced.
    A missing method will cause a NotImplementedError during runtime
    as a result.
    """
    retrieve_keys = None
    retrieve_all_keys = None
    create_keys = None
    update_keys = None

    # Mapping of API style options and output to CLI style options and output
    mapping_options = {
        'addattr': 'addattr',
        'all': 'all',
        'setattr': 'setattr',
        'raw': 'raw',
        'version': 'version',
        }
    mapping_output = {}

    # Indicator for skipping errors that are not handled during CLI testing
    skip_error = False

    # List of options that do not take value
    novalue = ['all', 'raw']

    _override_me_msg = "This method needs to be overridden in a subclass"

    def __init__(self, default_version=None):
        self.api = api
        self.default_version = default_version or API_VERSION
        self._dn = None
        self.attrs = {}

        self.exists = False

    @property
    def dn(self):
        """A property containing the distinguished name of the entry."""
        if not self._dn:
            raise ValueError('The DN must be set in the init method.')
        return self._dn

    @dn.setter
    def dn(self, value):
        if not (isinstance(value, DN) or isinstance(value, Fuzzy)):
            raise ValueError('The value must be an instance of DN or Fuzzy.')
        self._dn = value

    @property
    def rdn(self):
        return self.dn[0]

    @property
    def name(self):
        """Property holding the name of the entry in LDAP.

        This property is computed in runtime.
        """
        return self.rdn.value

    def filter_attrs(self, keys):
        """Return a dict of expected attrs, filtered by the given keys"""
        if not self.attrs:
            raise RuntimeError('The tracker instance has no attributes.')
        return {k: v for k, v in self.attrs.items() if k in keys}

    def cli_command(self, name, *args, **options):
        """
        Prepare CLI command for testing
        """
        cmd = "ipa {}".format(to_cli(name))
        for item in args:
            cmd += " {}".format(item)
        for key in options:
            if key in self.novalue and options[key]:
                cmd += " --{0}".format(self.mapping_options[key])
            elif key in self.novalue and not options[key]:
                continue
            else:
                if type(options[key]) is unicode and ' ' in options[key]:
                    options[key] = '"{}"'.format(options[key])
                cmd += " --{0}={1}".format(
                    self.mapping_options[key], options[key])
        return cmd

    def cli_output(self, result):
        """
        Reformats text output to dictionary to be compared with expected values
        """
        result = result.split("\n")
        modresult = {'result': {}, 'summary': None}
        for line in result:
            if re.match("^-*$", line):
                continue
            elif ':' in line:
                key = self.mapping_output[line.split(':')[0].strip()]
                value = line.split(':')[1].strip()
                if value == 'True':
                    value = True
                elif value == 'False':
                    value = False
                else:
                    value = unicode(value)

                if key in modresult['result']:
                    modresult['result'][key].append(value)
                elif value is True or value is False:
                    modresult['result'][key] = value
                else:
                    modresult['result'][key] = [value]
            else:
                modresult['summary'] = unicode(line)

        return modresult

    def cli_mode(self):
        """ Returns True if CLI testing mode is on, False otherwise """
        return pytest.config.getoption('cli')

    def run_command(self, name, *args, **options):
        """Run the given IPA command

        Logs the command using print for easier debugging

        Run in CLI testing mode if executed with --cli option,
        run in API mode otherwise.
        """
        if self.cli_mode():
            cmd = self.cli_command(name, *args, **options)
            subprocess_env = os.environ.copy()
            del subprocess_env["IPA_UNIT_TEST_MODE"]

            cmd = subprocess.Popen(cmd, shell=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   env=subprocess_env)
            output = cmd.communicate()
            result, error = output

            if error and not self.skip_error:
                # if stderr is not empty and the error is not supposed to be
                # ignored, raise error
                raise(errors.ExecutionError(message=unicode(error[12:-1])))
            elif self.skip_error:
                self.skip_error = False

            result = self.cli_output(result)

        else:
            cmd = self.api.Command[name]

            options.setdefault('version', self.default_version)

            args_repr = ', '.join(
                [repr(a) for a in args] +
                ['%s=%r' % item for item in list(options.items())])
            try:
                result = cmd(*args, **options)
            except Exception as e:
                print('Ran command: %s(%s): %s: %s' % (cmd, args_repr,
                                                       type(e).__name__, e))
                raise
            else:
                print('Ran command: %s(%s): OK' % (cmd, args_repr))

        return result

    def make_command(self, name, *args, **options):
        """Make a functools.partial function to run the given command"""
        return functools.partial(self.run_command, name, *args, **options)

    def make_fixture(self, request):
        """Make a pytest fixture for this tracker

        The fixture ensures the plugin entry does not exist before
        and after the tests that use it.
        """
        del_command = self.make_delete_command()
        try:
            self.skip_error = True
            del_command()
        except errors.NotFound:
            pass

        def cleanup():
            existed = self.exists
            try:
                self.skip_error = True
                del_command()
            except errors.NotFound:
                if existed:
                    raise
            self.exists = False

        request.addfinalizer(cleanup)

        return self

    def ensure_exists(self):
        """If the entry does not exist (according to tracker state), create it
        """
        if not self.exists:
            self.create()

    def ensure_missing(self):
        """If the entry exists (according to tracker state), delete it
        """
        if self.exists:
            self.delete()

    def make_create_command(self):
        """Make function that creates the plugin entry object."""
        raise NotImplementedError(self._override_me_msg)

    def make_delete_command(self):
        """Make function that deletes the plugin entry object."""
        raise NotImplementedError(self._override_me_msg)

    def make_retrieve_command(self, all=False, raw=False):
        """Make function that retrieves the entry using ${CMD}_show"""
        raise NotImplementedError(self._override_me_msg)

    def make_find_command(self, *args, **kwargs):
        """Make function that finds the entry using ${CMD}_find

        Note that the name (or other search terms) needs to be specified
        in arguments.
        """
        raise NotImplementedError(self._override_me_msg)

    def make_update_command(self, updates):
        """Make function that modifies the entry using ${CMD}_mod"""
        raise NotImplementedError(self._override_me_msg)

    def create(self):
        """Helper function to create an entry and check the result"""
        self.track_create()
        command = self.make_create_command()
        result = command()
        self.check_create(result)

    def track_create(self):
        """Update expected state for host creation

        The method should look similar to the following
        example of host plugin.

        self.attrs = dict(
            dn=self.dn,
            fqdn=[self.fqdn],
            description=[self.description],
            ... # all required attributes
        )
        self.exists = True
        """
        raise NotImplementedError(self._override_me_msg)

    def check_create(self, result):
        """Check plugin's add command result"""
        raise NotImplementedError(self._override_me_msg)

    def delete(self):
        """Helper function to delete a host and check the result"""
        self.track_delete()
        command = self.make_delete_command()
        result = command()
        self.check_delete(result)

    def track_delete(self):
        """Update expected state for host deletion"""
        self.exists = False
        self.attrs = {}

    def check_delete(self, result):
        """Check plugin's `del` command result"""
        raise NotImplementedError(self._override_me_msg)

    def retrieve(self, all=False, raw=False):
        """Helper function to retrieve an entry and check the result"""
        command = self.make_retrieve_command(all=all, raw=raw)
        result = command()
        self.check_retrieve(result, all=all, raw=raw)

    def check_retrieve(self, result, all=False, raw=False):
        """Check the plugin's `show` command result"""
        raise NotImplementedError(self._override_me_msg)

    def find(self, all=False, raw=False):
        """Helper function to search for this hosts and check the result"""
        command = self.make_find_command(self.name, all=all, raw=raw)
        result = command()
        self.check_find(result, all=all, raw=raw)

    def check_find(self, result, all=False, raw=False):
        """Check the plugin's `find` command result"""
        raise NotImplementedError(self._override_me_msg)

    def update(self, updates, expected_updates=None):
        """Helper function to update this hosts and check the result

        The ``updates`` are used as options to the *_mod command,
        and the self.attrs is updated with this dict.
        Additionally, self.attrs is updated with ``expected_updates``.
        """
        if expected_updates is None:
            expected_updates = {}

        command = self.make_update_command(updates)
        result = command()
        self.attrs.update(updates)
        self.attrs.update(expected_updates)
        for key, value in self.attrs.items():
            if value is None:
                del self.attrs[key]

        self.check_update(result, extra_keys=set(updates.keys()) |
                                             set(expected_updates.keys()))

    def check_update(self, result, extra_keys=()):
        """Check the plugin's `mod` command result"""
        raise NotImplementedError(self._override_me_msg)
