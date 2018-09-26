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


class BaseTracker:
    _override_me_msg = "This method needs to be overridden in a subclass"

    def __init__(self, default_version=None):
        self.api = api
        self.default_version = default_version or API_VERSION
        self._dn = None
        self.attrs = {}

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

    def run_command(self, name, *args, **options):
        """Run the given IPA command

        Logs the command using print for easier debugging
        """
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
        """Make fixture for the tracker

        Don't do anything here.
        """
        return self


class RetrievalTracker(BaseTracker):
    retrieve_keys = None
    retrieve_all_keys = None

    def make_retrieve_command(self, all=False, raw=False):
        """Make function that retrieves the entry using ${CMD}_show"""
        raise NotImplementedError(self._override_me_msg)

    def check_retrieve(self, result, all=False, raw=False):
        """Check the plugin's `show` command result"""
        raise NotImplementedError(self._override_me_msg)

    def retrieve(self, all=False, raw=False):
        """Helper function to retrieve an entry and check the result"""
        command = self.make_retrieve_command(all=all, raw=raw)
        result = command()
        self.check_retrieve(result, all=all, raw=raw)


class SearchTracker(BaseTracker):

    def make_find_command(self, *args, **kwargs):
        """Make function that finds the entry using ${CMD}_find

        Note that the name (or other search terms) needs to be specified
        in arguments.
        """
        raise NotImplementedError(self._override_me_msg)

    def check_find(self, result, all=False, raw=False):
        """Check the plugin's `find` command result"""
        raise NotImplementedError(self._override_me_msg)

    def find(self, all=False, raw=False):
        """Helper function to search for this hosts and check the result"""
        command = self.make_find_command(self.name, all=all, raw=raw)
        result = command()
        self.check_find(result, all=all, raw=raw)


class ModificationTracker(BaseTracker):
    update_keys = None
    singlevalue_keys = None

    def make_update_command(self, updates):
        """Make function that modifies the entry using ${CMD}_mod"""
        raise NotImplementedError(self._override_me_msg)

    def check_update(self, result, extra_keys=()):
        """Check the plugin's `mod` command result"""
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

        self.check_update(
            result,
            extra_keys=set(updates.keys()) | set(expected_updates.keys())
        )


class CreationTracker(BaseTracker):
    create_keys = None

    def __init__(self, default_version=None):
        super(CreationTracker, self).__init__(default_version=default_version)
        self.exists = False

    def make_create_command(self):
        """Make function that creates the plugin entry object."""
        raise NotImplementedError(self._override_me_msg)

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

    def create(self):
        """Helper function to create an entry and check the result"""
        self.track_create()
        command = self.make_create_command()
        result = command()
        self.check_create(result)

    def ensure_exists(self):
        """If the entry does not exist (according to tracker state), create it
        """
        if not self.exists:
            self.create()

    def make_delete_command(self):
        """Make function that deletes the plugin entry object."""
        raise NotImplementedError(self._override_me_msg)

    def track_delete(self):
        """Update expected state for host deletion"""
        self.exists = False
        self.attrs = {}

    def check_delete(self, result):
        """Check plugin's `del` command result"""
        raise NotImplementedError(self._override_me_msg)

    def delete(self):
        """Helper function to delete a host and check the result"""
        self.track_delete()
        command = self.make_delete_command()
        result = command()
        self.check_delete(result)

    def ensure_missing(self):
        """If the entry exists (according to tracker state), delete it
        """
        if self.exists:
            self.delete()

    def make_fixture(self, request):
        """Make a pytest fixture for this tracker

        The fixture ensures the plugin entry does not exist before
        and after the tests that use it.
        """
        del_command = self.make_delete_command()
        try:
            del_command()
        except errors.NotFound:
            pass

        def cleanup():
            existed = self.exists
            try:
                del_command()
            except errors.NotFound:
                if existed:
                    raise
            self.exists = False

        request.addfinalizer(cleanup)

        return super(CreationTracker, self).make_fixture(request)


class EnableTracker(BaseTracker):
    def __init__(self, default_version=None, enabled=True):
        super(EnableTracker, self).__init__(default_version=default_version)
        self.original_enabled = enabled
        self.enabled = enabled

    def make_enable_command(self):
        """Make function that enables the entry using ${CMD}_enable"""
        raise NotImplementedError(self._override_me_msg)

    def enable(self):
        self.enabled = True
        command = self.make_enable_command()
        result = command()
        self.check_enable(result)

    def check_enable(self, result):
        """Check the plugin's `enable` command result"""
        raise NotImplementedError(self._override_me_msg)

    def make_disable_command(self):
        """Make function that disables the entry using ${CMD}_disable"""
        raise NotImplementedError(self._override_me_msg)

    def disable(self):
        self.enabled = False
        command = self.make_disable_command()
        result = command()
        self.check_disable(result)

    def check_disable(self, result):
        """Check the plugin's `disable` command result"""
        raise NotImplementedError(self._override_me_msg)

    def make_fixture(self, request):
        """Make a pytest fixture for this tracker

        The fixture ensures the plugin entry is in the same state
        (enabled/disabled) after the test as it was before it.
        """
        def cleanup():
            if self.original_enabled != self.enabled:
                if self.original_enabled:
                    command = self.make_enable_command()
                else:
                    command = self.make_disable_command()
                command()

        request.addfinalizer(cleanup)

        return super(EnableTracker, self).make_fixture(request)


class ConfigurationTracker(RetrievalTracker, ModificationTracker):
    def make_fixture(self, request):
        """Make a pytest fixture for this tracker

        Make sure that the state of entry in the end is the same
        it was in the begining.
        """
        retrieve = self.make_retrieve_command(all=True)
        res = retrieve()['result']
        original_state = {}
        for k, v in res.items():
            if k in self.update_keys:
                original_state[k] = v[0] if k in self.singlevalue_keys else v

        def revert():
            update = self.make_update_command(original_state)
            try:
                update()
            except errors.EmptyModlist:
                # ignore no change
                pass

        request.addfinalizer(revert)

        return super(ConfigurationTracker, self).make_fixture(request)


class Tracker(RetrievalTracker, SearchTracker, ModificationTracker,
              CreationTracker):
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
    pass
