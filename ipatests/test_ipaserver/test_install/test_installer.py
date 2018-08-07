#
# Copyright (C) 2018  FreeIPA Contributors.  See COPYING for license
#
from __future__ import absolute_import

import six

from abc import ABCMeta, abstractproperty
from collections import namedtuple
import itertools
import tempfile

from ipatests.util import assert_equal
from ipaserver.install.ipa_replica_install import ReplicaInstall

Keyval = namedtuple('Keyval', ['option', 'value'])


class InstallerTestBase(six.with_metaclass(ABCMeta, object)):
    OPTS_DICT = {}

    # don't allow creating classes with tested_cls unspecified
    @abstractproperty
    def tested_cls(self):
        return None

    def setup_class(self):
        """Initializes the tested class so that it can be used later on
        """
        self.tested_cls.make_parser()
        assert \
            getattr(self.tested_cls, 'option_parser', False), \
            ("Unable to generate option parser for {}"
             .format(self.tested_cls.__name__))

        self._populate_opts_dict()

    @classmethod
    def _populate_opts_dict(cls):
        """Populate the class-owned OPTS_DICT with available options
        """
        if not getattr(cls.tested_cls, 'option_parser', False):
            raise RuntimeError("You need to create the parser of the tested "
                               "class first.")

        # add all options from the option groups
        # pylint: disable=no-member
        for opt_group in cls.tested_cls.option_parser.option_groups:
            for opt in opt_group.option_list:
                cls.OPTS_DICT[opt.dest] = opt._short_opts + opt._long_opts
        # add options outside groups
        for opt in cls.tested_cls.option_parser.option_list:
            cls.OPTS_DICT[opt.dest] = opt._short_opts + opt._long_opts

    def parse_cli_args(self, args):
        """Parses the CLI-like arguments and returns them in python objects

        :param args: A string representing the CLI arguments

        :returns: dictionary and a list of parsed options and arguments
        """
        return self.tested_cls.option_parser.parse_args(args.split())

    def get_installer_instance(self, args):
        """Get instance of the configuring class
        """
        parsed_opts = self.parse_cli_args(args)
        cls = self.tested_cls.get_command_class(*parsed_opts)
        command_instance = cls(*parsed_opts)
        return command_instance.init_configurator()

    def combine_options(self, *args):
        return ' '.join(args)

    def all_option_permutations(self, *key_val):
        """Gets all short-option/long-option permutations

        :param key_val: Keyval tuples specifying the options to grab from
                        OPTS_DICT along with the values to assign to them

        :returns: list or list of lists of all permutations
        """
        if len(key_val) == 0:
            return []
        elif len(key_val) == 1:
            val = key_val[0].value
            return ['{opt} {val}'.format(opt=opt, val=val)
                    for opt in self.OPTS_DICT[key_val[0].option]]

        permutation_lists = [self.OPTS_DICT[k.option] for k in key_val]
        permutation = itertools.product(*permutation_lists)

        ret = []
        for p in permutation:
            opt_vals = []
            for i, kv in enumerate(key_val):
                opt_vals.append(
                    '{opt} {val}'.format(
                        opt=p[i], val=kv.value))
            ret.append(opt_vals)
        return ret


class TestReplicaInstaller(InstallerTestBase):
    tested_cls = ReplicaInstall

    PASSWORD = Keyval("auto_password",
                      "c3ca2246bcf309d1b636581ce429da3522a8aec4")
    ADMIN_PASSWORD = Keyval("admin_password", "milan_je_buh123")
    PRINCIPAL = Keyval("principal", "ubercool_guy")

    def test_password_option_DL1(self):
        # OTP enrollment
        for passwd_opt in self.all_option_permutations(self.PASSWORD):
            ic = self.get_installer_instance(passwd_opt)
            assert_equal(ic.password, self.PASSWORD.value)

        # admin principal enrollment
        for adm_password_opt in (
            self.all_option_permutations(self.ADMIN_PASSWORD)
        ):
            ic = self.get_installer_instance(adm_password_opt)
            assert_equal(ic.password, None)
            assert_equal(ic.admin_password, self.ADMIN_PASSWORD.value)

        # if principal is set, we interpret --password as that principal's
        for passwd_opt, principal_opt in (
            self.all_option_permutations(self.PASSWORD, self.PRINCIPAL)
        ):
            ic = self.get_installer_instance(
                self.combine_options(passwd_opt, principal_opt))
            assert_equal(ic.password, None)
            assert_equal(ic.principal, self.PRINCIPAL.value)
            assert_equal(ic.admin_password, self.PASSWORD.value)

        # if principal is set, we interpret --password as that principal's
        # unless admin-password is also specified, in which case it's once
        # again an OTP
        for adm_password_opt, passwd_opt, principal_opt in (
            self.all_option_permutations(
                self.ADMIN_PASSWORD, self.PASSWORD, self.PRINCIPAL)
        ):
            ic = self.get_installer_instance(
                self.combine_options(
                    adm_password_opt, passwd_opt, principal_opt))
            assert_equal(ic.password, self.PASSWORD.value)
            assert_equal(ic.principal, self.PRINCIPAL.value)
            assert_equal(ic.admin_password, self.ADMIN_PASSWORD.value)
