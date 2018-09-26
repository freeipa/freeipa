#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
"""kerberos_aliases

The module implements a mixin class that provides an interface
to the Kerberos Aliases feature of freeIPA.

In order to use the class the child class must implement the
`_make_add_alias_cmd` and `_make_remove_alias_cmd` methods that
are different for each entity type.

The KerberosAliasMixin class then provides the implementation
of the manipulation of the kerberos alias in general.

It is up to the child class or the user to validate the
alias being added for a particular type of an entry.
"""


class KerberosAliasError(Exception):
    pass


class KerberosAliasMixin:
    """KerberosAliasMixin"""

    def _make_add_alias_cmd(self):
        raise NotImplementedError("The _make_add_alias_cmd method "
                                  "is not implemented.")

    def _make_remove_alias_cmd(self):
        raise NotImplementedError("The _make_remove_alias_cmd method "
                                  "is not implemented.")

    def _check_for_krbprincipalname_attr(self):
        # Check if the tracker has a principal name
        # Each compatible entry has at least one kerberos
        # principal matching the canonical principal name
        principals = self.attrs.get('krbprincipalname')
        if self.exists:
            if not principals:
                raise KerberosAliasError(
                    "{} doesn't have krbprincipalname attribute"
                    .format(self.__class__.__name__))
        else:
            raise ValueError("The entry {} doesn't seem to exist"
                             .format(self.name))

    def _normalize_principal_list(self, principal_list):
        """Normalize the list for further manipulation."""
        if not isinstance(principal_list, (list, tuple)):
            return [principal_list]
        else:
            return principal_list

    def _normalize_principal_value(self, principal):
        """Normalize principal value by appending the realm string."""
        return u'@'.join((principal, self.api.env.realm))

    def add_principal(self, principal_list, **options):
        """Add kerberos principal alias to the entity.

        Add principal alias to the underlying entry and
        update the attributes in the Tracker instance.
        """
        self._check_for_krbprincipalname_attr()

        principal_list = self._normalize_principal_list(principal_list)

        cmd = self._make_add_alias_cmd()
        cmd(principal_list, **options)

        tracker_principals = self.attrs.get('krbprincipalname')
        tracker_principals.extend((
            self._normalize_principal_value(item) for item in principal_list))

    def remove_principal(self, principal_list, **options):
        """Remove kerberos principal alias from an entry.

        Remove principal alias from the tracked entry.
        """
        self._check_for_krbprincipalname_attr()

        principal_list = self._normalize_principal_list(principal_list)

        cmd = self._make_remove_alias_cmd()
        cmd(principal_list, **options)

        # Make a copy of the list so the tracker instance is not modified
        # if there is an error deleting the aliases
        # This can happen when deleting multiple aliases and at least
        # one of them doesn't exist, raising ValueError
        tracker_principals = self.attrs.get('krbprincipalname')[:]

        for item in principal_list:
            tracker_principals.remove(self._normalize_principal_value(item))

        self.attrs['krbprincipalname'] = tracker_principals
