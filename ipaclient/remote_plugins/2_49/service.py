#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

# pylint: disable=unused-import
import six

from . import Command, Method, Object
from ipalib import api, parameters, output
from ipalib.parameters import DefaultFrom
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

if six.PY3:
    unicode = str

__doc__ = _("""
Services

A IPA service represents a service that runs on a host. The IPA service
record can store a Kerberos principal, an SSL certificate, or both.

An IPA service can be managed directly from a machine, provided that
machine has been given the correct permission. This is true even for
machines other than the one the service is associated with. For example,
requesting an SSL certificate using the host service principal credentials
of the host. To manage a service using host credentials you need to
kinit as the host:

 # kinit -kt /etc/krb5.keytab host/ipa.example.com@EXAMPLE.COM

Adding an IPA service allows the associated service to request an SSL
certificate or keytab, but this is performed as a separate step; they
are not produced as a result of adding the service.

Only the public aspect of a certificate is stored in a service record;
the private key is not stored.

EXAMPLES:

 Add a new IPA service:
   ipa service-add HTTP/web.example.com

 Allow a host to manage an IPA service certificate:
   ipa service-add-host --hosts=web.example.com HTTP/web.example.com
   ipa role-add-member --hosts=web.example.com certadmin

 Override a default list of supported PAC types for the service:
   ipa service-mod HTTP/web.example.com --pac-type=MS-PAC

 Delete an IPA service:
   ipa service-del HTTP/web.example.com

 Find all IPA services associated with a host:
   ipa service-find web.example.com

 Find all HTTP services:
   ipa service-find HTTP

 Disable the service Kerberos key and SSL certificate:
   ipa service-disable HTTP/web.example.com

 Request a certificate for an IPA service:
   ipa cert-request --principal=HTTP/web.example.com example.csr

 Generate and retrieve a keytab for an IPA service:
   ipa-getkeytab -s ipa.example.com -p HTTP/web.example.com -k /etc/httpd/httpd.keytab
""")

register = Registry()


@register()
class service(Object):
    takes_params = (
        parameters.Str(
            'krbprincipalname',
            primary_key=True,
            label=_(u'Principal'),
            doc=_(u'Service principal'),
        ),
        parameters.Bytes(
            'usercertificate',
            required=False,
            label=_(u'Certificate'),
            doc=_(u'Base-64 encoded server certificate'),
        ),
        parameters.Str(
            'ipakrbauthzdata',
            required=False,
            multivalue=True,
            label=_(u'PAC type'),
            doc=_(u"Override default list of supported PAC types. Use 'NONE' to disable PAC support for this service"),
        ),
        parameters.Flag(
            'has_keytab',
            label=_(u'Keytab'),
        ),
        parameters.Str(
            'managedby_host',
            label=_(u'Managed by'),
        ),
    )


@register()
class service_add(Method):
    __doc__ = _("Add a new IPA new service.")

    takes_args = (
        parameters.Str(
            'krbprincipalname',
            cli_name='principal',
            label=_(u'Principal'),
            doc=_(u'Service principal'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Bytes(
            'usercertificate',
            required=False,
            cli_name='certificate',
            label=_(u'Certificate'),
            doc=_(u'Base-64 encoded server certificate'),
        ),
        parameters.Str(
            'ipakrbauthzdata',
            required=False,
            multivalue=True,
            cli_name='pac_type',
            cli_metavar="['MS-PAC', 'PAD', 'NONE']",
            label=_(u'PAC type'),
            doc=_(u"Override default list of supported PAC types. Use 'NONE' to disable PAC support for this service"),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(u'Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(u'Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'force',
            label=_(u'Force'),
            doc=_(u'force principal name even if not in DNS'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class service_add_host(Method):
    __doc__ = _("Add hosts that can manage this service.")

    takes_args = (
        parameters.Str(
            'krbprincipalname',
            cli_name='principal',
            label=_(u'Principal'),
            doc=_(u'Service principal'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_(u'member host'),
            doc=_(u'comma-separated list of hosts to add'),
            alwaysask=True,
        ),
    )
    has_output = (
        output.Entry(
            'result',
        ),
        output.Output(
            'failed',
            dict,
            doc=_(u'Members that could not be added'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of members added'),
        ),
    )


@register()
class service_del(Method):
    __doc__ = _("Delete an IPA service.")

    takes_args = (
        parameters.Str(
            'krbprincipalname',
            multivalue=True,
            cli_name='principal',
            label=_(u'Principal'),
            doc=_(u'Service principal'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_(u"Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            dict,
            doc=_(u'List of deletions that failed'),
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class service_disable(Method):
    __doc__ = _("Disable the Kerberos key and SSL certificate of a service.")

    takes_args = (
        parameters.Str(
            'krbprincipalname',
            cli_name='principal',
            label=_(u'Principal'),
            doc=_(u'Service principal'),
            no_convert=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_(u'True means the operation was successful'),
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class service_find(Method):
    __doc__ = _("Search for IPA services.")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_(u'A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'krbprincipalname',
            required=False,
            cli_name='principal',
            label=_(u'Principal'),
            doc=_(u'Service principal'),
            no_convert=True,
        ),
        parameters.Str(
            'ipakrbauthzdata',
            required=False,
            multivalue=True,
            cli_name='pac_type',
            cli_metavar="['MS-PAC', 'PAD', 'NONE']",
            label=_(u'PAC type'),
            doc=_(u"Override default list of supported PAC types. Use 'NONE' to disable PAC support for this service"),
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_(u'Time Limit'),
            doc=_(u'Time limit of search in seconds'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_(u'Size Limit'),
            doc=_(u'Maximum number of entries returned'),
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_(u'Primary key only'),
            doc=_(u'Results should contain primary key attribute only ("principal")'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'man_by_host',
            required=False,
            multivalue=True,
            cli_name='man_by_hosts',
            label=_(u'host'),
            doc=_(u'Search for services with these managed by hosts.'),
        ),
        parameters.Str(
            'not_man_by_host',
            required=False,
            multivalue=True,
            cli_name='not_man_by_hosts',
            label=_(u'host'),
            doc=_(u'Search for services without these managed by hosts.'),
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.ListOfEntries(
            'result',
        ),
        output.Output(
            'count',
            int,
            doc=_(u'Number of entries returned'),
        ),
        output.Output(
            'truncated',
            bool,
            doc=_(u'True if not all results were returned'),
        ),
    )


@register()
class service_mod(Method):
    __doc__ = _("Modify an existing IPA service.")

    takes_args = (
        parameters.Str(
            'krbprincipalname',
            cli_name='principal',
            label=_(u'Principal'),
            doc=_(u'Service principal'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Bytes(
            'usercertificate',
            required=False,
            cli_name='certificate',
            label=_(u'Certificate'),
            doc=_(u'Base-64 encoded server certificate'),
        ),
        parameters.Str(
            'ipakrbauthzdata',
            required=False,
            multivalue=True,
            cli_name='pac_type',
            cli_metavar="['MS-PAC', 'PAD', 'NONE']",
            label=_(u'PAC type'),
            doc=_(u"Override default list of supported PAC types. Use 'NONE' to disable PAC support for this service"),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(u'Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(u'Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'delattr',
            required=False,
            multivalue=True,
            doc=_(u'Delete an attribute/value pair. The option will be evaluated\nlast, after all sets and adds.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'rights',
            label=_(u'Rights'),
            doc=_(u'Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class service_remove_host(Method):
    __doc__ = _("Remove hosts that can manage this service.")

    takes_args = (
        parameters.Str(
            'krbprincipalname',
            cli_name='principal',
            label=_(u'Principal'),
            doc=_(u'Service principal'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'host',
            required=False,
            multivalue=True,
            cli_name='hosts',
            label=_(u'member host'),
            doc=_(u'comma-separated list of hosts to remove'),
            alwaysask=True,
        ),
    )
    has_output = (
        output.Entry(
            'result',
        ),
        output.Output(
            'failed',
            dict,
            doc=_(u'Members that could not be removed'),
        ),
        output.Output(
            'completed',
            int,
            doc=_(u'Number of members removed'),
        ),
    )


@register()
class service_show(Method):
    __doc__ = _("Display information about an IPA service.")

    takes_args = (
        parameters.Str(
            'krbprincipalname',
            cli_name='principal',
            label=_(u'Principal'),
            doc=_(u'Service principal'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'rights',
            label=_(u'Rights'),
            doc=_(u'Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'out',
            required=False,
            doc=_(u'file to store certificate in'),
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.Output(
            'value',
            unicode,
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )
