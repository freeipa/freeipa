#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#


from . import Method, Object
from ipalib import parameters, output
from ipalib.plugable import Registry
from ipalib.text import _

__doc__ = _("""
Realm domains

Manage the list of domains associated with IPA realm.

EXAMPLES:

 Display the current list of realm domains:
   ipa realmdomains-show

 Replace the list of realm domains:
   ipa realmdomains-mod --domain=example.com
   ipa realmdomains-mod --domain={example1.com,example2.com,example3.com}

 Add a domain to the list of realm domains:
   ipa realmdomains-mod --add-domain=newdomain.com

 Delete a domain from the list of realm domains:
   ipa realmdomains-mod --del-domain=olddomain.com
""")

register = Registry()


@register()
class realmdomains(Object):
    takes_params = (
        parameters.Str(
            'associateddomain',
            multivalue=True,
            label=_('Domain'),
        ),
        parameters.Str(
            'add_domain',
            required=False,
            label=_('Add domain'),
        ),
        parameters.Str(
            'del_domain',
            required=False,
            label=_('Delete domain'),
        ),
    )


@register()
class realmdomains_mod(Method):
    __doc__ = _("Modify realm domains.")

    takes_options = (
        parameters.Str(
            'associateddomain',
            required=False,
            multivalue=True,
            cli_name='domain',
            label=_('Domain'),
            no_convert=True,
        ),
        parameters.Str(
            'add_domain',
            required=False,
            label=_('Add domain'),
            no_convert=True,
        ),
        parameters.Str(
            'del_domain',
            required=False,
            label=_('Delete domain'),
            no_convert=True,
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(
                'Set an attribute to a name/value pair. '
                'Format is attr=value.\nFor multi-valued attributes, '
                'the command replaces the values already present.'
            ),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(
                'Add an attribute/value pair. Format is attr=value. '
                'The attribute\nmust be part of the schema.'
            ),
            exclude=('webui',),
        ),
        parameters.Str(
            'delattr',
            required=False,
            multivalue=True,
            doc=_(
                'Delete an attribute/value pair. '
                'The option will be evaluated\nlast, after all sets and adds.'
            ),
            exclude=('webui',),
        ),
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_(
                'Display the access rights of this entry (requires --all). '
                'See ipa man page for details.'
            ),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'force',
            label=_('Force'),
            doc=_('Force adding domain even if not in DNS'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class realmdomains_show(Method):
    __doc__ = _("Display the list of realm domains.")

    takes_options = (
        parameters.Flag(
            'rights',
            label=_('Rights'),
            doc=_(
                'Display the access rights of this entry (requires --all). '
                'See ipa man page for details.'
            ),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(
                'Retrieve and print all attributes from the server. '
                'Affects command output.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(
                'Print entries as stored on the server. '
                'Only affects output format.'
            ),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (str, type(None)),
            doc=_('User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_("The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )
