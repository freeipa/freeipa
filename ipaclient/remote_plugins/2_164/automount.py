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
Automount

Stores automount(8) configuration for autofs(8) in IPA.

The base of an automount configuration is the configuration file auto.master.
This is also the base location in IPA. Multiple auto.master configurations
can be stored in separate locations. A location is implementation-specific
with the default being a location named 'default'. For example, you can have
locations by geographic region, by floor, by type, etc.

Automount has three basic object types: locations, maps and keys.

A location defines a set of maps anchored in auto.master. This allows you
to store multiple automount configurations. A location in itself isn't
very interesting, it is just a point to start a new automount map.

A map is roughly equivalent to a discrete automount file and provides
storage for keys.

A key is a mount point associated with a map.

When a new location is created, two maps are automatically created for
it: auto.master and auto.direct. auto.master is the root map for all
automount maps for the location. auto.direct is the default map for
direct mounts and is mounted on /-.

An automount map may contain a submount key. This key defines a mount
location within the map that references another map. This can be done
either using automountmap-add-indirect --parentmap or manually
with automountkey-add and setting info to "-type=autofs :<mapname>".

EXAMPLES:

Locations:

  Create a named location, "Baltimore":
    ipa automountlocation-add baltimore

  Display the new location:
    ipa automountlocation-show baltimore

  Find available locations:
    ipa automountlocation-find

  Remove a named automount location:
    ipa automountlocation-del baltimore

  Show what the automount maps would look like if they were in the filesystem:
    ipa automountlocation-tofiles baltimore

  Import an existing configuration into a location:
    ipa automountlocation-import baltimore /etc/auto.master

    The import will fail if any duplicate entries are found. For
    continuous operation where errors are ignored, use the --continue
    option.

Maps:

  Create a new map, "auto.share":
    ipa automountmap-add baltimore auto.share

  Display the new map:
    ipa automountmap-show baltimore auto.share

  Find maps in the location baltimore:
    ipa automountmap-find baltimore

  Create an indirect map with auto.share as a submount:
    ipa automountmap-add-indirect baltimore --parentmap=auto.share --mount=sub auto.man

    This is equivalent to:

    ipa automountmap-add-indirect baltimore --mount=/man auto.man
    ipa automountkey-add baltimore auto.man --key=sub --info="-fstype=autofs ldap:auto.share"

  Remove the auto.share map:
    ipa automountmap-del baltimore auto.share

Keys:

  Create a new key for the auto.share map in location baltimore. This ties
  the map we previously created to auto.master:
    ipa automountkey-add baltimore auto.master --key=/share --info=auto.share

  Create a new key for our auto.share map, an NFS mount for man pages:
    ipa automountkey-add baltimore auto.share --key=man --info="-ro,soft,rsize=8192,wsize=8192 ipa.example.com:/shared/man"

  Find all keys for the auto.share map:
    ipa automountkey-find baltimore auto.share

  Find all direct automount keys:
    ipa automountkey-find baltimore --key=/-

  Remove the man key from the auto.share map:
    ipa automountkey-del baltimore auto.share --key=man
""")

register = Registry()


@register()
class automountkey(Object):
    takes_params = (
        parameters.Str(
            'automountkey',
            label=_(u'Key'),
            doc=_(u'Automount key name.'),
        ),
        parameters.Str(
            'automountinformation',
            label=_(u'Mount information'),
        ),
        parameters.Str(
            'description',
            required=False,
            primary_key=True,
            label=_(u'description'),
            exclude=('webui', 'cli'),
        ),
    )


@register()
class automountlocation(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
            label=_(u'Location'),
            doc=_(u'Automount location name.'),
        ),
    )


@register()
class automountmap(Object):
    takes_params = (
        parameters.Str(
            'automountmapname',
            primary_key=True,
            label=_(u'Map'),
            doc=_(u'Automount map name.'),
        ),
        parameters.Str(
            'description',
            required=False,
            label=_(u'Description'),
        ),
    )


@register()
class automountkey_add(Method):
    __doc__ = _("Create a new automount key.")

    takes_args = (
        parameters.Str(
            'automountlocationcn',
            cli_name='automountlocation',
            label=_(u'Location'),
            doc=_(u'Automount location name.'),
        ),
        parameters.Str(
            'automountmapautomountmapname',
            cli_name='automountmap',
            label=_(u'Map'),
            doc=_(u'Automount map name.'),
        ),
    )
    takes_options = (
        parameters.Str(
            'automountkey',
            cli_name='key',
            label=_(u'Key'),
            doc=_(u'Automount key name.'),
        ),
        parameters.Str(
            'automountinformation',
            cli_name='info',
            label=_(u'Mount information'),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class automountkey_del(Method):
    __doc__ = _("Delete an automount key.")

    takes_args = (
        parameters.Str(
            'automountlocationcn',
            cli_name='automountlocation',
            label=_(u'Location'),
            doc=_(u'Automount location name.'),
        ),
        parameters.Str(
            'automountmapautomountmapname',
            cli_name='automountmap',
            label=_(u'Map'),
            doc=_(u'Automount map name.'),
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_(u"Continuous mode: Don't stop on errors."),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'automountkey',
            cli_name='key',
            label=_(u'Key'),
            doc=_(u'Automount key name.'),
        ),
        parameters.Str(
            'automountinformation',
            required=False,
            cli_name='info',
            label=_(u'Mount information'),
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
        output.ListOfPrimaryKeys(
            'value',
        ),
    )


@register()
class automountkey_find(Method):
    __doc__ = _("Search for an automount key.")

    takes_args = (
        parameters.Str(
            'automountlocationcn',
            cli_name='automountlocation',
            label=_(u'Location'),
            doc=_(u'Automount location name.'),
        ),
        parameters.Str(
            'automountmapautomountmapname',
            cli_name='automountmap',
            label=_(u'Map'),
            doc=_(u'Automount map name.'),
        ),
        parameters.Str(
            'criteria',
            required=False,
            doc=_(u'A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'automountkey',
            required=False,
            cli_name='key',
            label=_(u'Key'),
            doc=_(u'Automount key name.'),
        ),
        parameters.Str(
            'automountinformation',
            required=False,
            cli_name='info',
            label=_(u'Mount information'),
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_(u'Time Limit'),
            doc=_(u'Time limit of search in seconds (0 is unlimited)'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_(u'Size Limit'),
            doc=_(u'Maximum number of entries returned (0 is unlimited)'),
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
class automountkey_mod(Method):
    __doc__ = _("Modify an automount key.")

    takes_args = (
        parameters.Str(
            'automountlocationcn',
            cli_name='automountlocation',
            label=_(u'Location'),
            doc=_(u'Automount location name.'),
        ),
        parameters.Str(
            'automountmapautomountmapname',
            cli_name='automountmap',
            label=_(u'Map'),
            doc=_(u'Automount map name.'),
        ),
    )
    takes_options = (
        parameters.Str(
            'automountkey',
            cli_name='key',
            label=_(u'Key'),
            doc=_(u'Automount key name.'),
        ),
        parameters.Str(
            'automountinformation',
            required=False,
            cli_name='info',
            label=_(u'Mount information'),
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
        parameters.Str(
            'newautomountinformation',
            required=False,
            cli_name='newinfo',
            label=_(u'New mount information'),
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
        parameters.Str(
            'rename',
            required=False,
            label=_(u'Rename'),
            doc=_(u'Rename the automount key object'),
            exclude=('webui',),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class automountkey_show(Method):
    __doc__ = _("Display an automount key.")

    takes_args = (
        parameters.Str(
            'automountlocationcn',
            cli_name='automountlocation',
            label=_(u'Location'),
            doc=_(u'Automount location name.'),
        ),
        parameters.Str(
            'automountmapautomountmapname',
            cli_name='automountmap',
            label=_(u'Map'),
            doc=_(u'Automount map name.'),
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
            'automountkey',
            cli_name='key',
            label=_(u'Key'),
            doc=_(u'Automount key name.'),
        ),
        parameters.Str(
            'automountinformation',
            required=False,
            cli_name='info',
            label=_(u'Mount information'),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class automountlocation_add(Method):
    __doc__ = _("Create a new automount location.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='location',
            label=_(u'Location'),
            doc=_(u'Automount location name.'),
        ),
    )
    takes_options = (
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class automountlocation_del(Method):
    __doc__ = _("Delete an automount location.")

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='location',
            label=_(u'Location'),
            doc=_(u'Automount location name.'),
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
        output.ListOfPrimaryKeys(
            'value',
        ),
    )


@register()
class automountlocation_find(Method):
    __doc__ = _("Search for an automount location.")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_(u'A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'cn',
            required=False,
            cli_name='location',
            label=_(u'Location'),
            doc=_(u'Automount location name.'),
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_(u'Time Limit'),
            doc=_(u'Time limit of search in seconds (0 is unlimited)'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_(u'Size Limit'),
            doc=_(u'Maximum number of entries returned (0 is unlimited)'),
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
            doc=_(u'Results should contain primary key attribute only ("location")'),
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
class automountlocation_show(Method):
    __doc__ = _("Display an automount location.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='location',
            label=_(u'Location'),
            doc=_(u'Automount location name.'),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class automountlocation_tofiles(Method):
    __doc__ = _("Generate automount files for a specific location.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='location',
            label=_(u'Location'),
            doc=_(u'Automount location name.'),
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'result',
        ),
    )


@register()
class automountmap_add(Method):
    __doc__ = _("Create a new automount map.")

    takes_args = (
        parameters.Str(
            'automountlocationcn',
            cli_name='automountlocation',
            label=_(u'Location'),
            doc=_(u'Automount location name.'),
        ),
        parameters.Str(
            'automountmapname',
            cli_name='map',
            label=_(u'Map'),
            doc=_(u'Automount map name.'),
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class automountmap_add_indirect(Method):
    __doc__ = _("Create a new indirect mount point.")

    takes_args = (
        parameters.Str(
            'automountlocationcn',
            cli_name='automountlocation',
            label=_(u'Location'),
            doc=_(u'Automount location name.'),
        ),
        parameters.Str(
            'automountmapname',
            cli_name='map',
            label=_(u'Map'),
            doc=_(u'Automount map name.'),
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
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
            'key',
            cli_name='mount',
            label=_(u'Mount point'),
        ),
        parameters.Str(
            'parentmap',
            required=False,
            label=_(u'Parent map'),
            doc=_(u'Name of parent automount map (default: auto.master).'),
            default=u'auto.master',
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class automountmap_del(Method):
    __doc__ = _("Delete an automount map.")

    takes_args = (
        parameters.Str(
            'automountlocationcn',
            cli_name='automountlocation',
            label=_(u'Location'),
            doc=_(u'Automount location name.'),
        ),
        parameters.Str(
            'automountmapname',
            multivalue=True,
            cli_name='map',
            label=_(u'Map'),
            doc=_(u'Automount map name.'),
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
        output.ListOfPrimaryKeys(
            'value',
        ),
    )


@register()
class automountmap_find(Method):
    __doc__ = _("Search for an automount map.")

    takes_args = (
        parameters.Str(
            'automountlocationcn',
            cli_name='automountlocation',
            label=_(u'Location'),
            doc=_(u'Automount location name.'),
        ),
        parameters.Str(
            'criteria',
            required=False,
            doc=_(u'A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'automountmapname',
            required=False,
            cli_name='map',
            label=_(u'Map'),
            doc=_(u'Automount map name.'),
        ),
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_(u'Time Limit'),
            doc=_(u'Time limit of search in seconds (0 is unlimited)'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_(u'Size Limit'),
            doc=_(u'Maximum number of entries returned (0 is unlimited)'),
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
            doc=_(u'Results should contain primary key attribute only ("map")'),
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
class automountmap_mod(Method):
    __doc__ = _("Modify an automount map.")

    takes_args = (
        parameters.Str(
            'automountlocationcn',
            cli_name='automountlocation',
            label=_(u'Location'),
            doc=_(u'Automount location name.'),
        ),
        parameters.Str(
            'automountmapname',
            cli_name='map',
            label=_(u'Map'),
            doc=_(u'Automount map name.'),
        ),
    )
    takes_options = (
        parameters.Str(
            'description',
            required=False,
            cli_name='desc',
            label=_(u'Description'),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class automountmap_show(Method):
    __doc__ = _("Display an automount map.")

    takes_args = (
        parameters.Str(
            'automountlocationcn',
            cli_name='automountlocation',
            label=_(u'Location'),
            doc=_(u'Automount location name.'),
        ),
        parameters.Str(
            'automountmapname',
            cli_name='map',
            label=_(u'Map'),
            doc=_(u'Automount map name.'),
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
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )
