# Authors:
#   Pavel Zuna <pzuna@redhat.com>
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
"""
Example plugins
"""

# Hey guys, so you're interested in writing plugins for IPA? Great!
# We compiled this small file with examples on how to extend IPA to suit
# your needs. We'll be going from very simple to pretty complex plugins
# hopefully covering most of what our framework has to offer.

# First, let's import some stuff.

# errors is a module containing all IPA specific exceptions.
from ipalib import errors
# Command is the base class for command plugin.
from ipalib import Command
# Str is a subclass of Param, it is used to define string parameters for
# command. We'll go through all other subclasses of Param supported by IPA
# later in this file
from ipalib import Str
# output is a module containing the most common output patterns.
# Command plugin do output validation based on these patterns.
# You can define your own as we're going to show you later.
from ipalib import output


# To make the example ready for Python 3, we alias "unicode" to strings.
import six
if six.PY3:
    unicode = str


# We're going to create an example command plugin, that takes a name as its
# only argument. Commands in IPA support input validation by defining
# functions we're going to call 'validators'. This is an example of such
# function:
def validate_name(ugettext, name):
    """
    Validate names for the exhelloworld command. Names starting with 'Y'
    (picked at random) are considered invalid.
    """
    if name.startswith('Y'):
        raise errors.ValidationError(
            name='name',
            error='Names starting with \'Y\' are invalid!'
        )
    # If the validator doesn't return anything (i.e. it returns None),
    # the parameter passes validation.


class exhelloworld(Command):
    """
    Example command: Hello world!
    """
    # takes_args is an attribute of Command. It's a tuple containing
    # instances of Param (or its subclasses such as Str) that define
    # what position arguments are accepted by the command.
    takes_args = (
        # The first argument of Param constructor is the name that will be
        # used to identify this parameter. It can be followed by validator
        # functions. The constructor can also take a bunch of keyword
        # arguments. Here we use default, to set the parameters default value
        # and autofill, that fills the default value if the parameter isn't
        # present.
        # Note the ? at the end of the parameter name. It makes the parameter
        # optional.
        Str('name?', validate_name,
            default=u'anonymous coward',
            autofill=True,
        ),
    )

    # has_output is an attribute of Command, it is a tuple containing
    # output.Output instances that define its output pattern.
    # Commands in IPA return dicts with keys corresponding to items
    # in the has_output tuple.
    has_output = (
        # output.summary is one of the basic patterns.
        # It's a string that should be filled with a user-friendly
        # decription of the action performed by the command.
        output.summary,
    )

    # Every command needs to override the execute method.
    # This is where the command functionality should go.
    # It is always executed on the server-side, so don't rely
    # on client-side stuff in here!
    def execute(self, name, **options):
        return dict(summary='Hello world, %s!' % name)

# register the command, uncomment this line if you want to try it out
#api.register(exhelloworld)

# Anyway, that was a pretty bad example of a command or, to be more precise,
# a bad example of resource use. When a client executes a command locally, its
# name and parameters are transfered to the server over XML-RPC. The command
# execute method is then executed on the server and results are transfered
# back to the client. The command does nothing, but create a string - a task
# that could be easily done locally. This can be done by overriding the Command
# forward method. It has the same signature as execute and is normally
# responsible for transferring stuff to the server.
# Most commands will, however, need to perfom tasks on the server. I didn't
# want to start with forward and confuse the hell out of you. :)


# Okey, time to look at something a little more advance. A command that
# actually communicates with the LDAP backend.

# Let's import a new parameter type: Flag.
# Parameters of type Flag do not have values per say. They are either enabled
# or disabled (True or False), so there's no need to make then optional, ever.
from ipalib import Flag

class exshowuser(Command):
    """
    Example command: retrieve an user entry from LDAP
    """
    takes_args = (
        Str('username'),
    )

    # takes_options is another attribute of Command. It works the same
    # way as takes_args, but instead of positional arguments, it enables
    # us to define what options the commmand takes.
    # Note that an options can be both required and optional.
    takes_options = (
        Flag('all',
            # the doc keyword argument is what you see when you go
            # `ipa COMMAND --help` or `ipa help COMMAND`
            doc='retrieve and print all attributes from the server. Affects command output.',
            flags=['no_output'],
        ),
    )

    has_output = (
        # Here, you can see a custom output pattern. The pattern constructor
        # takes the output name (key in the dictionary returned by execute),
        # the allowed type(s) (can be a tuple with several types), a
        # simple description and a list of flags. Currently, only
        # the 'no_display' flag is supported by the Command.output_for_cli
        # method, but you can always use your own if you plan
        # to override it - I'll show you how later.
        output.Output('result', dict, 'user entry without DN'),
        output.Output('dn', unicode, 'DN of the user entry', ['no_display']),
    )

    # Notice the ** argument notation for options. It is not required, but
    # we strongly recommend you to use it. In some cases, special options
    # are added automatically to commands and not listing them or using **
    # may lead to exception flying around... and nobody likes exceptions
    # flying around.
    def execute(self, username, **options):
        # OK, I said earlier that this command is going to communicate
        # with the LDAP backend, You could always use python-ldap to do
        # that, but there's also this nice class we have... it's called
        # ldap2 and this is how you get a handle to it:
        ldap = self.api.Backend.ldap2

        # ldap2 enables you to do a lot of crazy stuff with LDAP and it's
        # specially crafted to suit IPA plugin needs. I recommend you either
        # look at ipaserver/plugins/ldap2 or checkout some of the generated
        # HTML docs on www.freeipa.org as I won't be able to cover everything
        # it offers in this file.

        # We want to retrieve an user entry from LDAP. We need to know its
        # DN first. There's a bunch of method in ldap2 to build DNs. For our
        # purpose, this will do:
        dn = ldap.make_dn_from_attr(
            'uid', username, self.api.env.container_user
        )
        # Note that api.env contains a lot of useful constant. We recommend
        # you to check them out and use them whenever possible.

        # Let's check if the --all option is enabled. If it is, let's
        # retrieve all of the entry attributes. If not, only retrieve some
        # basic stuff like the username, first and last names.
        if options.get('all', False):
            attrs_list = ['*']
        else:
            attrs_list = ['uid', 'givenname', 'sn']

        # Give us the entry, LDAP!
        (dn, entry_attrs) = ldap.get_entry(dn, attrs_list)

        return dict(result=entry_attrs, dn=dn)

# register the command, uncomment this line if you want to try it out
#api.register(exshowuser)


# Now let's a take a look on how you can modify the command output if you don't
# like the default.

class exshowuser2(exshowuser):
    """
    Example command: exusershow with custom output
    """
    # Just some values we're going to use for textui.print_entry
    attr_order = ['uid', 'givenname', 'sn']
    attr_labels = {
        'uid': 'User login', 'givenname': 'First name', 'sn': 'Last name'
    }

    def output_for_cli(self, textui, output, *args, **options):
        # Now we've done it! We have overridden the default output_for_cli.
        # textui is a class that implements a lot of useful outputting methods,
        # please use it when you can
        # output contains the dict returned by execute
        # args, options contain the command parameters
        textui.print_dashed('User entry:')
        textui.print_indented('DN: %s' % output['dn'])
        textui.print_entry(output['result'], self.attr_order, self.attr_labels)

# register the command, uncomment this line if you want to try it out
#api.register(exshowuser2)

# Alright, so now you'll always want to define your own output_for_cli...
# No, you won't! Because the default output_for_cli isn't as stupid as it looks.
# It can take information from the command parameters and output patterns
# to produce nice output like all real IPA commands have.

class exshowuser3(exshowuser):
    """
    Example command: exusershow that takes full advantage of the default output
    """
    takes_args = (
        # We're going to rename the username argument to uid to match
        # the attribute name it represent. The cli_name kwarg is what
        # users will see in the CLI and label is what the default
        # output_for_cli is going to use when printing the attribute value.
        Str('uid',
            cli_name='username',
            label='User login',
        ),
    )

    # has_output_params works the same way as takes_args and takes_options,
    # but is only used to define output attributes. These won't show up
    # as parameters for the command.
    has_output_params = (
        Str('givenname',
            label='First name',
        ),
        Str('sn',
            label='Last name',
        ),
    )

    # standard_entry includes an entry 'result' (dict), a summary 'summary'
    # and the entry primary key 'value'
    # It also makes the command automatically add two special options:
    # --all and --raw. Look at the description of nearly any real IPA command
    # to see what they're about.
    has_output = output.standard_entry

    # Since --all and --raw are added automatically thanks to standard_entry,
    # we need to clear takes_options from the base class otherwise we would
    # get a parameter conflict.
    takes_options = tuple()

    def execute(self, *args, **options):
        # Let's just call execute of the base class, extract it's output
        # and fit it into the standard_entry output pattern.
        output = super(exshowuser3, self).execute(*args, **options)
        output['result']['dn'] = output['dn']
        return dict(result=output['result'], value=args[0])

# register the command, uncomment this line if you want to try it out
#api.register(exshowuser3)


# Pretty cool, right? But you will probably want to implement a set of commands
# to manage a certain type of entries (like users in the above examples).
# To save you the massive PITA of parameter copy&paste, we introduced
# the Object and Method plugin classes. Let's see how they work.

from ipalib import Object, Method

# First, we're going to create an object that represent the user entry.
class exuser(Object):
    """
    Example plugin: user object
    """
    # takes_params is an attribute of Object. It is used to define output
    # parameters for associated Methods. Methods can also use them to
    # to generate their own parameters as you'll see in a while.
    takes_params = (
        Str('uid',
            cli_name='username',
            label='User login',
            # The primary_key kwarg is used to, well, specify the object's
            # primary key.
            primary_key=True,
        ),
        Str('givenname?',
            cli_name='first',
            label='First name',
        ),
        Str('sn?',
            cli_name='last',
            label='Last name',
        ),
    )

# register the object, uncomment this line if you want to try it out
#api.register(exuser)

# Next, we're going to create a set of methods to manage this type of object
# i.e. to manage user entries. We're only going to do "read" commands, because
# we don't want to damage your user entries - adding, deleting, modifying is a
# bit more complicated and will be covered later in this file.

# Methods are automatically associated with a parent Object based on class
# names. They can then access their parent Object using self.obj.
# Simply said, Methods are just Commands associated with an Object.

class exuser_show(Method):
    has_output = output.standard_entry

    # get_args is a method of Command used to generate positional arguments
    # we're going to use it to extract parameters from the parent
    # Object
    def get_args(self):
        # self.obj.primary_key contains a reference the parameter with
        # primary_key kwarg set to True.
        # Parameters can be cloned to create new instance with additional
        # kwargs. Here we add the attribute kwargs, that tells the framework
        # the parameters corresponds to an LDAP attribute. The query kwargs
        # tells the framework to skip parameter validation (i.e. do NOT call
        # validators).
        yield self.obj.primary_key.clone(attribute=True, query=True)

    def execute(self, *args, **options):
        ldap = self.api.Backend.ldap2

        dn = ldap.make_dn_from_attr(
            'uid', args[0], self.api.env.container_user
        )

        if options.get('all', False):
            attrs_list = ['*']
        else:
            attrs_list = [p.name for p in self.output_params()]

        (dn, entry_attrs) = ldap.get_entry(dn, attrs_list)
        entry_attrs['dn'] = dn

        return dict(result=entry_attrs, value=args[0])

# register the command, uncomment this line if you want to try it out
#api.register(exuser_show)

class exuser_find(Method):
    # standard_list_of_entries is an output pattern that
    # define a dict with a list of entries, their count
    # and a truncated flag. The truncated flag is used to mark
    # truncated (incomplete) search results - for example due to
    # timeouts.
    has_output = output.standard_list_of_entries

    # get_options is similar to get_args, but is used to generate
    # options instead of positional arguments
    def get_options(self):
        for option in self.obj.params():
            yield option.clone(
                attribute=True, query=True, required=False
            )

    def execute(self, *args, **options):
        ldap = self.api.Backend.ldap2

        # args_options_2_entry is a helper method of Command used
        # to create a dictionary from the command parameters that
        # have the attribute kwargs set to True.
        search_kw = self.args_options_2_entry(*args, **options)

        # make_filter will create an LDAP filter from attribute values
        # exact=False means the values are surrounded with * when constructing
        # the filter and rules=ldap.MATCH_ALL means the filter is going
        # to use the & operators. More complex filters can be constructed
        # by joining simpler filters using ldap2.combine_filters.
        attr_filter = ldap.make_filter(
            search_kw, exact=False, rules=ldap.MATCH_ALL
        )

        if options.get('all', False):
            attrs_list = ['*']
        else:
            attrs_list = [p.name for p in self.output_params()]

        # perform the search
        (entries, truncated) = ldap.find_entries(
            attr_filter, attrs_list, self.api.env.container_user,
            scope=ldap.SCOPE_ONELEVEL
        )

        # find_entries returns DNs and attributes separately, but the output
        # patter expects them in one dict. We need to arrange that.
        for e in entries:
            e[1]['dn'] = e[0]
        entries = [e for (_dn, e) in entries]

        return dict(result=entries, count=len(entries), truncated=truncated)

# register the command, uncomment this line if you want to try it out
#api.register(exuser_find)

# As most commands associated with objects are used to manage entries in LDAP,
# we defined a basic set of base classes for your plugins implementing CRUD
# operations. This is maily to save you from defining your own has_output,
# get_args, get_options and to have a standardized way of doing things for the
# sake of consistency. We won't cover them here, because you probably won't
# need to use them. So why did we botter? Well, you're going to see in
# a while. If interested anyway, check them out in ipalib/crud.py.


# At this point, if you've already seen some of the real plugins, you might
# be going like "WTH is this !@#^&? The user_show plugin is only like 4 lines
# of code and does much more than the exshowuser crap. Well yes, that's because
# it is based on one of the awesome plugin base classes we created to save
# authors from doing all the dirty work. Let's take a look at them.

# COMING SOON: baseldap.py classes, extending existing plugins, etc.
