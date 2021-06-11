# Copyright (C) 2016  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import

import abc
import grp
import inspect
import json
import pwd
import re
import sys

from jwcrypto.common import json_encode

import six

from .compat import configparser
from .log import CustodiaLoggingAdapter, auditlog, getLogger


logger = getLogger(__name__)


class _Required(object):
    __slots__ = ()

    def __repr__(self):
        return 'REQUIRED'


class INHERIT_GLOBAL(object):  # noqa: N801
    __slots__ = ('default',)

    def __init__(self, default):
        self.default = default

    def __repr__(self):
        return 'INHERIT_GLOBAL({})'.format(self.default)


REQUIRED = _Required()


class CustodiaException(Exception):
    pass


class HTTPError(CustodiaException):
    def __init__(self, code=None, message=None):
        self.code = code if code is not None else 500
        self.mesg = message
        errstring = '%d: %s' % (self.code, self.mesg)
        super(HTTPError, self).__init__(errstring)


class CSStoreError(CustodiaException):
    pass


class CSStoreExists(CustodiaException):
    pass


class CSStoreUnsupported(CustodiaException):
    pass


class CSStoreDenied(CustodiaException):
    pass


class OptionHandler(object):
    """Handler and parser for plugin options
    """
    def __init__(self, parser, section):
        self.parser = parser
        self.section = section
        # handler is reserved to look up the plugin class
        self.seen = {'handler'}

    def get(self, po):
        """Lookup value for a PluginOption instance

        Args:
            po: PluginOption

        Returns: converted value
        """
        name = po.name
        typ = po.typ
        default = po.default

        handler = getattr(self, '_get_{}'.format(typ), None)
        if handler is None:
            raise ValueError(typ)
        self.seen.add(name)

        # pylint: disable=not-callable
        if not self.parser.has_option(self.section, name):
            if default is REQUIRED:
                raise NameError(self.section, name)
            if isinstance(default, INHERIT_GLOBAL):
                return handler('global', name, default.default)
            # don't return default here, give the handler a chance to modify
            # the default, e.g. pw_uid with default='root' returns 0.

        return handler(self.section, name, default)
        # pylint: enable=not-callable

    def check_surplus(self):
        surplus = []
        for name, _ in self.parser.items(self.section):
            if (name not in self.seen and not
                    self.parser.has_option(configparser.DEFAULTSECT, name)):
                surplus.append(name)
        return surplus

    def _get_int(self, section, name, default):
        return self.parser.getint(section, name, fallback=default)

    def _get_oct(self, section, name, default):
        value = self.parser.get(section, name, fallback=default)
        return int(value, 8)

    def _get_hex(self, section, name, default):
        value = self.parser.get(section, name, fallback=default)
        return int(value, 16)

    def _get_float(self, section, name, default):
        return self.parser.getfloat(section, name, fallback=default)

    def _get_bool(self, section, name, default):
        return self.parser.getboolean(section, name, fallback=default)

    def _get_regex(self, section, name, default):
        value = self.parser.get(section, name, fallback=default)
        if not value:
            return None
        else:
            return re.compile(value)

    def _get_str(self, section, name, default):
        return self.parser.get(section, name, fallback=default)

    def _split_string(self, value):
        if ',' in value:
            values = value.split(',')
        else:
            values = value.split(' ')
        return list(v.strip() for v in values if v.strip())

    def _get_str_set(self, section, name, default):
        try:
            value = self.parser.get(section, name)
        except configparser.NoOptionError:
            return default
        if not value or not value.strip():
            return None
        else:
            return set(self._split_string(value))

    def _get_str_list(self, section, name, default):
        try:
            value = self.parser.get(section, name)
        except configparser.NoOptionError:
            return default
        if not value or not value.strip():
            return None
        else:
            return self._split_string(value)

    def _get_store(self, section, name, default):
        return self.parser.get(section, name, fallback=default)

    def _get_pwd_uid(self, section, name, default):
        value = self.parser.get(section, name, fallback=default)
        try:
            return int(value)
        except ValueError:
            return pwd.getpwnam(value).pw_uid

    def _get_grp_gid(self, section, name, default):
        value = self.parser.get(section, name, fallback=default)
        try:
            return int(value)
        except ValueError:
            return grp.getgrnam(value).gr_gid

    def _get_json(self, section, name, default):
        value = self.parser.get(section, name, fallback=default)
        return json.loads(value)


class PluginOption(object):
    """Plugin option

    code::

        class MyPlugin(CustodiaPlugin):
            number = PluginOption(int, REQUIRED, 'my value')
            values = PluginOption('str_list', 'foo bar', 'a list of strings')


    config::

        [myplugin]
        handler = MyPlugin
        number = 1
        values = egg spam python


    **Supported value types**

    *str*
      plain string
    *str_set*
      set of comma-separated or space-separated strings
    *str_list*
      ordered list of comma-separated or space-separated strings
    *int*
      number (converted from base 10)
    *hex*
      number (converted from base 16)
    *oct*
      number (converted from base 8)
    *float*
      floating point number
    *bool*
      boolean (true: on, true, yes, 1; false: off, false, no, 0)
    *regex*
      regular expression string
    *store*
      special value for refer to a store plugin
    *pwd_uid*
      numeric user id or user name
    *grp_gid*
      numeric group id or group name
    *json*
      JSON string
    """
    __slots__ = ('name', 'typ', 'default', 'doc')

    def __init__(self, typ, default, doc):
        self.name = None
        if typ in {str, int, float, bool, oct, hex}:
            self.typ = typ.__name__
        else:
            self.typ = typ
        self.default = default
        self.doc = doc

    def __repr__(self):
        if self.default is REQUIRED:
            msg = "<Required option {0.name} ({0.typ}): {0.doc}>"
        else:
            msg = ("<Option {0.name} ({0.typ}, default: '{0.default}'): "
                   "{0.doc}>")
        return msg.format(self)


class CustodiaPluginMeta(abc.ABCMeta):
    def __new__(cls, name, bases, namespace, **kwargs):
        ncls = super(CustodiaPluginMeta, cls).__new__(
            cls, name, bases, namespace, **kwargs)

        if sys.version_info < (3, 0):
            # pylint: disable=deprecated-method
            args = inspect.getargspec(ncls.__init__).args
            # pylint: enable=deprecated-method
        else:
            sig = inspect.signature(ncls.__init__)  # pylint: disable=no-member
            args = list(sig.parameters)

        if args[1:3] != ['config', 'section']:
            # old-style plugin class
            ncls._options = None  # pylint: disable=protected-access
            return ncls

        # new-style plugin class
        # every plugin has a debug option. In case it is not set, the debug
        # flag from [global] is inherited.
        if not hasattr(ncls, 'debug'):
            ncls.debug = PluginOption(bool, INHERIT_GLOBAL(False), '')
        # get options
        options = []
        for name, value in inspect.getmembers(ncls):
            if not isinstance(value, PluginOption):
                continue
            value.name = name
            options.append(value)

        ncls._options = tuple(options)  # pylint: disable=protected-access
        return ncls


@six.add_metaclass(CustodiaPluginMeta)
class CustodiaPlugin(object):
    """Abstract base class for all Custodia plugins
    """
    _options = ()

    def __init__(self, config, section=None):
        origin, debug = self._configure(config, section)
        self._auditlog = auditlog
        self.section = section  # plugin loader sets section for old plugins
        self.origin = origin
        self.logger = CustodiaLoggingAdapter(self, debug)

    def audit_key_access(self, *args, **kwargs):
        self._auditlog.key_access(self.origin, *args, **kwargs)

    def audit_svc_access(self, *args, **kwargs):
        self._auditlog.svc_access(self.origin, *args, **kwargs)

    def _configure(self, config, section):
        if section is not None and self._options is not None:
            # new style configuration
            opt = OptionHandler(config, section)
            # pylint: disable=not-an-iterable
            for option in self._options:
                value = opt.get(option)
                # special case for store
                if option.typ == 'store':
                    if option.name != 'store':
                        raise ValueError(option.name)
                    self.store_name = value
                    self.store = None
                else:
                    setattr(self, option.name, value)

            surplus = opt.check_surplus()
            if surplus:
                raise ValueError('Surplus options in {}: {}'.format(
                    section, surplus))

            origin = '%s-[%s]' % (type(self).__name__, section)
            debug = self.debug  # pylint: disable=no-member
        else:
            # old style configuration
            if config is None:
                config = {}
            self.config = config
            # special case for store
            if 'store' in config:
                self.store_name = self.config.get('store')
                self.store = None
            origin = config.get('facility_name', self.__class__.__name__)
            debug = config.get('debug', 'false').lower() == 'true'

        return origin, debug

    def _attach_store(self, config, cfgparser, context):
        """Attach nested store
        """
        if getattr(self, 'store', None) is not None:
            # already attached
            return
        store_plugin = config['stores'].get(self.store_name)
        if store_plugin is None:
            raise ValueError(
                "'{}' references non-existing store '{}'".format(
                    self.section, self.store_name))
        # pylint: disable=attribute-defined-outside-init
        self.store = store_plugin
        # pylint: enable=attribute-defined-outside-init
        store_plugin.finalize_init(config, cfgparser, context=self)

    def finalize_init(self, config, cfgparser, context=None):
        """Two-phase initialization

        Args:
            config: server config dictionary
            cfgparser: configparser instance
            context: initialization context (None for global)
        """
        if getattr(self, 'store_name', None) is not None:
            self._attach_store(config, cfgparser, context)


class CSStore(CustodiaPlugin):
    """Base class for stores
    """
    @abc.abstractmethod
    def get(self, key):
        pass

    @abc.abstractmethod
    def set(self, key, value, replace=False):
        pass

    # relax ABC for now, see https://github.com/latchset/custodia/issues/84

    # @abc.abstractmethod
    def span(self, key):
        raise NotImplementedError

    # @abc.abstractmethod
    def list(self, keyfilter=None):
        raise NotImplementedError

    # @abc.abstractmethod
    def cut(self, key):
        raise NotImplementedError


class HTTPAuthorizer(CustodiaPlugin):
    """Base class for authorizers
    """
    @abc.abstractmethod
    def handle(self, request):
        pass


class HTTPAuthenticator(CustodiaPlugin):
    """Base class for authenticators
    """
    @abc.abstractmethod
    def handle(self, request):
        pass


DEFAULT_CTYPE = 'text/html; charset=utf-8'
SUPPORTED_COMMANDS = ['GET', 'PUT', 'POST', 'DELETE']


class HTTPConsumer(CustodiaPlugin):
    """Base class for consumers
    """
    def __init__(self, config, section=None):
        super(HTTPConsumer, self).__init__(config, section)
        self.subs = dict()
        self.root = self

    def add_sub(self, name, sub):
        self.subs[name] = sub
        if hasattr(sub, 'root'):
            sub.root = self.root

    def _find_handler(self, request):
        base = self
        command = request.get('command', 'GET')
        if command not in SUPPORTED_COMMANDS:
            raise HTTPError(501)
        trail = request.get('trail', None)
        if trail is not None:
            for comp in trail:
                subs = getattr(base, 'subs', {})
                if comp in subs:
                    base = subs[comp]
                    trail.pop(0)
                else:
                    break

        handler = getattr(base, command)
        if handler is None:
            raise HTTPError(400)

        return handler

    def handle(self, request):
        handler = self._find_handler(request)
        response = {'headers': dict()}

        # Handle request
        output = handler(request, response)
        if output is None:
            output = response.get('output')

        ct = response['headers'].get('Content-Type')
        if ct is None:
            ct = response['headers']['Content-Type'] = DEFAULT_CTYPE

        if 'application/json' in ct and isinstance(output, (dict, list)):
            output = json_encode(output).encode('utf-8')
            response['headers']['Content-Length'] = str(len(output))

        response['output'] = output

        if output is not None and not hasattr(output, 'read') \
                and not isinstance(output, six.binary_type):
            msg = "Handler {} returned unsupported type {} ({}):\n{!r}"
            raise TypeError(msg.format(handler, type(output), ct, output))

        if output is not None and 'Content-Length' not in response['headers']:
            if hasattr(output, 'read'):
                # LOG: warning file-type objects should set Content-Length
                pass
            else:
                response['headers']['Content-Length'] = str(len(output))

        return response
