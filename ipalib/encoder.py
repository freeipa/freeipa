# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
"""
This module provides the Encoder base class, that adds encoding/decoding
capabilities to classes extending it. It also defines a set of decorators
designed to automagically encode method arguments and decode their return
values.
"""

class Encoder(object):
    """
    Base class implementing encoding python scalar types to strings
    and vise-versa.
    """
    encode_to = 'utf-8'
    encode_none = False
    encode_dict_keys = False
    encode_dict_keys_postprocess = True
    encode_dict_vals = True
    encode_dict_vals_postprocess = True
    encode_postprocessor = staticmethod(lambda x: x)

    decode_from = 'utf-8'
    decode_none = False
    decode_dict_keys = False
    decode_dict_keys_postprocess = True
    decode_dict_vals = True
    decode_dict_vals_postprocess = True
    decode_dict_vals_table = dict()
    decode_dict_vals_table_keygen = staticmethod(lambda x: x)
    decode_postprocessor = staticmethod(lambda x: x)

    def _decode_dict_val(self, key, val):
        f = self.decode_dict_vals_table.get(
            self.decode_dict_vals_table_keygen(key), self.decode
        )
        return f(val)

    def encode(self, var):
        """
        Encode any python built-in python type variable into `self.encode_to`.

        Compound types have their individual members encoded.

        Returns an encoded copy of 'var'.
        """
        if isinstance(var, basestring):
            return self.encode_postprocessor(var.encode(self.encode_to))
        elif isinstance(var, (bool, float, int, long)):
            return self.encode_postprocessor(str(var).encode(self.encode_to))
        elif isinstance(var, list):
            return [self.encode(m) for m in var]
        elif isinstance(var, tuple):
            return tuple(self.encode(m) for m in var)
        elif isinstance(var, dict):
            if self.encode_dict_keys:
                dct = dict()
                if not self.encode_dict_keys_postprocess:
                    tmp = self.encode_postprocessor
                    self.encode_postprocessor = lambda x: x
                for (k, v) in var.iteritems():
                    dct[self.encode(k)] = v
                if not self.encode_dict_keys_postprocess:
                    self.encode_postprocessor = tmp
            else:
                dct = dict(var)
            if self.encode_dict_vals:
                if not self.encode_dict_vals_postprocess:
                    tmp = self.encode_postprocessor
                    self.encode_postprocessor = lambda x: x
                for (k, v) in dct.iteritems():
                    dct[k] = self.encode(v)
                if not self.encode_dict_vals_postprocess:
                    self.encode_postprocessor = tmp
            return dct
        elif var is None:
            if self.encode_none:
                return self.encode_postprocessor(
                    str(var).encode(self.encode_to)
                )
            return None
        raise TypeError('python built-in type expected, got \'%s\'', type(var))

    def decode(self, var):
        """
        Decode strings in `self.decode_from` into python strings.

        Compound types have their individual members decoded.

        Dictionaries can have their values decoded into other types
        by looking up keys in `self.decode_dict_vals_table`.

        Returns a decoded copy of 'var'.
        """
        if isinstance(var, basestring):
            return self.decode_postprocessor(var.decode(self.decode_from))
        elif isinstance(var, (bool, float, int, long)):
            return self.decode_postprocessor(unicode(var))
        elif isinstance(var, list):
            return [self.decode(m) for m in var]
        elif isinstance(var, tuple):
            return tuple(self.decode(m) for m in var)
        elif isinstance(var, dict):
            if self.decode_dict_keys:
                dct = dict()
                if not self.decode_dict_keys_postprocess:
                    tmp = self.decode_postprocessor
                    self.decode_postprocessor = lambda x: x
                for (k, v) in var.iteritems():
                    dct[self.decode(k)] = v
                if not self.decode_dict_keys_postprocess:
                    self.decode_postprocessor = tmp
            else:
                dct = dict(var)
            if self.decode_dict_vals:
                if not self.decode_dict_vals_postprocess:
                    tmp = self.decode_postprocessor
                    self.decode_postprocessor = lambda x: x
                for (k, v) in dct.iteritems():
                    dct[k] = self._decode_dict_val(k, v)
                if not self.decode_dict_vals_postprocess:
                    self.decode_postprocessor = tmp
            return dct
        elif var is None:
            if self.decode_none:
                return self.decode_postprocessor(
                    str(var).decode(self.decode_from)
                )
            return None
        raise TypeError('python built-in type expected, got \'%s\'', type(var))

## ENCODER METHOD DECORATORS

def encode_args(*outer_args):
    """
    Encode arguments of the decorated method specified by their sequence
    number or name for keyword arguments.

    Example:
    class some_class_that_needs_encoding_capabilities(Encoder):
        ...
        @encode_args(1, 3, 'name'):
        def some_method(
            self, encode_this, dont_encode_this, encode_this_too, **kwargs
        ):
            # if there's going to be a 'name' kwargs it will be encoded
        ...

    This is an Encoder method decorator.
    """
    def decorate(f):
        def new_f(*args, **kwargs):
            assert isinstance(args[0], Encoder), \
                'first argument not Encoder instance'
            new_args = list(args)
            for a in outer_args:
                if isinstance(a, int):
                    new_args[a] = args[0].encode(args[a])
                elif isinstance(a, basestring) and a in kwargs:
                    kwargs[a] = args[0].encode(kwargs[a])
                else:
                    raise TypeError(
                        'encode_args takes a list of ints and basestrings'
                    )
            return f(*new_args, **kwargs)
        new_f.func_name = f.func_name
        return new_f
    return decorate


def decode_retval():
    """
    Decode the return value of the decorated method.

    Example:
    class some_class_that_needs_encoding_capabilities(Encoder):
        ...
        @decode_retval():
        def some_method(self):
            ...
            return this_will_be_decoded
        ...

    This is an Encoder method decorator AND IT HAS TO BE CALLED (use "()")!
    """
    def decorate(f):
        def new_f(*args, **kwargs):
            assert isinstance(args[0], Encoder), \
                'first argument not Encoder instance'
            return args[0].decode(f(*args, **kwargs))
        new_f.func_name = f.func_name
        return new_f
    return decorate

