# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
Encoding capabilities.
"""

class EncoderSettings(object):
    """
    Container for encoder settings.
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
    decode_dict_vals_table_keygen = staticmethod(lambda x, y: x)
    decode_postprocessor = staticmethod(lambda x: x)


class Encoder(object):
    """
    Base class implementing encoding of python scalar types to strings
    and vise-versa.
    """

    encoder_settings = EncoderSettings()

    def __init__(self):
        # each instance should have its own settings
        self.encoder_settings = EncoderSettings()

    def _decode_dict_val(self, key, val):
        f = self.encoder_settings.decode_dict_vals_table.get(
            self.encoder_settings.decode_dict_vals_table_keygen(key, val)
        )
        if f:
            return val
        return self.decode(val)

    def encode(self, var):
        """
        Encode any python built-in python type variable into `self.encode_to`.

        Compound types have their individual members encoded.

        Returns an encoded copy of 'var'.
        """
        if isinstance(var, str):
            return var
        elif isinstance(var, unicode):
            return self.encoder_settings.encode_postprocessor(
                var.encode(self.encoder_settings.encode_to)
            )
        elif isinstance(var, (bool, float, int, long)):
            return self.encoder_settings.encode_postprocessor(
                str(var).encode(self.encoder_settings.encode_to)
            )
        elif isinstance(var, list):
            return [self.encode(m) for m in var]
        elif isinstance(var, tuple):
            return tuple(self.encode(m) for m in var)
        elif isinstance(var, dict):
            if self.encoder_settings.encode_dict_keys:
                dct = dict()
                if not self.encoder_settings.encode_dict_keys_postprocess:
                    tmp = self.encoder_settings.encode_postprocessor
                    self.encoder_settings.encode_postprocessor = lambda x: x
                for (k, v) in var.iteritems():
                    dct[self.encode(k)] = v
                if not self.encoder_settings.encode_dict_keys_postprocess:
                    self.encoder_settings.encode_postprocessor = tmp
            else:
                dct = dict(var)
            if self.encoder_settings.encode_dict_vals:
                if not self.encoder_settings.encode_dict_vals_postprocess:
                    tmp = self.encoder_settings.encode_postprocessor
                    self.encoder_settings.encode_postprocessor = lambda x: x
                for (k, v) in dct.iteritems():
                    dct[k] = self.encode(v)
                if not self.encoder_settings.encode_dict_vals_postprocess:
                    self.encoder_settings.encode_postprocessor = tmp
            return dct
        elif var is None:
            if self.encoder_settings.encode_none:
                return self.encoder_settings.encode_postprocessor(
                    str(var).encode(self.encoder_settings.encode_to)
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
        if isinstance(var, unicode):
            return var
        elif isinstance(var, str):
            return self.encoder_settings.decode_postprocessor(
                var.decode(self.encoder_settings.decode_from)
            )
        elif isinstance(var, (bool, float, int, long)):
            return var
        elif isinstance(var, list):
            return [self.decode(m) for m in var]
        elif isinstance(var, tuple):
            return tuple(self.decode(m) for m in var)
        elif isinstance(var, dict):
            if self.encoder_settings.decode_dict_keys:
                dct = dict()
                if not self.encoder_settings.decode_dict_keys_postprocess:
                    tmp = self.encoder_settings.decode_postprocessor
                    self.encoder_settings.decode_postprocessor = lambda x: x
                for (k, v) in var.iteritems():
                    dct[self.decode(k)] = v
                if not self.encoder_settings.decode_dict_keys_postprocess:
                    self.encoder_settings.decode_postprocessor = tmp
            else:
                dct = dict(var)
            if self.encoder_settings.decode_dict_vals:
                if not self.encoder_settings.decode_dict_vals_postprocess:
                    tmp = self.encoder_settings.decode_postprocessor
                    self.encoder_settings.decode_postprocessor = lambda x: x
                for (k, v) in dct.iteritems():
                    dct[k] = self._decode_dict_val(k, v)
                if not self.encoder_settings.decode_dict_vals_postprocess:
                    self.encoder_settings.decode_postprocessor = tmp
            return dct
        elif var is None:
            if self.encoder_settings.decode_none:
                return self.encoder_settings.decode_postprocessor(
                    str(var).decode(self.encoder_settings.decode_from)
                )
            return None
        raise TypeError('python built-in type expected, got \'%s\'', type(var))

## ENCODER METHOD DECORATORS

def encode_args(*outer_args):
    def decorate(f):
        def new_f(*args, **kwargs):
            assert isinstance(args[0], Encoder), \
                'first argument not Encoder instance'
            new_args = list(args)
            for a in outer_args:
                if isinstance(a, int):
                    if a < len(args):
                        new_args[a] = args[0].encode(args[a])
                elif isinstance(a, basestring):
                    if a in kwargs:
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
    def decorate(f):
        def new_f(*args, **kwargs):
            assert isinstance(args[0], Encoder), \
                'first argument not Encoder instance'
            return args[0].decode(f(*args, **kwargs))
        new_f.func_name = f.func_name
        return new_f
    return decorate

