#! /usr/bin/python -E
# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#          see inline
#
# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 or later
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

__all__ = ["dsinstance", "krbinstance"]

#
# Functions common for the XML RPC client and server
#
# Authors:
#       Mike McLean <mikem@redhat.com> (from koji)

# functions for encoding/decoding optional arguments

def encode_args(*args,**opts):
    """The function encodes optional arguments as regular arguments.

    This is used to allow optional arguments in xmlrpc calls
    Returns a tuple of args
    """
    if opts:
        opts['__starstar'] = True
        args = args + (opts,)
    return args

def decode_args(*args):
    """Decodes optional arguments from a flat argument list

    Complementary to encode_args
    Returns a tuple (args,opts) where args is a tuple and opts is a dict
    """
    opts = {}
    if len(args) > 0:
        last = args[-1]
        if type(last) == dict and last.get('__starstar',False):
            del last['__starstar']
            opts = last
            args = args[:-1]
    return args,opts

