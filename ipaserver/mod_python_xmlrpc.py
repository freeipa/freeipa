# mod_python script

# ipaxmlrpc - an XMLRPC interface for ipa.
# Copyright (c) 2007 Red Hat
#
#    IPA is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation;
#    version 2.1 of the License.
#
#    This software is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this software; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
# Based on kojixmlrpc - an XMLRPC interface for koji by
# Mike McLean <mikem@redhat.com>
#
# Authors:
# Rob Crittenden <rcritten@redhat.com>

"""
Production XML-RPC server using mod_python.

This module is depreciated.  See the `ipaserver.xmlrpc()` function.
"""

import sys
import os
import time
import traceback
import pprint
import logging
import string
from ipalib import api

# We only initialize api when actually running under mod_python:
try:
    from mod_python import apache
    api.bootstrap(context='server', in_server=True, log=None)
    api.finalize()
except ImportError:
    pass

# Global list of available functions
gfunctions = {}

def register_function(function, name = None):
    if name is None:
        name = function.__name__
    gfunctions[name] = function

class ModXMLRPCRequestHandler(object):
    """Simple XML-RPC handler for mod_python environment"""

    def __init__(self):
        global gfunctions

        self.funcs = gfunctions
        self.traceback = False
        #introspection functions
        self.register_function(self.ping, name="ping")
        self.register_function(self.list_api, name="_listapi")
        self.register_function(self.system_listMethods, name="system.listMethods")
        self.register_function(self.system_methodSignature, name="system.methodSignature")
        self.register_function(self.system_methodHelp, name="system.methodHelp")
        self.register_function(self.multiCall)

    def register_function(self, function, name = None):
        if name is None:
            name = function.__name__
        self.funcs[name] = function

    def register_module(self, instance, prefix=None):
        """Register all the public functions in an instance with prefix prepended

        For example
            h.register_module(exports,"pub.sys")
        will register the methods of exports with names like
            pub.sys.method1
            pub.sys.method2
            ...etc
        """
        for name in dir(instance):
            if name.startswith('_'):
                continue
            function = getattr(instance, name)
            if not callable(function):
                continue
            if prefix is not None:
                name = "%s.%s" %(prefix,name)
            self.register_function(function, name=name)

    def register_instance(self,instance):
        self.register_module(instance)

    def _marshaled_dispatch(self, data, req):
        """Dispatches an XML-RPC method from marshalled (XML) data."""

        params, method = loads(data)
        pythonopts = req.get_options()

        # Populate the Apache environment variables
        req.add_common_vars()

        context.opts['remoteuser'] = req.user

        try:
            ccache = req.subprocess_env.get('KRB5CCNAME')
            return api.Backend.xmlserver.marshaled_dispatch(data, ccache)
        except Exception, e:
            api.log.exception(
                'mod_python_xmlrpc: caught error in _marshaled_dispatch()'
            )
            raise e

    def _dispatch(self,method,params):
        func = self.funcs.get(method,None)
        if func is None:
             raise Fault(1, "Invalid method: %s" % method)

        params = list(ipautil.unwrap_binary_data(params))
        (args, kw) = xmlrpc_unmarshal(*params)

        ret = func(*args, **kw)

        return ipautil.wrap_binary_data(ret)

    def multiCall(self, calls):
        """Execute a multicall. Execute each method call in the calls list, collecting results and errors, and return those as a list."""
        results = []
        for call in calls:
            try:
                result = self._dispatch(call['methodName'], call['params'])
            except Fault, fault:
                results.append({'faultCode': fault.faultCode, 'faultString': fault.faultString})
            except:
                # transform unknown exceptions into XML-RPC Faults
                # don't create a reference to full traceback since this creates
                # a circular reference.
                exc_type, exc_value = sys.exc_info()[:2]
                faultCode = getattr(exc_type, 'faultCode', 1)
                faultString = ', '.join(exc_value.args)
                trace = traceback.format_exception(*sys.exc_info())
                # traceback is not part of the multicall spec, but we include it for debugging purposes
                results.append({'faultCode': faultCode, 'faultString': faultString, 'traceback': trace})
            else:
                results.append([result])

        return results

    def list_api(self):
        funcs = []
        for name,func in self.funcs.items():
            #the keys in self.funcs determine the name of the method as seen over xmlrpc
            #func.__name__ might differ (e.g. for dotted method names)
            args = self._getFuncArgs(func)
            doc = None
            try:
               doc = func.doc
            except AttributeError:
               doc = func.__doc__
            funcs.append({'name': name,
                          'doc': doc,
                          'args': args})
        return funcs

    def ping(self):
        """Simple test to see if the XML-RPC is up and active."""
        return "pong"

    def _getFuncArgs(self, func):
        try:
            # Plugins have this
            args = list(func.args)
            args.append("kw")
        except:
            # non-plugin functions such as the introspective ones
            args = []
            for x in range(0, func.func_code.co_argcount):
                if x == 0 and func.func_code.co_varnames[x] == "self":
                    continue
                # opts is a name we tack on internally. Don't publish it.
                if func.func_code.co_varnames[x] == "opts":
                    continue
                if func.func_defaults and func.func_code.co_argcount - x <= len(func.func_defaults):
                    args.append((func.func_code.co_varnames[x], func.func_defaults[x - func.func_code.co_argcount + len(func.func_defaults)]))
                else:
                    args.append(func.func_code.co_varnames[x])
        return args

    def system_listMethods(self):
        """List all available XML-RPC methods"""
        return self.funcs.keys()

    def system_methodSignature(self, method):
        """signatures are not supported"""
        #it is not possible to autogenerate this data
        return 'signatures not supported'

    def system_methodHelp(self, method):
        """Return help on a specific method"""
        func = self.funcs.get(method)
        if func is None:
            return ""
        arglist = []
        for arg in self._getFuncArgs(func):
            if isinstance(arg,str):
                arglist.append(arg)
            else:
                arglist.append('%s=%s' % (arg[0], arg[1]))
        ret = '%s(%s)' % (method, ", ".join(arglist))
        doc = None
        try:
           doc = func.doc
        except AttributeError:
           doc = func.__doc__
        if doc:
            ret += "\ndescription: %s" % func.__doc__
        return ret

    def handle_request(self,req):
        """Handle a single XML-RPC request"""

        # XMLRPC uses POST only. Reject anything else
        if req.method != 'POST':
            req.allow_methods(['POST'],1)
            raise apache.SERVER_RETURN, apache.HTTP_METHOD_NOT_ALLOWED

        # The LDAP connection pool is not thread-safe. Avoid problems and
        # force the forked model for now.
        if apache.mpm_query(apache.AP_MPMQ_IS_THREADED):
            response = dumps(Fault(3, "Apache must use the forked model"))
        else:
            response = self._marshaled_dispatch(req.read(), req)

        req.content_type = "text/xml"
        req.set_content_length(len(response))
        req.write(response)


#
# mod_python handler
#

def handler(req, profiling=False):
    h = ModXMLRPCRequestHandler()

    if profiling:
        import profile, pstats, StringIO, tempfile
        global _profiling_req
        _profiling_req = req
        temp = tempfile.NamedTemporaryFile()
        profile.run("import ipxmlrpc; ipaxmlrpc.handler(ipaxmlrpc._profiling_req, False)", temp.name)
        stats = pstats.Stats(temp.name)
        strstream = StringIO.StringIO()
        sys.stdout = strstream
        stats.sort_stats("time")
        stats.print_stats()
        req.write("<pre>" + strstream.getvalue() + "</pre>")
        _profiling_req = None
    else:
        context.opts = req.get_options()
        context.reqs = req
        try:
            h.handle_request(req)
        finally:
            # Clean up any per-request data and connections
            for k in context.__dict__.keys():
                del context.__dict__[k]

    return apache.OK

def setup_logger(level):
    """Make a global logging object."""
    l = logging.getLogger()
    l.setLevel(level)
    h = logging.StreamHandler()
    f = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
    h.setFormatter(f)
    l.addHandler(h)

    return

def load_modules():
    """Load all plugins and register the XML-RPC functions we provide.

       Called by mod_python PythonImport

       PythonImport /path/to/ipaxmlrpc.py::load_modules main_interpreter
       ...
       PythonInterpreter main_interpreter
       PythonHandler ipaxmlrpc
    """

    # Get and register all the methods
    for cmd in api.Command:
        logging.debug("registering XML-RPC call %s" % cmd)
        register_function(api.Command[cmd], cmd)
