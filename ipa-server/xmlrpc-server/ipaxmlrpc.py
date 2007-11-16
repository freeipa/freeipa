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

import sys
sys.path.append("/usr/share/ipa")


import time
import traceback
import pprint
from xmlrpclib import Marshaller,loads,dumps,Fault
from mod_python import apache

import ipaserver
import funcs
from ipa import ipaerror, ipautil
import ldap

import string
import base64

#
# An override so we can base64 encode all outgoing values. 
# This is set by calling: Marshaller._Marshaller__dump = xmlrpclib_dump
#
# Not currently used.
#
def xmlrpclib_escape(s, replace = string.replace):
    """
    xmlrpclib only handles certain characters. Lets encode the whole
    blob
    """

    return base64.encodestring(s)

def xmlrpclib_dump(self, value, write):
    """
    xmlrpclib cannot marshal instances of subclasses of built-in
    types. This function overrides xmlrpclib.Marshaller.__dump so that
    any value that is an instance of one of its acceptable types is
    marshalled as that type.

    xmlrpclib also cannot handle invalid 7-bit control characters. See
    above.
    """

    # Use our escape function
    args = [self, value, write]
    if isinstance(value, (str, unicode)):
        args.append(xmlrpclib_escape)

    try:
        # Try for an exact match first
        f = self.dispatch[type(value)]
    except KeyError:
        # Try for an isinstance() match
        for Type, f in self.dispatch.iteritems():
            if isinstance(value, Type):
                f(*args)
                return
        raise TypeError, "cannot marshal %s objects" % type(value)
    else:
        f(*args)


class ModXMLRPCRequestHandler(object):
    """Simple XML-RPC handler for mod_python environment"""

    def __init__(self):
        self.funcs = {}
        self.traceback = False
        #introspection functions
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

        opts={}
        opts['remoteuser'] = req.user

        if req.subprocess_env.get("KRB5CCNAME") is not None:
            opts['krbccache'] = req.subprocess_env.get("KRB5CCNAME")
        else:
            response = dumps(Fault(5, "Did not receive Kerberos credentials."))
            return response

        if pythonopts.get("IPADebug"):
            opts['ipadebug'] = pythonopts.get("IPADebug")

            if opts['ipadebug'].lower() == "on":
                for o in opts:
                    sys.stderr.write("IPA: setting option %s: %s\n" % (o, opts[o]))
                    sys.stderr.flush()
                for e in req.subprocess_env:
                    sys.stderr.write("IPA: environment %s: %s\n" % (e, req.subprocess_env[e]))
                    sys.stderr.flush()

        # Tack onto the end of the passed-in arguments any options we also
        # need
        params = params + (opts,)

        # special case
#        if method == "get_user":
#            Marshaller._Marshaller__dump = xmlrpclib_dump

        start = time.time()
        # generate response
        try:
            response = self._dispatch(method, params)
            # wrap response in a singleton tuple
            response = (response,)
            response = dumps(response, methodresponse=1, allow_none=1)
        except ipaerror.IPAError, e:
            self.traceback = True

            if (isinstance(e.detail, ldap.LDAPError)):
                err = ": %s: %s" % (e.detail.args[0]['desc'], e.detail.args[0].get('info',''))
                response = dumps(Fault(e.code, str(e) + err))
            else:
                response = dumps(Fault(e.code, str(e)))
        except:
            self.traceback = True
            # report exception back to server
            e_class, e = sys.exc_info()[:2]
            faultCode = getattr(e_class,'faultCode',1)
            tb_str = ''.join(traceback.format_exception(*sys.exc_info()))
            faultString = tb_str
            response = dumps(Fault(faultCode, faultString))

        return response

    def _dispatch(self,method,params):
        func = self.funcs.get(method,None)
        if func is None:
             raise Fault(1, "Invalid method: %s" % method)

        args = list(ipautil.unwrap_binary_data(params))
        for i in range(len(args)):
          if args[i] == '__NONE__':
              args[i] = None 

        ret = func(*args)

        return ipautil.wrap_binary_data(ret)

    def multiCall(self, calls):
        """Execute a multicall.  Execute each method call in the calls list, collecting
        results and errors, and return those as a list."""
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

    def list_api(self,opts):
        funcs = []
        for name,func in self.funcs.items():
            #the keys in self.funcs determine the name of the method as seen over xmlrpc
            #func.__name__ might differ (e.g. for dotted method names)
            args = self._getFuncArgs(func)
            funcs.append({'name': name,
                          'doc': func.__doc__,
                          'args': args})
        return funcs

    def _getFuncArgs(self, func):
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

    def system_listMethods(self, opts):
        return self.funcs.keys()

    def system_methodSignature(self, method, opts):
        #it is not possible to autogenerate this data
        return 'signatures not supported'

    def system_methodHelp(self, method, opts):
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
        if func.__doc__:
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
        opts = req.get_options()
        try:
            f = funcs.IPAServer()
            h = ModXMLRPCRequestHandler()
            h.register_function(f.get_aci_entry)
            h.register_function(f.get_entry_by_dn)
            h.register_function(f.get_entry_by_cn)
            h.register_function(f.update_entry)
            h.register_function(f.get_user_by_uid)
            h.register_function(f.get_user_by_principal)
            h.register_function(f.get_user_by_email)
            h.register_function(f.get_users_by_manager)
            h.register_function(f.add_user)
            h.register_function(f.get_custom_fields)
            h.register_function(f.set_custom_fields)
            h.register_function(f.get_all_users)
            h.register_function(f.find_users)
            h.register_function(f.update_user)
            h.register_function(f.delete_user)
            h.register_function(f.mark_user_deleted)
            h.register_function(f.modifyPassword)
            h.register_function(f.get_groups_by_member)
            h.register_function(f.add_group)
            h.register_function(f.find_groups)
            h.register_function(f.add_member_to_group)
            h.register_function(f.add_members_to_group)
            h.register_function(f.remove_member_from_group)
            h.register_function(f.remove_members_from_group)
            h.register_function(f.add_user_to_group)
            h.register_function(f.add_users_to_group)
            h.register_function(f.add_group_to_group)
            h.register_function(f.remove_user_from_group)
            h.register_function(f.remove_users_from_group)
            h.register_function(f.add_groups_to_user)
            h.register_function(f.remove_groups_from_user)
            h.register_function(f.update_group)
            h.register_function(f.delete_group)
            h.register_function(f.attrs_to_labels)
            h.register_function(f.group_members)
            h.register_function(f.get_ipa_config)
            h.register_function(f.update_ipa_config)
            h.register_function(f.get_password_policy)
            h.register_function(f.update_password_policy)
            h.handle_request(req)
        finally:
             pass
    return apache.OK
