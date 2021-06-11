# Copyright (C) 2015  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import

import json
import os
from base64 import b64decode, b64encode

from custodia import log
from custodia.message.common import UnallowedMessage
from custodia.message.common import UnknownMessageType
from custodia.message.formats import Validator
from custodia.plugin import (
    CSStoreDenied, CSStoreError, CSStoreExists, CSStoreUnsupported
)
from custodia.plugin import HTTPConsumer, HTTPError, PluginOption


class Secrets(HTTPConsumer):
    allowed_keytypes = PluginOption('str_set', 'simple', None)
    store = PluginOption('store', None, None)

    def __init__(self, config, section):
        super(Secrets, self).__init__(config, section)
        self._validator = Validator(self.allowed_keytypes)

    def _db_key(self, trail):
        if len(trail) < 2:
            self.logger.debug(
                "Forbidden action: Operation only permitted within a "
                "container")
            raise HTTPError(403)
        return os.path.join('keys', *trail)

    def _db_container_key(self, default, trail):
        f = None
        if len(trail) > 1:
            f = self._db_key(trail)
        elif len(trail) == 1 and trail[0] != '':
            self.logger.debug(
                "Forbidden action: Wrong container path. Container names must "
                "end with '/'")
            raise HTTPError(403)
        elif default is None:
            self.logger.debug("Forbidden action: No default namespace")
            raise HTTPError(403)
        else:
            # Use the default namespace
            f = self._db_key([default, ''])
        return f

    def _parse(self, request, query, name):
        return self._validator.parse(request, query, name)

    def _parse_query(self, request, name):
        # default to simple
        query = request.get('query', '')
        if len(query) == 0:
            query = {'type': 'simple', 'value': ''}
        return self._parse(request, query, name)

    def _parse_bin_body(self, request, name):
        body = request.get('body')
        if body is None:
            raise HTTPError(400)
        value = b64encode(bytes(body)).decode('utf-8')
        payload = {'type': 'simple', 'value': value}
        return self._parse(request, payload, name)

    def _parse_body(self, request, name):
        body = request.get('body')
        if body is None:
            raise HTTPError(400)
        value = json.loads(bytes(body).decode('utf-8'))
        return self._parse(request, value, name)

    def _parse_maybe_body(self, request, name):
        body = request.get('body')
        if body is None:
            value = {'type': 'simple', 'value': ''}
        else:
            value = json.loads(bytes(body).decode('utf-8'))
        return self._parse(request, value, name)

    def _parent_exists(self, default, trail):
        # check that the containers exist
        basename = self._db_container_key(trail[0], trail[:-1] + [''])
        try:
            keylist = self.root.store.list(basename)
        except CSStoreError:
            raise HTTPError(500)

        self.logger.debug('parent_exists: %s (%s, %r) -> %r',
                          basename, default, trail, keylist)

        if keylist is not None:
            return True

        # create default namespace if it is the only missing piece
        if len(trail) == 2 and default == trail[0]:
            container = self._db_container_key(default, '')
            self.root.store.span(container)
            return True

        return False

    def _format_reply(self, request, response, handler, output):
        reply = handler.reply(output)
        # special case to allow *very* simple clients
        if handler.msg_type == 'simple':
            binary = False
            accept = request.get('headers', {}).get('Accept', None)
            if accept is not None:
                types = accept.split(',')
                for t in types:
                    if t.strip() == 'application/json':
                        binary = False
                        break
                    elif t.strip() == 'application/octet-stream':
                        binary = True
            if binary is True:
                response['headers'][
                    'Content-Type'] = 'application/octet-stream'
                response['output'] = b64decode(reply['value'])
                return

        if reply is not None:
            response['headers'][
                'Content-Type'] = 'application/json; charset=utf-8'
            response['output'] = reply

    def GET(self, request, response):
        trail = request.get('trail', [])
        if len(trail) == 0 or trail[-1] == '':
            self._list(trail, request, response)
        else:
            self._get_key(trail, request, response)

    def PUT(self, request, response):
        trail = request.get('trail', [])
        if len(trail) == 0 or trail[-1] == '':
            raise HTTPError(405)
        else:
            self._set_key(trail, request, response)

    def DELETE(self, request, response):
        trail = request.get('trail', [])
        if len(trail) == 0:
            raise HTTPError(405)
        if trail[-1] == '':
            self._destroy(trail, request, response)
        else:
            self._del_key(trail, request, response)

    def POST(self, request, response):
        trail = request.get('trail', [])
        if len(trail) > 0 and trail[-1] == '':
            self._create(trail, request, response)
        else:
            raise HTTPError(405)

    def _list(self, trail, request, response):
        try:
            name = '/'.join(trail)
            msg = self._parse_query(request, name)
        except Exception as e:
            raise HTTPError(406, str(e))
        default = request.get('default_namespace', None)
        basename = self._db_container_key(default, trail)
        try:
            keylist = self.root.store.list(basename)
            self.logger.debug('list %s returned %r', basename, keylist)
            if keylist is None:
                raise HTTPError(404)
            response['headers'][
                'Content-Type'] = 'application/json; charset=utf-8'
            response['output'] = msg.reply(keylist)
        except CSStoreDenied:
            self.logger.exception(
                "List: Permission to perform this operation was denied")
            raise HTTPError(403)
        except CSStoreError:
            self.logger.exception('List: Internal server error')
            raise HTTPError(500)
        except CSStoreUnsupported:
            self.logger.exception('List: Unsupported operation')
            raise HTTPError(501)

    def _create(self, trail, request, response):
        try:
            name = '/'.join(trail)
            msg = self._parse_maybe_body(request, name)
        except Exception as e:
            raise HTTPError(406, str(e))
        default = request.get('default_namespace', None)
        basename = self._db_container_key(None, trail)
        try:
            if len(trail) > 2:
                ok = self._parent_exists(default, trail[:-1])
                if not ok:
                    raise HTTPError(404)

            self.root.store.span(basename)
        except CSStoreDenied:
            self.logger.exception(
                "Create: Permission to perform this operation was denied")
            raise HTTPError(403)
        except CSStoreExists:
            self.logger.debug('Create: Key already exists')
            response['code'] = 200
            return
        except CSStoreError:
            self.logger.exception('Create: Internal server error')
            raise HTTPError(500)
        except CSStoreUnsupported:
            self.logger.exception('Create: Unsupported operation')
            raise HTTPError(501)

        output = msg.reply(None)
        if output is not None:
            response['headers'][
                'Content-Type'] = 'application/json; charset=utf-8'
            response['output'] = output
        response['code'] = 201

    def _destroy(self, trail, request, response):
        try:
            name = '/'.join(trail)
            msg = self._parse_maybe_body(request, name)
        except Exception as e:
            raise HTTPError(406, str(e))
        basename = self._db_container_key(None, trail)
        try:
            keylist = self.root.store.list(basename)
            if keylist is None:
                raise HTTPError(404)
            if len(keylist) != 0:
                raise HTTPError(409)
            ret = self.root.store.cut(basename.rstrip('/'))
        except CSStoreDenied:
            self.logger.exception(
                "Delete: Permission to perform this operation was denied")
            raise HTTPError(403)
        except CSStoreError:
            self.logger.exception('Delete: Internal server error')
            raise HTTPError(500)
        except CSStoreUnsupported:
            self.logger.exception('Delete: Unsupported operation')
            raise HTTPError(501)

        if ret is False:
            raise HTTPError(404)

        output = msg.reply(None)
        if output is None:
            response['code'] = 204
        else:
            response['headers'][
                'Content-Type'] = 'application/json; charset=utf-8'
            response['output'] = output
            response['code'] = 200

    def _client_name(self, request):
        if 'remote_user' in request:
            return request['remote_user']
        elif 'creds' in request:
            creds = request['creds']
            return '<pid={pid:d} uid={uid:d} gid={gid:d}>'.format(**creds)
        else:
            return 'Unknown'

    def _audit(self, ok, fail, fn, trail, request, response):
        action = fail
        client = self._client_name(request)
        key = '/'.join(trail)
        try:
            fn(trail, request, response)
            action = ok
        finally:
            self.audit_key_access(action, client, key)

    def _get_key(self, trail, request, response):
        self._audit(log.AUDIT_GET_ALLOWED, log.AUDIT_GET_DENIED,
                    self._int_get_key, trail, request, response)

    def _int_get_key(self, trail, request, response):
        try:
            name = '/'.join(trail)
            handler = self._parse_query(request, name)
        except Exception as e:
            raise HTTPError(406, str(e))
        key = self._db_key(trail)
        try:
            output = self.root.store.get(key)
            if output is None:
                raise HTTPError(404)
            elif len(output) == 0:
                raise HTTPError(406)
            self._format_reply(request, response, handler, output)
        except CSStoreDenied:
            self.logger.exception(
                "Get: Permission to perform this operation was denied")
            raise HTTPError(403)
        except CSStoreError:
            self.logger.exception('Get: Internal server error')
            raise HTTPError(500)
        except CSStoreUnsupported:
            self.logger.exception('Get: Unsupported operation')
            raise HTTPError(501)

    def _set_key(self, trail, request, response):
        self._audit(log.AUDIT_SET_ALLOWED, log.AUDIT_SET_DENIED,
                    self._int_set_key, trail, request, response)

    def _int_set_key(self, trail, request, response):
        try:
            name = '/'.join(trail)

            content_type = request.get('headers', {}).get('Content-Type', '')
            content_type_value = content_type.split(';')[0].strip()
            if content_type_value == 'application/octet-stream':
                msg = self._parse_bin_body(request, name)
            elif content_type_value == 'application/json':
                msg = self._parse_body(request, name)
            else:
                raise ValueError('Invalid Content-Type')
        except UnknownMessageType as e:
            raise HTTPError(406, str(e))
        except UnallowedMessage as e:
            raise HTTPError(406, str(e))
        except Exception as e:
            raise HTTPError(400, str(e))

        # must _db_key first as access control is done here for now
        # otherwise users would e able to probe containers in namespaces
        # they do not have access to.
        key = self._db_key(trail)

        try:
            default = request.get('default_namespace', None)
            ok = self._parent_exists(default, trail)
            if not ok:
                raise HTTPError(404)

            ok = self.root.store.set(key, msg.payload)
        except CSStoreDenied:
            self.logger.exception(
                "Set: Permission to perform this operation was denied")
            raise HTTPError(403)
        except CSStoreExists:
            self.logger.exception('Set: Key already exist')
            raise HTTPError(409)
        except CSStoreError:
            self.logger.exception('Set: Internal Server Error')
            raise HTTPError(500)
        except CSStoreUnsupported:
            self.logger.exception('Set: Unsupported operation')
            raise HTTPError(501)

        output = msg.reply(None)
        if output is not None:
            response['headers'][
                'Content-Type'] = 'application/json; charset=utf-8'
            response['output'] = output
        response['code'] = 201

    def _del_key(self, trail, request, response):
        self._audit(log.AUDIT_DEL_ALLOWED, log.AUDIT_DEL_DENIED,
                    self._int_del_key, trail, request, response)

    def _int_del_key(self, trail, request, response):
        try:
            name = '/'.join(trail)
            msg = self._parse_maybe_body(request, name)
        except Exception as e:
            raise HTTPError(406, str(e))
        key = self._db_key(trail)
        try:
            ret = self.root.store.cut(key)
        except CSStoreDenied:
            self.logger.exception(
                "Delete: Permission to perform this operation was denied")
            raise HTTPError(403)
        except CSStoreError:
            self.logger.exception('Delete: Internal Server Error')
            raise HTTPError(500)
        except CSStoreUnsupported:
            self.logger.exception('Delete: Unsupported operation')
            raise HTTPError(501)

        if ret is False:
            raise HTTPError(404)

        output = msg.reply(None)
        if output is None:
            response['code'] = 204
        else:
            response['headers'][
                'Content-Type'] = 'application/json; charset=utf-8'
            response['output'] = output
            response['code'] = 200
