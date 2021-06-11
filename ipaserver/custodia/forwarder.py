# Copyright (C) 2015  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import

import uuid

from custodia.client import CustodiaHTTPClient
from custodia.plugin import HTTPConsumer, HTTPError
from custodia.plugin import INHERIT_GLOBAL, PluginOption, REQUIRED


class Forwarder(HTTPConsumer):
    forward_uri = PluginOption(str, REQUIRED, None)
    tls_cafile = PluginOption(str, INHERIT_GLOBAL(None), 'Path to CA file')
    tls_certfile = PluginOption(
        str, None, 'Path to cert file for client cert auth')
    tls_keyfile = PluginOption(
        str, None, 'Path to key file for client cert auth')
    forward_headers = PluginOption('json', '{}', None)
    prefix_remote_user = PluginOption(bool, True, None)
    timeout = PluginOption(float, 10.0, 'Connection timeout in seconds')

    def __init__(self, config, section):
        super(Forwarder, self).__init__(config, section)
        self.client = CustodiaHTTPClient(self.forward_uri)
        if self.tls_certfile is not None:
            self.client.set_client_cert(self.tls_certfile, self.tls_keyfile)
        if self.tls_cafile is not None:
            self.client.set_ca_cert(self.tls_cafile)
        self.client.timeout = self.timeout
        self.uuid = str(uuid.uuid4())
        # pylint: disable=unsubscriptable-object
        # pylint: disable=unsupported-assignment-operation
        self.forward_headers['X-LOOP-CUSTODIA'] = self.uuid

    def _path(self, request):
        trail = request.get('trail', [])
        if self.prefix_remote_user:
            prefix = [request.get('remote_user', 'guest').rstrip('/')]
        else:
            prefix = []
        return '/'.join(prefix + trail)

    def _headers(self, request):
        headers = {}
        headers.update(self.forward_headers)
        loop = request['headers'].get('X-LOOP-CUSTODIA', None)
        if loop is not None:
            headers['X-LOOP-CUSTODIA'] += ',' + loop
        return headers

    def _response(self, reply, response):
        if reply.status_code < 200 or reply.status_code > 299:
            raise HTTPError(reply.status_code)
        response['code'] = reply.status_code
        if reply.content:
            response['output'] = reply.content

    def _request(self, cmd, request, response, path, **kwargs):
        if self.uuid in request['headers'].get('X-LOOP-CUSTODIA', ''):
            raise HTTPError(502, "Loop detected")
        reply = cmd(path, **kwargs)
        self._response(reply, response)

    def GET(self, request, response):
        self._request(self.client.get, request, response,
                      self._path(request),
                      params=request.get('query', None),
                      headers=self._headers(request))

    def PUT(self, request, response):
        self._request(self.client.put, request, response,
                      self._path(request),
                      data=request.get('body', None),
                      params=request.get('query', None),
                      headers=self._headers(request))

    def DELETE(self, request, response):
        self._request(self.client.delete, request, response,
                      self._path(request),
                      params=request.get('query', None),
                      headers=self._headers(request))

    def POST(self, request, response):
        self._request(self.client.post, request, response,
                      self._path(request),
                      data=request.get('body', None),
                      params=request.get('query', None),
                      headers=self._headers(request))
