"""
WSGI appliction for IPA server.
"""

from ipalib import api
api.bootstrap(context='server', debug=True, log=None)
try:
    api.finalize()
except StandardError, e:
    api.log.error('Failed to start IPA: %s' % e)
else:
    api.log.info('*** PROCESS START ***')
    import ipawebui
    ui = ipawebui.create_wsgi_app(api)

    # This is the WSGI callable:
    application = api.Backend.session
