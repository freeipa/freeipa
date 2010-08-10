"""
WSGI appliction for IPA server.
"""
from ipalib import api
from ipalib.config import Env
from ipalib.constants import DEFAULT_CONFIG

# Determine what debug level is configured. We can only do this
# by reading in the configuration file(s). The server always reads
# default.conf and will also read in `context'.conf.
env = Env()
env._bootstrap(context='server', log=None)
env._finalize_core(**dict(DEFAULT_CONFIG))

# Initialize the API with the proper debug level
api.bootstrap(context='server', debug=env.debug, log=None)
try:
    api.finalize()
except StandardError, e:
    api.log.error('Failed to start IPA: %s' % e)
else:
    api.log.info('*** PROCESS START ***')

    # This is the WSGI callable:
    application = api.Backend.session
