# Copyright (C) 2015  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import

import logging
import sys
import warnings


import six


LOGGING_FORMAT = "%(asctime)s - %(origin)-32s - %(message)s"
LOGGING_DATEFORMAT = "%Y-%m-%d %H:%M:%S"


class OriginContextFilter(logging.Filter):
    """Context filter to include 'origin' attribute in record
    """
    def filter(self, record):
        if not hasattr(record, 'origin'):
            record.origin = record.name.split('.')[-1]

        return True


class CustodiaFormatter(logging.Formatter):
    def format(self, record):
        # customize record.exc_text, Formatter.format() does not modify
        # exc_text when it has been set before.
        short_exc = False
        if record.exc_info and not record.exc_text:
            if getattr(record, "exc_fullstack", True):
                record.exc_text = self.formatException(record.exc_info)
            else:
                short_exc = True
                record.exc_text = u"{0.__name__}: {1}".format(
                    record.exc_info[0], record.exc_info[1]
                )

        result = super(CustodiaFormatter, self).format(record)
        if short_exc:
            # format() adds \n between message and exc_text
            text, exc = result.rsplit(u'\n', 1)
            return u"{0} ({1})".format(text, exc)
        else:
            return result


class CustodiaLoggingAdapter(logging.LoggerAdapter):
    def __init__(self, plugin, debug):
        logger = logging.getLogger(
            '{0.__class__.__module__}.{0.__class__.__name__}'.format(plugin)
        )
        logger.setLevel(logging.DEBUG if debug else logging.INFO)
        extra = {'origin': plugin.origin}
        super(CustodiaLoggingAdapter, self).__init__(logger, extra=extra)

    # pylint: disable=arguments-differ
    def exception(self, msg, *args, **kwargs):
        """Like standard exception() logger but only print stack in debug mode
        """
        extra = kwargs.setdefault('extra', {})
        extra['exc_fullstack'] = self.isEnabledFor(logging.DEBUG)
        kwargs['exc_info'] = True
        self.log(logging.ERROR, msg, *args, **kwargs)


def getLogger(name):
    """Create logger with custom exception() method
    """
    def exception(self, msg, *args, **kwargs):
        extra = kwargs.setdefault('extra', {})
        extra['exc_fullstack'] = self.isEnabledFor(logging.DEBUG)
        kwargs['exc_info'] = True
        self.log(logging.ERROR, msg, *args, **kwargs)

    logger = logging.getLogger(name)
    logger.exception = six.create_bound_method(exception, logger)
    return logger


def setup_logging(debug=False, auditfile=None, handler=None):
    root_logger = logging.getLogger()
    # default is stream handler to stderr
    if handler is None:
        handler = logging.StreamHandler(sys.stderr)

    # remove handler instance from root handler to prevent multiple
    # output handlers.
    handler_cls = type(handler)
    root_logger.handlers[:] = list(
        h for h in root_logger.handlers if not isinstance(h, handler_cls)
    )

    # configure handler
    handler.setFormatter(CustodiaFormatter(
        fmt=LOGGING_FORMAT, datefmt=LOGGING_DATEFORMAT
    ))
    handler.addFilter(OriginContextFilter())
    root_logger.addHandler(handler)

    # set logging level
    custodia_logger = getLogger('custodia')
    if debug:
        custodia_logger.setLevel(logging.DEBUG)
        custodia_logger.debug('Custodia debug logger enabled')
        # If the global debug is enabled, turn debug on in all 'custodia.*'
        # loggers
        logdict = logging.Logger.manager.loggerDict
        for name, obj in logdict.items():
            if not isinstance(obj, logging.Logger):
                continue
            if name.startswith('custodia.'):
                obj.setLevel(logging.DEBUG)
    else:
        custodia_logger.setLevel(logging.INFO)

    # setup file handler for audit log
    audit_logger = logging.getLogger('custodia.audit')
    if auditfile is not None and len(audit_logger.handlers) == 0:
        audit_fmt = logging.Formatter(LOGGING_FORMAT, LOGGING_DATEFORMAT)
        audit_hdrl = logging.FileHandler(auditfile)
        audit_hdrl.setFormatter(audit_fmt)
        audit_logger.addHandler(audit_hdrl)

        custodia_logger.debug('Custodia audit log: %s', auditfile)


AUDIT_NONE = 0
AUDIT_GET_ALLOWED = 1
AUDIT_GET_DENIED = 2
AUDIT_SET_ALLOWED = 3
AUDIT_SET_DENIED = 4
AUDIT_DEL_ALLOWED = 5
AUDIT_DEL_DENIED = 6
AUDIT_LAST = 7
AUDIT_SVC_NONE = 8
AUDIT_SVC_AUTH_PASS = 9
AUDIT_SVC_AUTH_FAIL = 10
AUDIT_SVC_AUTHZ_PASS = 11
AUDIT_SVC_AUTHZ_FAIL = 12
AUDIT_SVC_LAST = 13
AUDIT_MESSAGES = [
    "AUDIT FAILURE",
    "ALLOWED: '%(client)s' requested key '%(key)s'",  # AUDIT_GET_ALLOWED
    "DENIED: '%(client)s' requested key '%(key)s'",   # AUDIT_GET_DENIED
    "ALLOWED: '%(client)s' stored key '%(key)s'",     # AUDIT_SET_ALLOWED
    "DENIED: '%(client)s' stored key '%(key)s'",      # AUDIT_SET_DENIED
    "ALLOWED: '%(client)s' deleted key '%(key)s'",    # AUDIT_DEL_ALLOWED
    "DENIED: '%(client)s' deleted key '%(key)s'",     # AUDIT_DEL_DENIED
    "AUDIT FAILURE 7",
    "AUDIT FAILURE 8",
    "PASS: '%(cli)s' authenticated as '%(name)s'",  # SVC_AUTH_PASS
    "FAIL: '%(cli)s' authenticated as '%(name)s'",  # SVC_AUTH_FAIL
    "PASS: '%(cli)s' authorized for '%(name)s'",    # SVC_AUTHZ_PASS
    "FAIL: '%(cli)s' authorized for '%(name)s'",    # SVC_AUTHZ_FAIL
    "AUDIT FAILURE 13",
]


class AuditLog(object):
    def __init__(self, logger):
        self.logger = logger

    def key_access(self, origin, action, client, keyname):
        if action <= AUDIT_NONE or action >= AUDIT_LAST:
            action = AUDIT_NONE
        msg = AUDIT_MESSAGES[action]
        args = {'client': client, 'key': keyname}
        self.logger.info(msg, args, extra={'origin': origin})

    def svc_access(self, origin, action, client, name):
        if action <= AUDIT_SVC_NONE or action >= AUDIT_SVC_LAST:
            action = AUDIT_NONE
        msg = AUDIT_MESSAGES[action]
        args = {'cli': client, 'name': name}
        self.logger.info(msg, args, extra={'origin': origin})


auditlog = AuditLog(logging.getLogger('custodia.audit'))


class ProvisionalWarning(FutureWarning):
    pass


def warn_provisional(modulename, stacklevel=3):
    msg = ("Module '{}' is a provisional API. It may changed or get "
           "removed in future releases.")
    return warnings.warn(msg.format(modulename), ProvisionalWarning,
                         stacklevel=stacklevel)
