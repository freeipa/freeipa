# Copyright (C) 2026  FreeIPA Contributors see COPYING for license

"""
Gunicorn configuration for ipacta.

Loaded via --config python:ipacta.gunicorn_conf when ipacta is started
by wsgi.py::main().  The post_fork hook reinitialises the LDAP connection pool
and logging file handlers in every worker after Gunicorn forks them away from
the master process.

With --preload the master imports the WSGI application (including the LDAP
pool globals and any logging FileHandlers) before forking workers.  Without
explicit reinitialisation:
- LDAP connections are not fork-safe (python-ldap protocol corruption)
- FileHandlers share the same underlying OS file description and the same
  Python TextIO buffer state with the master, causing tell()/flush() in the
  worker to block when the master is concurrently writing to the same fd.
"""

import io
import logging
import sys

logger = logging.getLogger(__name__)


def _reopen_log_handlers(worker_pid):
    """Close and reopen all inherited FileHandler instances after fork.

    After os.fork() the child inherits a copy of the master's open file
    descriptors and Python TextIO buffer state.  Concurrent use of the
    shared OS file description from two processes causes tell()/flush()
    inside RotatingFileHandler.shouldRollover() to block indefinitely when
    the master is writing to the same fd.

    Strategy: detach the inherited TextIO buffer WITHOUT flushing (flush
    would redundantly write the master's buffered data a second time), then
    reopen the handler so the worker gets its own independent file description.
    """
    seen = set()

    def _reopen(handler):
        if not isinstance(handler, logging.FileHandler):
            return
        if id(handler) in seen:
            return
        seen.add(id(handler))
        try:
            old_stream = handler.stream
            if old_stream is not None:
                # Detach without flushing: the master owns the buffer content.
                try:
                    old_stream.detach()
                except (io.UnsupportedOperation, AttributeError):
                    try:
                        old_stream.close()
                    except Exception:
                        pass
            handler.stream = handler._open()
        except Exception as e:
            name = getattr(handler, "baseFilename", repr(handler))
            sys.stderr.write(
                f"Worker {worker_pid}: failed to reopen log handler"
                f" {name}: {e}\n"
            )

    root = logging.getLogger()
    for h in root.handlers:
        _reopen(h)

    for _name, log in logging.Logger.manager.loggerDict.items():
        if isinstance(log, logging.Logger):
            for h in log.handlers:
                _reopen(h)


def post_fork(server, worker):
    """Reinitialise the LDAP pool and log file handlers in each worker.

    Called by Gunicorn in the worker process immediately after fork() returns.
    The inherited state from the master is discarded so each worker starts
    with its own independent, clean resources.
    """
    # Reopen log file handlers first so that subsequent log calls in this
    # hook go through a valid, worker-owned file description.
    _reopen_log_handlers(worker.pid)

    try:
        from ipacta.ldap_utils import close_ldap_pool, close_ldap_connection
        close_ldap_pool()
        close_ldap_connection()
        logger.debug(
            "Worker %s: LDAP pool reinitialised after fork", worker.pid
        )
    except Exception as e:
        logger.warning(
            "Worker %s: failed to reinitialise LDAP pool after fork: %s",
            worker.pid,
            e,
        )


def worker_exit(server, worker):
    """Clean up LDAP pool when a worker shuts down."""
    try:
        from ipacta.ldap_utils import close_ldap_pool, close_ldap_connection
        close_ldap_pool()
        close_ldap_connection()
    except Exception:
        pass
