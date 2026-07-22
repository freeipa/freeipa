#!/usr/bin/env python3
# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
WSGI Application Entry Point for Python CA REST API Server

This module provides the WSGI application entry point using Gunicorn
or other WSGI servers for production deployment.
"""

import os
import logging
from pathlib import Path

from ipaplatform.paths import paths

logger = logging.getLogger(__name__)


def setup_logging(config):
    """Setup logging based on configuration"""
    log_level = config.get("logging", "level", fallback="INFO")
    log_file = config.get(
        "logging",
        "log_file",
        fallback=f"{paths.IPACTA_LOG_DIR}/ipacta.log",
    )

    # Create log directory if it doesn't exist
    log_dir = Path(log_file).parent
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        logger.warning(
            "Cannot create log directory %s, logging to console only", log_dir
        )
        return

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # File handler with rotation
    try:
        from logging.handlers import RotatingFileHandler

        max_bytes = int(
            config.get("logging", "max_log_size", fallback="10485760")
        )
        backup_count = int(
            config.get("logging", "backup_count", fallback="10")
        )

        file_handler = RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count
        )
        file_handler.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(formatter)

        root_logger.addHandler(file_handler)
        logger.debug("Logging to file: %s", log_file)

    except Exception as e:
        logger.warning("Failed to setup file logging: %s", e)


def create_wsgi_app():
    """Create WSGI application with configuration"""
    # Bootstrap logging before any other import so early errors are visible.
    # Guard against re-configuration when the module is imported multiple times
    # (e.g. test suites) or after Gunicorn forks.
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

    # Load configuration from file specified in environment or default
    from ipacta.config import IpactaConfig, WSGI_DEFAULTS

    config_file = os.environ.get("IPACTA_CONFIG", paths.IPACTA_CONF)
    config = IpactaConfig.from_file(
        config_file, strict=False, defaults=WSGI_DEFAULTS
    )

    # Setup logging
    setup_logging(config)

    logger.debug(
        "Initializing Python CA REST API Server (config: %s)", config_file
    )

    # Import and create Flask app
    try:
        from ipacta.rest_api import create_app

        # Create application with configuration
        app = create_app({"config": config})

        # Limit request body size to prevent DoS (10 MB)
        app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

        logger.debug("Python CA REST API Server initialized successfully")
        logger.debug("Configuration loaded from: %s", config_file)

        # Log key configuration values for debugging
        if config.has_section("server"):
            bind_host = config.get("server", "bind_host", fallback="not set")
            https_port = config.get("server", "https_port", fallback="not set")
            workers = config.get("server", "workers", fallback="not set")
            threads = config.get("server", "threads", fallback="not set")
            logger.info("Server bind_host: %s", bind_host)
            logger.info("Server https_port: %s", https_port)
            logger.info("Server workers: %s", workers)
            logger.info("Server threads: %s", threads)

        # Start resource tracking if configured under [debug] section.
        # resource_log_interval = 300   (seconds; 0 = disabled)
        # tracemalloc = false           (set true for allocation tracing)
        try:
            raw_interval = config.get(
                "debug", "resource_log_interval", fallback="0"
            )
            interval = float(raw_interval)
            if interval > 0:
                from ipacta.resource_tracker import (
                    enable_tracemalloc,
                    start_periodic_logging,
                )
                tm_env = os.environ.get(
                    "IPACTA_TRACEMALLOC", ""
                ).lower()
                tm_cfg = config.get(
                    "debug", "tracemalloc", fallback="false"
                ).lower()
                if tm_env in ("1", "true", "yes") or tm_cfg in (
                    "1",
                    "true",
                    "yes",
                ):
                    enable_tracemalloc()
                start_periodic_logging(interval)
        except Exception as e:
            logger.warning("Failed to start resource tracking: %s", e)

        return app

    except ImportError as e:
        logger.error("Failed to import ipacta modules: %s", e)
        logger.error("Make sure ipacta is properly installed")
        raise
    except Exception as e:
        logger.error("Failed to initialize application: %s", e, exc_info=True)
        raise


# Create WSGI application instance.
# This runs at module import time so Gunicorn can find 'application'.
# Callers (tests, tools) that import this module should be prepared for
# exceptions here when the environment is not configured.
application = create_wsgi_app()


def main():
    """Main entry point for running with Gunicorn"""
    import argparse

    parser = argparse.ArgumentParser(description="Python CA WSGI Server")
    parser.add_argument(
        "--config",
        default=paths.IPACTA_CONF,
        help="Configuration file path",
    )
    parser.add_argument(
        "--bind", default="127.0.0.1:8080", help="Bind address (host:port)"
    )
    parser.add_argument(
        "--workers", type=int, default=1, help="Number of worker processes"
    )
    parser.add_argument(
        "--threads", type=int, default=4, help="Number of threads per worker"
    )
    parser.add_argument(
        "--worker-class",
        default="gthread",
        choices=["sync", "gthread", "gevent", "eventlet"],
        help="Worker class type",
    )
    parser.add_argument("--certfile", help="SSL certificate file")
    parser.add_argument("--keyfile", help="SSL key file")
    parser.add_argument(
        "--daemon", action="store_true", help="Daemonize the Gunicorn process"
    )
    parser.add_argument(
        "--pid", default="/run/ipacta/ipacta.pid", help="PID file path"
    )
    parser.add_argument(
        "--access-logfile",
        default=f"{paths.IPACTA_LOG_DIR}/access.log",
        help="Access log file",
    )
    parser.add_argument(
        "--error-logfile",
        default=f"{paths.IPACTA_LOG_DIR}/gunicorn.log",
        help="Gunicorn log file",
    )

    args = parser.parse_args()

    # Build Gunicorn command
    gunicorn_args = [
        "gunicorn",
        # gunicorn_conf.py defines post_fork() to reinitialise the LDAP
        # pool in every worker after --preload forks them from the master.
        "--config",
        "python:ipacta.gunicorn_conf",
        "--bind",
        args.bind,
        "--workers",
        str(args.workers),
        "--threads",
        str(args.threads),
        "--worker-class",
        args.worker_class,
        "--timeout",
        "120",
        "--access-logfile",
        args.access_logfile,
        "--error-logfile",
        args.error_logfile,
        "--pid",
        args.pid,
        "--preload",
    ]

    # Add SSL if specified
    if args.certfile and args.keyfile:
        gunicorn_args.extend(
            [
                "--certfile",
                args.certfile,
                "--keyfile",
                args.keyfile,
            ]
        )

    # Add daemon mode if requested
    if args.daemon:
        gunicorn_args.append("--daemon")

    # Add WSGI module
    gunicorn_args.append("ipacta.wsgi:application")

    logger.debug("Starting Gunicorn with: %s", " ".join(gunicorn_args))

    # Execute Gunicorn
    os.execvp("gunicorn", gunicorn_args)


if __name__ == "__main__":
    # Check if running under Gunicorn
    if "gunicorn" in os.environ.get("SERVER_SOFTWARE", ""):
        # Running under Gunicorn, use the application instance
        pass
    else:
        # Running standalone, start Gunicorn
        main()
