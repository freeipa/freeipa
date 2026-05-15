# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
REST API Server for Python CA - Replacement for pki-tomcat

This package provides a Flask-based REST API server that implements the
PKI REST API endpoints, allowing ipacta to serve as a drop-in
replacement for Dogtag PKI's pki-tomcat service.
"""

import argparse
import importlib
import logging
import pkgutil

from flask import Flask, request

from ipacta.rest_api._helpers import error_response
import ipacta.rest_api._globals as _g

logger = logging.getLogger(__name__)

# Create Flask application
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


# ============================================================================
# Error Handlers
# ============================================================================


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return error_response(
        "NotFound", f"Endpoint not found: {request.path}", 404
    )


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error("Internal server error: %s", error)
    return error_response("InternalServerError", "Internal server error", 500)


# ============================================================================
# Auto-discover and register blueprints
# ============================================================================

for _importer, modname, _ispkg in pkgutil.iter_modules(
    __path__, __name__ + "."
):
    if modname.rsplit(".", 1)[-1].startswith("_"):
        continue
    mod = importlib.import_module(modname)
    if hasattr(mod, "bp"):
        app.register_blueprint(mod.bp)


# ============================================================================
# Application Factory and Main Entry Point
# ============================================================================


def create_app(config=None):
    """
    Application factory

    Args:
        config: Dictionary containing 'config' key with RawConfigParser object
                from ipacta.conf
    """
    if config:
        # Store the ipacta.conf configuration for use by the application
        if "config" in config:
            _g.ipa_ca_config = config["config"]

            # Configure logger level from config
            log_level = _g.ipa_ca_config.get(
                "logging", "level", fallback="INFO"
            )
            logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
            logger.debug(
                "Stored ipacta.conf configuration for application use "
                "(log level: %s)",
                log_level,
            )

        # Update Flask's internal config
        app.config.update(config)

    # Initialize backends on startup
    with app.app_context():
        _g.init_ca()

    return app


def main():
    """Main entry point for running the server"""

    parser = argparse.ArgumentParser(description="Python CA REST API Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument(
        "--port", type=int, default=8080, help="Port to bind to"
    )
    parser.add_argument("--ssl-cert", help="SSL certificate file")
    parser.add_argument("--ssl-key", help="SSL key file")
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug mode"
    )

    args = parser.parse_args()

    # Configure SSL if certificates provided
    ssl_context = None
    if args.ssl_cert and args.ssl_key:
        ssl_context = (args.ssl_cert, args.ssl_key)
        logger.debug("SSL enabled with cert: %s", args.ssl_cert)

    logger.debug(
        "Starting Python CA REST API server on %s:%s", args.host, args.port
    )

    # Run Flask application
    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        ssl_context=ssl_context,
    )


def __getattr__(name):
    """Lazy re-export of ca_backend and kra_backend from _globals"""
    if name == "ca_backend":
        return _g.ca_backend
    if name == "kra_backend":
        return _g.kra_backend
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if __name__ == "__main__":
    main()
