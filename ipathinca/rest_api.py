# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
REST API Server for Python CA - Replacement for pki-tomcat

This module provides a Flask-based REST API server that implements the
PKI REST API endpoints, allowing ipathinca to serve as a drop-in
replacement for Dogtag PKI's pki-tomcat service.
"""

import logging
import argparse

from flask import Flask, request

# Import REST API helpers
from ipathinca.rest_api_helpers import (
    # Decorators
    # Validators
    # Response helpers
    error_response,
    # Handler classes
    # Legacy helpers
)

# Configure logging - will be set from config in create_app()
logger = logging.getLogger(__name__)

# Create Flask application
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# Global configuration (loaded from ipathinca.conf)
ipa_ca_config = None


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
    logger.error(f"Internal server error: {error}")
    return error_response("InternalServerError", "Internal server error", 500)


# ============================================================================
# Main Entry Point
# ============================================================================


def create_app(config=None):
    """
    Application factory

    Args:
        config: Dictionary containing 'config' key with RawConfigParser object
                from ipathinca.conf
    """
    global ipa_ca_config

    if config:
        # Store the ipathinca.conf configuration for use by the application
        if "config" in config:
            ipa_ca_config = config["config"]

            # Configure logger level from config
            log_level = ipa_ca_config.get("logging", "level", fallback="INFO")
            logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
            logger.debug(
                "Stored ipathinca.conf configuration for application use "
                f"(log level: {log_level})"
            )

        # Update Flask's internal config
        app.config.update(config)

    # Initialize backends on startup

    return app


def main():
    """Main entry point for running the server"""

    parser = argparse.ArgumentParser(description="Python CA REST API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
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
        logger.debug(f"SSL enabled with cert: {args.ssl_cert}")

    logger.debug(
        f"Starting Python CA REST API server on {args.host}:{args.port}"
    )

    # Run Flask application
    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        ssl_context=ssl_context,
    )


if __name__ == "__main__":
    main()
