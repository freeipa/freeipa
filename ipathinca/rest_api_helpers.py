# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
REST API Helper Functions and Classes

This module contains all the helper code for the REST API, including:
- Decorators for common patterns
- Handler classes for grouped operations
- Response builders
- Input validation
- Legacy Dogtag compatibility helpers

Separating these from rest_api.py makes the main module cleaner and
easier to maintain.
"""

import logging
from typing import Dict, Any

from flask import jsonify

logger = logging.getLogger(__name__)


# ============================================================================
# Response Helpers
# ============================================================================


def error_response(
    error_type: str,
    message: str,
    status_code: int = 400,
    class_name: str = None,
) -> tuple:
    """Create error response in PKI format

    Args:
        error_type: Error type for Attributes
        message: Error message
        status_code: HTTP status code
        class_name: Java exception class name (defaults to PKIException)
    """
    if class_name is None:
        class_name = "com.netscape.certsrv.base.PKIException"

    return (
        jsonify(
            {
                "ClassName": class_name,
                "Code": status_code,
                "Message": message,
                "Attributes": {
                    "Attribute": [{"name": "error", "value": error_type}]
                },
            }
        ),
        status_code,
    )


def success_response(data: Dict[str, Any], status_code: int = 200) -> tuple:
    """Create success response"""
    return jsonify(data), status_code
