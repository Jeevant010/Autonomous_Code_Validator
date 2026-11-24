"""A small multi-file document portal used by the project-level verifier.

The package deliberately has layers instead of one flat module: configuration,
path resolution, storage, search, rendering, authentication, a service facade,
an in-process request router, and a CLI. That gives the verifier a realistic
amount of code and import structure to inspect.
"""

from __future__ import annotations

from .config import Settings
from .errors import (
    AuthError,
    DocumentNotFound,
    DocumentTooLarge,
    InvalidRequest,
    PortalError,
    UnsafePathError,
)
from .models import Document, DocumentSummary, PortalStats
from .service import DocumentService

__all__ = [
    "AuthError",
    "Document",
    "DocumentNotFound",
    "DocumentService",
    "DocumentSummary",
    "DocumentTooLarge",
    "InvalidRequest",
    "PortalError",
    "PortalStats",
    "Settings",
    "UnsafePathError",
]

__version__ = "1.4.0"
