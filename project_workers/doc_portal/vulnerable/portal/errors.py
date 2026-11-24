"""Domain errors for the document portal."""

from __future__ import annotations


class PortalError(Exception):
    """Base class for errors that callers may present to a user."""


class UnsafePathError(PortalError):
    """Raised when a document name cannot be resolved safely."""


class DocumentNotFound(PortalError):
    """Raised when a requested document does not exist."""


class DocumentTooLarge(PortalError):
    """Raised when a document exceeds the configured size limit."""


class InvalidRequest(PortalError):
    """Raised when a request is missing required data."""


class AuthError(PortalError):
    """Raised when a token or role check fails."""
