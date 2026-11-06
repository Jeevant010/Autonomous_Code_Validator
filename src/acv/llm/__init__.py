"""Optional language-model review layer.

The deterministic verifier remains the source of truth. This package adds a
live reviewer that can explain a candidate, surface a missed attack path, and
compare its own judgement with the gate.
"""

from .groq import (
    DEFAULT_MODEL,
    GroqClient,
    GroqError,
    LLMFinding,
    LLMReview,
    LLMUsage,
)

__all__ = [
    "DEFAULT_MODEL",
    "GroqClient",
    "GroqError",
    "LLMFinding",
    "LLMReview",
    "LLMUsage",
]
