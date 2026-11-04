"""Groq chat-completions client with a typed, review-only contract."""

from __future__ import annotations

import json
import os
import time
from typing import Any, Literal

import httpx
from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError, field_validator

DEFAULT_MODEL = "openai/gpt-oss-120b"
DEFAULT_BASE_URL = "https://api.groq.com/openai/v1"


class GroqError(RuntimeError):
    """Raised when the live model cannot produce a usable review."""


class LLMFinding(BaseModel):
    """One issue reported by the model."""

    severity: Literal["high", "medium", "low", "info"] = "info"
    cwe: str = ""
    line: int | None = None
    issue: str
    evidence: str = ""
    recommendation: str = ""

    @field_validator("severity", mode="before")
    @classmethod
    def _normalize_severity(cls, value: object) -> str:
        text = str(value or "").strip().lower()
        return text if text in {"high", "medium", "low", "info"} else "info"

    @field_validator("cwe", "evidence", "recommendation", mode="before")
    @classmethod
    def _none_to_string(cls, value: object) -> str:
        return "" if value is None else str(value)

    @field_validator("line", mode="before")
    @classmethod
    def _coerce_line(cls, value: object) -> int | None:
        if value is None or value == "":
            return None
        text = str(value).strip().lower().removeprefix("line").strip().rstrip(":")
        try:
            return int(float(text))
        except (TypeError, ValueError):
            return None


class LLMReview(BaseModel):
    """Structured result expected from the model."""

    verdict: Literal["likely_fixed", "likely_vulnerable", "incomplete", "uncertain"]
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    summary: str
    attack_path: str = ""
    findings: list[LLMFinding] = Field(default_factory=list)
    test_gaps: list[str] = Field(default_factory=list)
    reasoning: str = ""

    @field_validator("verdict", mode="before")
    @classmethod
    def _normalize_verdict(cls, value: object) -> str:
        text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
        aliases = {
            "fixed": "likely_fixed",
            "safe": "likely_fixed",
            "vulnerable": "likely_vulnerable",
            "unsafe": "likely_vulnerable",
            "partial": "incomplete",
        }
        normalized = aliases.get(text, text)
        if normalized not in {"likely_fixed", "likely_vulnerable", "incomplete", "uncertain"}:
            return "uncertain"
        return normalized

    @field_validator("confidence", mode="before")
    @classmethod
    def _normalize_confidence(cls, value: object) -> float:
        try:
            number = float(str(value))
        except (TypeError, ValueError):
            return 0.5
        if 1.0 < number <= 100.0:
            number /= 100.0
        return min(1.0, max(0.0, number))

    @field_validator("findings", mode="before")
    @classmethod
    def _normalize_findings(cls, value: object) -> object:
        if value is None or isinstance(value, str):
            return []
        if isinstance(value, dict):
            return [value]
        return value

    @field_validator("test_gaps", mode="before")
    @classmethod
    def _normalize_test_gaps(cls, value: object) -> object:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return value

    @field_validator("attack_path", "reasoning", mode="before")
    @classmethod
    def _none_to_text(cls, value: object) -> str:
        return "" if value is None else str(value)


class LLMUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class LLMResponse(BaseModel):
    review: LLMReview
    model: str
    latency_ms: int
    usage: LLMUsage


def _extract_json(text: str) -> dict[str, Any]:
    """Parse a JSON object even if the model wrapped it in a code fence."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start < 0 or end <= start:
            raise GroqError("model did not return a JSON object") from None
        try:
            parsed = json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError as exc:
            raise GroqError(f"model returned invalid JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise GroqError("model returned JSON that is not an object")
    return parsed


def _error_detail(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text[:500]
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or error)[:500]
        if error:
            return str(error)[:500]
    return str(payload)[:500]


class GroqClient:
    """Small OpenAI-compatible client for the Groq API."""

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not api_key.strip():
            raise GroqError("GROQ_API_KEY is empty")
        self._api_key = api_key.strip()
        self._transport = transport
        self.model = model
        self.base_url = base_url.rstrip("/")

    @classmethod
    def from_env(cls, model: str | None = None) -> GroqClient:
        """Build a client from `.env` or the process environment."""
        load_dotenv()
        api_key = os.environ.get("GROQ_API_KEY", "").strip()
        if not api_key:
            raise GroqError(
                "GROQ_API_KEY is not set. Copy .env.example to .env and add a Groq key."
            )
        selected = (model or os.environ.get("ACV_LLM_MODEL", "")).strip() or DEFAULT_MODEL
        return cls(api_key=api_key, model=selected)

    @staticmethod
    def is_configured() -> bool:
        """Return whether a key is present without exposing it."""
        load_dotenv()
        return bool(os.environ.get("GROQ_API_KEY", "").strip())

    def review(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        """Run one review request and normalize the response."""
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "autonomous-code-validator/0.2",
        }

        started = time.perf_counter()
        try:
            with httpx.Client(
                timeout=httpx.Timeout(90.0, connect=15.0),
                transport=self._transport,
            ) as client:
                response = client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                )
        except httpx.HTTPError as exc:
            raise GroqError(f"Groq request failed: {exc}") from exc

        latency_ms = int((time.perf_counter() - started) * 1000)
        if response.status_code >= 400:
            raise GroqError(
                f"Groq returned HTTP {response.status_code}: {_error_detail(response)}"
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise GroqError("Groq returned a non-JSON response") from exc
        if not isinstance(data, dict):
            raise GroqError("Groq returned an unexpected response shape")

        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise GroqError("Groq returned no choices")
        first = choices[0]
        if not isinstance(first, dict):
            raise GroqError("Groq returned an invalid choice")
        message = first.get("message")
        if not isinstance(message, dict):
            raise GroqError("Groq returned no message")
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise GroqError("Groq returned an empty message")

        try:
            review = LLMReview.model_validate(_extract_json(content))
        except ValidationError as exc:
            raise GroqError(f"Groq returned an invalid review: {exc}") from exc

        raw_usage = data.get("usage")
        usage_data = raw_usage if isinstance(raw_usage, dict) else {}
        usage = LLMUsage(
            prompt_tokens=int(usage_data.get("prompt_tokens") or 0),
            completion_tokens=int(usage_data.get("completion_tokens") or 0),
            total_tokens=int(usage_data.get("total_tokens") or 0),
        )
        model = str(data.get("model") or self.model)
        return LLMResponse(review=review, model=model, latency_ms=latency_ms, usage=usage)
