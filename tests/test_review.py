from __future__ import annotations

import json
from pathlib import Path

import httpx

from acv.llm import GroqClient, LLMReview
from acv.manifest import load_task
from acv.review import build_user_prompt, find_candidate

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "security_workers"


def test_review_schema_accepts_nested_findings() -> None:
    review = LLMReview.model_validate(
        {
            "verdict": "likely_vulnerable",
            "confidence": 0.9,
            "summary": "The shell remains reachable.",
            "attack_path": "value contains &&",
            "findings": [
                {
                    "severity": "high",
                    "cwe": "CWE-78",
                    "line": "9",
                    "issue": "shell injection",
                    "evidence": "sh -c",
                    "recommendation": "pass an argument list",
                }
            ],
            "test_gaps": [],
            "reasoning": "sh -c keeps the shell",
        }
    )
    assert review.findings[0].line == 9
    assert review.findings[0].severity == "high"


def test_groq_client_normalizes_a_fenced_review() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        content = """```json
        {
          "verdict": "likely_vulnerable",
          "confidence": 0.93,
          "summary": "The wrapper still invokes a shell.",
          "attack_path": "run_echo('x && touch marker')",
          "findings": [
            {
              "severity": "high",
              "cwe": "CWE-78",
              "line": 9,
              "issue": "shell metacharacters remain",
              "evidence": "subprocess.run(['sh', '-c', ...])",
              "recommendation": "pass an argument list"
            }
          ],
          "test_gaps": ["no metacharacter test"],
          "reasoning": "removing ; is not enough"
        }
        ```"""
        return httpx.Response(
            200,
            request=request,
            json={
                "model": "openai/gpt-oss-120b",
                "choices": [{"message": {"content": content}}],
                "usage": {
                    "prompt_tokens": 100,
                    "completion_tokens": 80,
                    "total_tokens": 180,
                },
            },
        )

    client = GroqClient(
        api_key="test-key",
        transport=httpx.MockTransport(handler),
    )
    response = client.review("system", "user")

    assert response.review.verdict == "likely_vulnerable"
    assert response.review.findings[0].line == 9
    assert response.usage.total_tokens == 180
    assert response.latency_ms >= 0
    assert captured["body"]["temperature"] == 0


def test_prompt_contains_untrusted_candidate_and_no_ground_truth() -> None:
    task = load_task(PACK / "cmd_runner")
    candidate = find_candidate(task, "sh_c_filter")
    prompt, chars = build_user_prompt(task, candidate)

    assert "CANDIDATE IMPLEMENTATION" in prompt
    assert "subprocess.run" in prompt
    assert '"-c"' in prompt
    assert "expected_accepted" not in prompt
    assert "mutant" not in prompt.lower()
    assert chars > 0
