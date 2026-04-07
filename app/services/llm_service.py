"""LLM service using Hugging Face Inference API for safe audit assistance."""

from __future__ import annotations

import json
from pathlib import Path

from huggingface_hub import InferenceClient

from app.config import settings
from app.services.safety_filter import sanitize_text, sanitize_dict

_PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"


def _load_prompt(name: str) -> str:
    return (_PROMPTS_DIR / name).read_text()


def _get_client() -> InferenceClient:
    return InferenceClient(token=settings.hf_token or None)


def _query(model: str, system_prompt: str, user_content: str) -> str:
    """Send a chat-completion request and return the response text."""
    client = _get_client()
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]
    response = client.chat_completion(
        model=model,
        messages=messages,
        max_tokens=1024,
        temperature=0.2,
    )
    return response.choices[0].message.content


def _try_parse_json(text: str) -> dict | str:
    """Try to extract and parse JSON from response text."""
    text = text.strip()
    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try extracting JSON block from markdown
    if "```json" in text:
        start = text.index("```json") + 7
        end = text.index("```", start)
        try:
            return json.loads(text[start:end].strip())
        except (json.JSONDecodeError, ValueError):
            pass
    if "```" in text:
        start = text.index("```") + 3
        end = text.index("```", start)
        try:
            return json.loads(text[start:end].strip())
        except (json.JSONDecodeError, ValueError):
            pass
    return text


def _sanitize_llm_output(result: dict | str) -> dict | str:
    """Apply safety filter to LLM output."""
    if isinstance(result, dict):
        return sanitize_dict(result)
    return sanitize_text(result)


def summarize_contract(source_code: str) -> dict | str:
    """Summarize a contract using the contract_summary prompt."""
    prompt = _load_prompt("contract_summary.txt")
    result = _query(
        settings.hf_model_summary,
        prompt,
        f"```solidity\n{source_code[:8000]}\n```",
    )
    return _sanitize_llm_output(_try_parse_json(result))


def classify_function(source_code: str) -> dict | str:
    """Classify a function's risk buckets."""
    prompt = _load_prompt("function_classifier.txt")
    result = _query(
        settings.hf_model_classifier,
        prompt,
        f"```solidity\n{source_code[:4000]}\n```",
    )
    return _sanitize_llm_output(_try_parse_json(result))


def explain_function(source_code: str) -> dict | str:
    """Explain a function for a junior reviewer."""
    prompt = _load_prompt("function_explainer.txt")
    result = _query(
        settings.hf_model_summary,
        prompt,
        f"```solidity\n{source_code[:4000]}\n```",
    )
    return _sanitize_llm_output(_try_parse_json(result))


def draft_finding(evidence: dict) -> dict | str:
    """Draft an audit finding note from structured evidence."""
    prompt = _load_prompt("finding_note.txt")
    result = _query(
        settings.hf_model_summary,
        prompt,
        json.dumps(evidence, indent=2),
    )
    return _sanitize_llm_output(_try_parse_json(result))
