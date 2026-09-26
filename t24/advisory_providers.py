"""advisory_providers.py — LLM provider dispatch for T-24 advisory extraction.

Extracted from advisory.py to keep both files under 300 lines.
Handles watsonx.ai Granite and Fireworks calls.
"""
from __future__ import annotations

import json
import logging
import os
import textwrap
from typing import Any

log = logging.getLogger(__name__)


def build_prompt(advisory_text: str) -> str:
    return textwrap.dedent(f"""\
        You are a security analyst. Extract the following fields from the advisory below.
        Respond with a JSON object and nothing else.

        Fields:
        - package: string (PyPI package name)
        - affected_range: string (PEP 440 version specifier, e.g. "< 5.4")
        - fixed_version: string (first fixed version, e.g. "5.4")
        - symbols: list of objects with "name" (string) and "kind" ("python" or "template_filter")
          Include only symbols explicitly named in the advisory text.
        - preconditions: list of strings describing runtime conditions required for exploitation
          (e.g. "proxies must be configured"). Empty list if none.

        Advisory text:
        ---
        {advisory_text}
        ---

        Respond ONLY with valid JSON. No markdown, no explanation.
    """)


def parse_llm_json(text: str) -> dict[str, Any]:
    """Extract JSON from LLM response, stripping any markdown fences."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    return json.loads(text)


class LLMResult(dict):
    """dict subclass that carries provider/model metadata for cache writing."""
    _provider: str = "unknown"
    _model: str = "unknown"
    _raw_text: str = ""


def call_provider(advisory_text: str, cve: str) -> LLMResult:
    """Try watsonx → Fireworks → raise RuntimeError."""
    watsonx_key = os.environ.get("WATSONX_APIKEY", "")
    fireworks_key = os.environ.get("FIREWORKS_API_KEY", "")
    fireworks_failure: str | None = None

    if watsonx_key:
        result = _call_watsonx(advisory_text, cve)
        if result is not None:
            return result

    if fireworks_key:
        result = _call_fireworks(advisory_text, cve)
        if result is not None:
            return result
        # _call_fireworks returned None — call failed (logged internally)
        fireworks_failure = "see log for details"

    if fireworks_failure is not None:
        raise RuntimeError(
            f"Fireworks call failed ({fireworks_failure}); "
            f"no cached extraction for {cve}."
        )

    raise RuntimeError(
        f"No cached extraction for {cve} and no provider key set. "
        f"Add FIREWORKS_API_KEY to .env or run with a populated cache/."
    )


def _call_watsonx(advisory_text: str, cve: str) -> LLMResult | None:
    try:
        from ibm_watsonx_ai import APIClient, Credentials  # type: ignore
        from ibm_watsonx_ai.foundation_models import ModelInference  # type: ignore
    except ImportError:
        log.debug("ibm-watsonx-ai not installed; skipping watsonx provider")
        return None

    try:
        url = os.environ.get("WATSONX_URL", "https://us-south.ml.cloud.ibm.com")
        project_id = os.environ.get("WATSONX_PROJECT_ID", "")
        model_id = os.environ.get("WATSONX_MODEL", "ibm/granite-3-3-8b-instruct")
        api_key = os.environ["WATSONX_APIKEY"]

        credentials = Credentials(url=url, api_key=api_key)
        client = APIClient(credentials=credentials)
        model = ModelInference(
            model_id=model_id, api_client=client, project_id=project_id,
        )
        response = model.generate_text(prompt=build_prompt(advisory_text))
        parsed = parse_llm_json(response)
        result = LLMResult(parsed)
        result._provider = "watsonx"
        result._model = model_id
        result._raw_text = response
        return result
    except Exception as exc:
        log.warning("watsonx call failed: %s", exc)
        return None


def _call_fireworks(advisory_text: str, cve: str) -> LLMResult | None:
    import urllib.request
    import urllib.error

    api_key = os.environ.get("FIREWORKS_API_KEY", "")
    if not api_key:
        return None

    model = os.environ.get("FIREWORKS_MODEL", "") or _pick_fireworks_model(api_key)
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": build_prompt(advisory_text)}],
        "temperature": 0,
    }).encode()

    req = urllib.request.Request(
        "https://api.fireworks.ai/inference/v1/chat/completions",
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read())
        text = body["choices"][0]["message"]["content"]
        parsed = parse_llm_json(text)
        result = LLMResult(parsed)
        result._provider = "fireworks"
        result._model = model
        result._raw_text = text
        return result
    except Exception as exc:
        log.warning("Fireworks call failed: %s", exc)
        return None


def _pick_fireworks_model(api_key: str) -> str:
    import urllib.request

    try:
        req = urllib.request.Request(
            "https://api.fireworks.ai/inference/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        models = [m["id"] for m in data.get("data", []) if "instruct" in m.get("id", "")]
        for candidate in models:
            if any(size in candidate for size in ["7b", "8b", "3b"]):
                log.info("Auto-selected Fireworks model: %s", candidate)
                return candidate
        if models:
            log.info("Auto-selected Fireworks model: %s", models[0])
            return models[0]
    except Exception as exc:
        log.warning("Failed to list Fireworks models: %s", exc)
    default = "accounts/fireworks/models/glm-5p3-flash"
    log.info("Falling back to default Fireworks model: %s", default)
    return default
