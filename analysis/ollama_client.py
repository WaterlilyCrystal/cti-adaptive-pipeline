from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict

import requests
from utils.monitor import get_effective_available_ram_gb

logger = logging.getLogger("ollama_client")

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5:3b-instruct-q4_K_M"
_cooldown_until = 0.0
_selected_model = None


class OllamaServiceError(RuntimeError):
    pass


def _llm_cfg(cfg: Dict | None) -> Dict[str, Any]:
    return (cfg or {}).get("llm", {})


def get_base_url(cfg: Dict | None = None) -> str:
    return str(_llm_cfg(cfg).get("base_url", DEFAULT_BASE_URL)).rstrip("/")


def get_model_name(cfg: Dict | None = None) -> str:
    return str(_llm_cfg(cfg).get("model", DEFAULT_MODEL))


def get_model_candidates(cfg: Dict | None = None) -> list[str]:
    cfg_llm = _llm_cfg(cfg)
    candidates = [str(cfg_llm.get("model", DEFAULT_MODEL)).strip()]
    for value in cfg_llm.get("fallback_models", []) or []:
        model_name = str(value).strip()
        if model_name and model_name not in candidates:
            candidates.append(model_name)
    return candidates


def estimate_model_min_ram_gb(model_name: str, cfg: Dict | None = None) -> float:
    overrides = (_llm_cfg(cfg).get("model_min_ram_overrides") or {}) if cfg else {}
    override_value = overrides.get(model_name)
    try:
        if override_value is not None:
            return max(1.0, float(override_value))
    except (TypeError, ValueError):
        pass

    lower = model_name.lower()
    match = re.search(r"(\d+(?:\.\d+)?)b", lower)
    if match:
        params_b = float(match.group(1))
    else:
        params_b = 7.0

    if params_b <= 1.5:
        required = 2.5
    elif params_b <= 3.5:
        required = 3.5
    elif params_b <= 7.5:
        required = 8.0
    elif params_b <= 9.0:
        required = 10.0
    elif params_b <= 14.5:
        required = 16.0
    else:
        required = 24.0

    if "q8" in lower:
        required += 2.0
    elif "q2" in lower:
        required = max(2.0, required - 1.5)

    return required


def _cooldown_seconds(cfg: Dict | None = None) -> int:
    try:
        return max(30, int(_llm_cfg(cfg).get("cooldown_seconds", 180)))
    except (TypeError, ValueError):
        return 180


def _request_timeout(cfg: Dict | None = None, default: int = 60) -> int:
    try:
        return max(5, int(_llm_cfg(cfg).get("request_timeout_seconds", default)))
    except (TypeError, ValueError):
        return default


def _label_timeout(cfg: Dict | None, request_label: str, default: int) -> int:
    llm_cfg = _llm_cfg(cfg)
    key_map = {
        "report": "report_timeout_seconds",
        "summary": "report_timeout_seconds",
        "reasoning": "reasoning_timeout_seconds",
    }
    selected_key = ""
    lowered = request_label.lower()
    for marker, key in key_map.items():
        if marker in lowered:
            selected_key = key
            break
    if not selected_key:
        return default
    try:
        return max(5, int(llm_cfg.get(selected_key, default)))
    except (TypeError, ValueError):
        return default


def _num_ctx(cfg: Dict | None = None) -> int:
    try:
        return max(1024, int(_llm_cfg(cfg).get("num_ctx", 8192)))
    except (TypeError, ValueError):
        return 8192


def _max_retries(cfg: Dict | None = None, default: int = 2) -> int:
    try:
        return max(1, min(int(_llm_cfg(cfg).get("max_retries", default)), 4))
    except (TypeError, ValueError):
        return default


def _probe_num_ctx(cfg: Dict | None = None) -> int:
    try:
        return max(256, min(int(_llm_cfg(cfg).get("probe_num_ctx", 512)), _num_ctx(cfg)))
    except (TypeError, ValueError):
        return 512


def _probe_timeout_seconds(cfg: Dict | None = None, fallback: int = 30) -> int:
    try:
        return max(10, int(_llm_cfg(cfg).get("probe_timeout_seconds", fallback)))
    except (TypeError, ValueError):
        return fallback


def _probe_retries(cfg: Dict | None = None, fallback: int = 2) -> int:
    try:
        return max(1, min(int(_llm_cfg(cfg).get("probe_retries", fallback)), 5))
    except (TypeError, ValueError):
        return fallback


def _set_cooldown(cfg: Dict | None, reason: str) -> None:
    global _cooldown_until
    seconds = _cooldown_seconds(cfg)
    _cooldown_until = time.monotonic() + seconds
    logger.error("Ollama entered cooldown for %ss: %s", seconds, reason)


def _ensure_available(cfg: Dict | None = None) -> None:
    remaining = _cooldown_until - time.monotonic()
    if remaining > 0:
        raise OllamaServiceError(f"Ollama cooldown active for {int(remaining)}s")


def _extract_error_message(exc: requests.exceptions.HTTPError) -> str:
    response = exc.response
    if response is None:
        return str(exc)
    try:
        payload = response.json()
        if isinstance(payload, dict) and payload.get("error"):
            return str(payload["error"])
    except ValueError:
        pass
    text = (response.text or "").strip()
    return text or str(exc)


def _format_runtime_hint(message: str) -> str:
    lower = message.lower()
    if "unable to allocate cpu buffer" in lower:
        return (
            "Ollama could not load the model into RAM. "
            "Close memory-heavy apps or configure a smaller model in config.yaml under llm.model / llm.fallback_models."
        )
    return message


def probe_service(cfg: Dict | None = None, timeout: int = 3) -> None:
    global _selected_model
    _ensure_available(cfg)
    base_url = get_base_url(cfg)
    tags_timeout = min(timeout, _probe_timeout_seconds(cfg))
    try:
        response = requests.get(f"{base_url}/api/tags", timeout=tags_timeout)
        response.raise_for_status()
    except requests.RequestException as exc:
        _set_cooldown(cfg, f"health probe failed: {exc}")
        raise OllamaServiceError(f"Ollama health probe failed: {exc}") from exc

    available_ram_gb = get_effective_available_ram_gb(cfg)
    last_error = None
    eligible_models = []
    for model_name in get_model_candidates(cfg):
        required_ram_gb = estimate_model_min_ram_gb(model_name, cfg)
        if available_ram_gb >= required_ram_gb:
            eligible_models.append(model_name)
        else:
            logger.warning(
                "Skipping model %s due to RAM guard. effective_ram_gb=%.2f required_ram_gb=%.1f",
                model_name,
                available_ram_gb,
                required_ram_gb,
            )

    if not eligible_models:
        configured = ", ".join(get_model_candidates(cfg))
        _set_cooldown(cfg, f"health probe blocked by RAM guard: effective_ram_gb={available_ram_gb}")
        raise OllamaServiceError(
            "No configured Ollama model fits current RAM budget. "
            f"effective_ram_gb={available_ram_gb:.2f}, models={configured}"
        )

    probe_timeout = _probe_timeout_seconds(cfg)
    probe_retries = _probe_retries(cfg)

    for model_name in eligible_models:
        payload = {
            "model": model_name,
            "prompt": "ping",
            "stream": False,
            "options": {
                "temperature": 0,
                "num_ctx": _probe_num_ctx(cfg),
                "num_predict": 8,
            },
        }
        for attempt in range(probe_retries):
            try:
                response = requests.post(f"{base_url}/api/generate", json=payload, timeout=probe_timeout)
                response.raise_for_status()
                text = response.json().get("response", "")
                if text.strip():
                    _selected_model = model_name
                    logger.info("Ollama probe succeeded with model %s", model_name)
                    return
                last_error = f"Empty response from model {model_name}"
            except requests.exceptions.HTTPError as exc:
                detail = _extract_error_message(exc)
                logger.warning("Ollama probe failed for model %s attempt %s/%s: %s", model_name, attempt + 1, probe_retries, detail)
                last_error = f"{model_name}: {_format_runtime_hint(detail)}"
            except (requests.RequestException, ValueError) as exc:
                logger.warning("Ollama probe failed for model %s attempt %s/%s: %s", model_name, attempt + 1, probe_retries, exc)
                last_error = f"{model_name}: {exc}"

            if attempt < probe_retries - 1:
                wait_time = min(8, 2 ** attempt)
                time.sleep(wait_time)

    _set_cooldown(cfg, f"health probe failed: {last_error}")
    raise OllamaServiceError(f"Ollama probe could not load any configured model. {last_error}")


def generate_text(
    prompt: str,
    *,
    system: str = "",
    temperature: float = 0.1,
    max_tokens: int = 1024,
    cfg: Dict | None = None,
    request_label: str = "request",
) -> str:
    _ensure_available(cfg)
    base_url = get_base_url(cfg)
    headers = {"Content-Type": "application/json"}
    timeout = _label_timeout(cfg, request_label, _request_timeout(cfg))
    max_retries = _max_retries(cfg)
    model_name = _selected_model or get_model_name(cfg)
    payload = {
        "model": model_name,
        "prompt": prompt,
        "system": system,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_ctx": _num_ctx(cfg),
            "num_predict": max_tokens,
        },
    }

    for attempt in range(max_retries):
        try:
            response = requests.post(f"{base_url}/api/generate", json=payload, headers=headers, timeout=timeout)
            response.raise_for_status()
            text = response.json().get("response", "")
            if not text.strip():
                raise OllamaServiceError(f"Empty response for {request_label}")
            return text
        except requests.exceptions.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else "unknown"
            detail = _extract_error_message(exc)
            if status_code >= 500 and attempt < max_retries - 1:
                wait_time = 2 ** attempt
                logger.warning(
                    "Ollama HTTP %s on %s attempt %s/%s. Retrying in %ss. detail=%s",
                    status_code,
                    request_label,
                    attempt + 1,
                    max_retries,
                    wait_time,
                    detail,
                )
                time.sleep(wait_time)
                continue
            message = _format_runtime_hint(detail)
            _set_cooldown(cfg, f"{request_label} failed with HTTP {status_code}: {detail}")
            raise OllamaServiceError(f"Ollama HTTP {status_code} during {request_label}. {message}") from exc
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                logger.warning(
                    "Ollama transport error on %s attempt %s/%s. Retrying in %ss.",
                    request_label,
                    attempt + 1,
                    max_retries,
                    wait_time,
                )
                time.sleep(wait_time)
                continue
            _set_cooldown(cfg, f"{request_label} transport failure: {exc}")
            raise OllamaServiceError(f"Ollama transport failure during {request_label}") from exc
        except requests.RequestException as exc:
            _set_cooldown(cfg, f"{request_label} request failure: {exc}")
            raise OllamaServiceError(f"Ollama request failure during {request_label}") from exc
        except ValueError as exc:
            _set_cooldown(cfg, f"{request_label} invalid JSON response: {exc}")
            raise OllamaServiceError(f"Ollama invalid JSON during {request_label}") from exc

    raise OllamaServiceError(f"Ollama failed during {request_label}")
