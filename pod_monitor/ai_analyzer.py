"""
AI Analyzer and Providers for Pod Monitor.

Provides LLM client integrations (Mock, Ollama, Groq, OpenAI) to analyze
sanitized log payloads and pod metadata for anomaly detection.
"""

import re
import json
import random
import logging
import asyncio
from abc import ABC, abstractmethod
from typing import List, Optional, Any, Tuple
from datetime import datetime
import aiohttp

from .models import LogEntry, LogLevel, Anomaly, Severity, PodStatus
from .log_optimizer import LogOptimizer
from .config import AIConfig

logger = logging.getLogger(__name__)


def _extract_pod_info_from_payload(payload: str) -> Tuple[str, Optional[str]]:
    """Extract pod IP and name from payload string if available."""
    pod_ip = ""
    pod_name = None
    if not payload:
        return pod_ip, pod_name

    match = re.search(r"Pod:\s*([^\s(]+)\s*\(([^)]+)\)", payload)
    if match:
        pod_name = match.group(1).strip()
        pod_ip = match.group(2).strip()
    return pod_ip, pod_name


def _parse_severity(val: Any) -> Severity:
    """Parse severity string/enum safely."""
    if isinstance(val, Severity):
        return val
    if isinstance(val, str):
        val_clean = val.strip().lower()
        for sev in Severity:
            if sev.value == val_clean or sev.name.lower() == val_clean:
                return sev
    return Severity.MEDIUM


def _clean_json_str(content: str) -> str:
    """Strip markdown code fences and extraneous whitespace."""
    content = content.strip()
    if content.startswith("```"):
        lines = content.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        content = "\n".join(lines).strip()
    return content


def _parse_anomaly_json(content: str, payload: str = "") -> List[Anomaly]:
    """
    Robustly parse JSON response from LLM into a list of Anomaly objects.
    Handles code fences, wrapped objects, and regex fallback.
    """
    if not content or not content.strip():
        return []

    cleaned = _clean_json_str(content)
    data = None

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        # Fallback: search for JSON array
        match_arr = re.search(r'\[\s*\{.*\}\s*\]', cleaned, re.DOTALL)
        if match_arr:
            try:
                data = json.loads(match_arr.group(0))
            except json.JSONDecodeError:
                pass

        if data is None:
            # Fallback: search for JSON object
            match_obj = re.search(r'\{\s*".*"\s*:.*\}', cleaned, re.DOTALL)
            if match_obj:
                try:
                    data = json.loads(match_obj.group(0))
                except json.JSONDecodeError:
                    pass

    if data is None:
        logger.warning(f"Failed to parse LLM response as JSON: {content[:200]}")
        return []

    # Normalize data into a list of dicts
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ("anomalies", "items", "results", "data", "errors"):
            if key in data and isinstance(data[key], list):
                items = data[key]
                break
        else:
            if "severity" in data or "description" in data:
                items = [data]
            else:
                items = []
    else:
        items = []

    pod_ip, pod_name = _extract_pod_info_from_payload(payload)
    anomalies: List[Anomaly] = []
    now = datetime.now()

    for item in items:
        if not isinstance(item, dict):
            continue

        severity = _parse_severity(item.get("severity", "medium"))
        description = str(item.get("description", "AI detected anomaly"))
        suggestion = str(item.get("suggestion", ""))

        log_ctx_raw = item.get("log_context", [])
        if isinstance(log_ctx_raw, list):
            log_context = [str(x) for x in log_ctx_raw]
        elif log_ctx_raw:
            log_context = [str(log_ctx_raw)]
        else:
            log_context = []

        item_ip = item.get("pod_ip") or pod_ip or "127.0.0.1"
        item_name = item.get("pod_name") or pod_name
        detected_by = item.get("detected_by", "ai")
        anomaly_id = item.get("id") or f"ai-{int(now.timestamp())}-{random.randint(1000, 9999)}"

        anomalies.append(
            Anomaly(
                id=anomaly_id,
                timestamp=now,
                severity=severity,
                description=description,
                pod_ip=item_ip,
                pod_name=item_name,
                log_context=log_context,
                suggestion=suggestion,
                detected_by=detected_by,
            )
        )

    return anomalies


# =====================================================================
# 1. AIProvider Abstract Base Class
# =====================================================================

class AIProvider(ABC):
    """Abstract base class for AI anomaly detection providers."""

    @abstractmethod
    async def analyze(self, payload: str) -> List[Anomaly]:
        """
        Analyze a prepared log & metadata payload string and return detected anomalies.

        Args:
            payload: String containing pod metadata and optimized logs

        Returns:
            List of detected Anomaly objects
        """
        pass


# =====================================================================
# 2. MockProvider
# =====================================================================

class MockProvider(AIProvider):
    """
    Mock AI Provider for testing and offline environments.
    Analyzes log payloads using rule-based heuristics to return simulated anomalies.
    """

    def __init__(self, sample_anomalies: Optional[List[Anomaly]] = None):
        self.sample_anomalies = sample_anomalies

    async def analyze(self, payload: str) -> List[Anomaly]:
        if self.sample_anomalies is not None:
            return list(self.sample_anomalies)

        if not payload or "No critical logs found" in payload:
            return []

        pod_ip, pod_name = _extract_pod_info_from_payload(payload)
        now = datetime.now()
        anomalies: List[Anomaly] = []
        payload_lower = payload.lower()

        # Check for critical crash/panic patterns
        if any(k in payload_lower for k in ("critical", "panic", "fatal", "oom", "crashloop")):
            anomalies.append(
                Anomaly(
                    id=f"ai-mock-{int(now.timestamp())}-{random.randint(1000, 9999)}",
                    timestamp=now,
                    severity=Severity.CRITICAL,
                    description="Critical container panic or system failure detected in logs",
                    pod_ip=pod_ip or "127.0.0.1",
                    pod_name=pod_name or "mock-pod",
                    log_context=["Critical log event found in payload"],
                    suggestion="Immediate investigation required. Check pod container status, exit codes, and memory limits.",
                    detected_by="ai",
                )
            )

        # Check for error / database / network patterns
        if any(k in payload_lower for k in ("error", "database", "failed", "timeout", "refused", "500")):
            anomalies.append(
                Anomaly(
                    id=f"ai-mock-{int(now.timestamp())}-{random.randint(1000, 9999)}",
                    timestamp=now,
                    severity=Severity.HIGH,
                    description="Service connectivity failure or high error frequency detected",
                    pod_ip=pod_ip or "127.0.0.1",
                    pod_name=pod_name or "mock-pod",
                    log_context=["Error log event found in payload"],
                    suggestion="Check database connection pool, service mesh network policies, and downstream dependencies.",
                    detected_by="ai",
                )
            )

        # Check for warning / resource pressure patterns
        if not anomalies and any(k in payload_lower for k in ("warning", "warn", "pressure", "slow", "high memory")):
            anomalies.append(
                Anomaly(
                    id=f"ai-mock-{int(now.timestamp())}-{random.randint(1000, 9999)}",
                    timestamp=now,
                    severity=Severity.MEDIUM,
                    description="High resource utilization or performance degradation warning",
                    pod_ip=pod_ip or "127.0.0.1",
                    pod_name=pod_name or "mock-pod",
                    log_context=["Warning log event found in payload"],
                    suggestion="Review memory limits and optimize slow database queries or worker jobs.",
                    detected_by="ai",
                )
            )

        return anomalies


# =====================================================================
# 3. OllamaProvider
# =====================================================================

class OllamaProvider(AIProvider):
    """
    Local AI Provider using Ollama HTTP API.
    Enforces JSON response format via Ollama's format parameter.
    """

    def __init__(
        self,
        ollama_url: str = "http://localhost:11434",
        model: str = "mistral",
        temperature: float = 0.3,
        timeout: float = 30.0,
    ):
        self.ollama_url = ollama_url.rstrip("/") if ollama_url else "http://localhost:11434"
        self.model = model or "mistral"
        self.temperature = temperature
        self.timeout = timeout

    async def analyze(self, payload: str) -> List[Anomaly]:
        if not payload:
            return []

        # Determine endpoint URL
        if self.ollama_url.endswith("/api/chat") or self.ollama_url.endswith("/api/generate"):
            url = self.ollama_url
            use_chat = self.ollama_url.endswith("/api/chat")
        else:
            url = f"{self.ollama_url}/api/chat"
            use_chat = True

        system_prompt = (
            "You are a Kubernetes log analysis expert. Analyze the provided pod metadata and logs to detect anomalies.\n"
            "You MUST respond ONLY with a strict JSON array of anomaly objects with this exact structure:\n"
            "[\n"
            "  {\n"
            '    "severity": "low" | "medium" | "high" | "critical",\n'
            '    "description": "Brief description of the anomaly",\n'
            '    "suggestion": "Recommended remediation step",\n'
            '    "log_context": ["relevant log line 1", "relevant log line 2"]\n'
            "  }\n"
            "]\n"
            "If no anomalies are present, return an empty JSON array: []."
        )

        if use_chat:
            request_body = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": payload},
                ],
                "format": "json",
                "stream": False,
                "options": {
                    "temperature": self.temperature,
                },
            }
        else:
            full_prompt = f"{system_prompt}\n\nPayload:\n{payload}"
            request_body = {
                "model": self.model,
                "prompt": full_prompt,
                "format": "json",
                "stream": False,
                "options": {
                    "temperature": self.temperature,
                },
            }

        client_timeout = aiohttp.ClientTimeout(total=self.timeout)
        try:
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                async with session.post(url, json=request_body) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"Ollama API returned HTTP {response.status}: {error_text}")
                        return []

                    result = await response.json()

                    if "message" in result and isinstance(result["message"], dict):
                        content = result["message"].get("content", "")
                    elif "response" in result:
                        content = result.get("response", "")
                    else:
                        content = json.dumps(result)

                    return _parse_anomaly_json(content, payload)

        except asyncio.TimeoutError:
            logger.error(f"Ollama request timed out after {self.timeout}s at {url}")
            return []
        except Exception as e:
            logger.error(f"Ollama analysis failed: {e}")
            return []


# =====================================================================
# 4. GroqProvider
# =====================================================================

class GroqProvider(AIProvider):
    """
    Cloud AI Provider using Groq's high-speed inference API.
    Sends chat completions requests to Groq endpoint with strict JSON schema enforcement.
    """

    GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

    def __init__(
        self,
        groq_token: Optional[str] = None,
        groq_model: str = "gemma2-9b-it",
        temperature: float = 0.3,
        max_tokens: int = 500,
        timeout: float = 30.0,
    ):
        self.groq_token = groq_token or ""
        self.groq_model = groq_model or "gemma2-9b-it"
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout

    async def analyze(self, payload: str) -> List[Anomaly]:
        if not payload:
            return []

        if not self.groq_token:
            logger.error("Groq token not configured for GroqProvider")
            return []

        headers = {
            "Authorization": f"Bearer {self.groq_token}",
            "Content-Type": "application/json",
        }

        system_prompt = (
            "You are a Kubernetes SRE and log analysis expert. Analyze the provided pod metadata and logs to detect anomalies.\n"
            "You MUST respond ONLY with a strict JSON array of anomaly objects conforming to the following structure:\n"
            "[\n"
            "  {\n"
            '    "severity": "low" | "medium" | "high" | "critical",\n'
            '    "description": "Brief description of the anomaly",\n'
            '    "suggestion": "Recommended action to resolve the issue",\n'
            '    "log_context": ["relevant log line 1", "relevant log line 2"]\n'
            "  }\n"
            "]\n"
            "If no anomalies are detected, return an empty JSON array: []."
        )

        request_body = {
            "model": self.groq_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": payload},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "response_format": {"type": "json_object"},
        }

        client_timeout = aiohttp.ClientTimeout(total=self.timeout)
        try:
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                async with session.post(self.GROQ_API_URL, headers=headers, json=request_body) as response:
                    if response.status == 429:
                        error_text = await response.text()
                        logger.warning(f"Groq API rate limit exceeded (HTTP 429): {error_text}")
                        return []
                    elif response.status != 200:
                        error_text = await response.text()
                        logger.error(f"Groq API returned HTTP {response.status}: {error_text}")
                        return []

                    result = await response.json()
                    choices = result.get("choices", [])
                    if not choices:
                        logger.warning("Groq API returned empty choices")
                        return []

                    content = choices[0].get("message", {}).get("content", "")
                    return _parse_anomaly_json(content, payload)

        except asyncio.TimeoutError:
            logger.error(f"Groq request timed out after {self.timeout}s")
            return []
        except Exception as e:
            logger.error(f"Groq analysis failed: {e}")
            return []


# =====================================================================
# Optional: OpenAIProvider
# =====================================================================

class OpenAIProvider(AIProvider):
    """
    Cloud AI Provider using OpenAI chat completions API via HTTP.
    """

    OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"

    def __init__(
        self,
        api_token: Optional[str] = None,
        model: str = "gpt-3.5-turbo",
        temperature: float = 0.3,
        max_tokens: int = 500,
        timeout: float = 30.0,
    ):
        self.api_token = api_token or ""
        self.model = model or "gpt-3.5-turbo"
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout

    async def analyze(self, payload: str) -> List[Anomaly]:
        if not payload:
            return []

        if not self.api_token:
            logger.error("OpenAI token not configured for OpenAIProvider")
            return []

        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

        system_prompt = (
            "You are a Kubernetes SRE and log analysis expert. Analyze the provided pod metadata and logs to detect anomalies.\n"
            "You MUST respond ONLY with a strict JSON array of anomaly objects conforming to the following structure:\n"
            "[\n"
            "  {\n"
            '    "severity": "low" | "medium" | "high" | "critical",\n'
            '    "description": "Brief description of the anomaly",\n'
            '    "suggestion": "Recommended action to resolve the issue",\n'
            '    "log_context": ["relevant log line 1", "relevant log line 2"]\n'
            "  }\n"
            "]\n"
            "If no anomalies are detected, return an empty JSON array: []."
        )

        request_body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": payload},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "response_format": {"type": "json_object"},
        }

        client_timeout = aiohttp.ClientTimeout(total=self.timeout)
        try:
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                async with session.post(self.OPENAI_API_URL, headers=headers, json=request_body) as response:
                    if response.status == 429:
                        error_text = await response.text()
                        logger.warning(f"OpenAI API rate limit exceeded (HTTP 429): {error_text}")
                        return []
                    elif response.status != 200:
                        error_text = await response.text()
                        logger.error(f"OpenAI API returned HTTP {response.status}: {error_text}")
                        return []

                    result = await response.json()
                    choices = result.get("choices", [])
                    if not choices:
                        return []

                    content = choices[0].get("message", {}).get("content", "")
                    return _parse_anomaly_json(content, payload)

        except Exception as e:
            logger.error(f"OpenAI analysis failed: {e}")
            return []


# =====================================================================
# 5. get_ai_provider Factory Function
# =====================================================================

def get_ai_provider(config: AIConfig) -> AIProvider:
    """
    Factory function to instantiate the appropriate AIProvider based on AIConfig.

    Args:
        config: AIConfig instance containing provider settings

    Returns:
        AIProvider instance (MockProvider, OllamaProvider, GroqProvider, or OpenAIProvider)
    """
    if not config or not getattr(config, "enabled", True):
        return MockProvider()

    provider_type = getattr(config, "provider", "mock").lower()

    if provider_type == "mock" or (getattr(config, "mock_mode", False) and provider_type not in ("groq", "ollama", "openai")):
        return MockProvider()

    if provider_type == "groq":
        return GroqProvider(
            groq_token=config.groq_token,
            groq_model=config.groq_model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
        )

    if provider_type == "ollama":
        return OllamaProvider(
            ollama_url=config.ollama_url or "http://localhost:11434",
            model=config.ollama_model,
            temperature=config.temperature,
        )

    if provider_type == "openai":
        return OpenAIProvider(
            api_token=config.openai_token,
            model=config.openai_model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
        )

    logger.warning(f"Unknown AI provider '{provider_type}', falling back to MockProvider")
    return MockProvider()


# =====================================================================
# AIAnalyzer Class
# =====================================================================

class AIAnalyzer:
    """
    High-level analyzer coordinating log optimization and AI anomaly detection.
    """

    def __init__(
        self,
        config: Optional[AIConfig] = None,
        provider: Optional[AIProvider] = None,
        api_token: Optional[str] = None,
        ollama_url: Optional[str] = None,
        mock_mode: bool = True,
    ):
        if provider is not None:
            self.provider = provider
        elif config is not None:
            self.provider = get_ai_provider(config)
        else:
            # Backward compatibility with legacy parameters
            if not mock_mode and api_token:
                self.provider = OpenAIProvider(api_token=api_token)
            elif not mock_mode and ollama_url:
                self.provider = OllamaProvider(ollama_url=ollama_url)
            else:
                self.provider = MockProvider()

        self.mock_mode = isinstance(self.provider, MockProvider)
        self.context_window = 50

    async def analyze_logs(self, logs: List[LogEntry], pod_status: PodStatus) -> List[Anomaly]:
        """
        Analyze logs for anomalies using the configured AI provider.

        Runs raw logs through LogOptimizer (filter -> deduplicate -> scrub -> prepare_payload),
        passes the payload to the AIProvider, catches errors gracefully, and attaches
        resulting anomalies to pod_status for UI rendering.
        """
        target_logs = logs if logs else getattr(pod_status, "logs", [])
        if not target_logs:
            pod_status.anomalies = []
            return []

        try:
            # 1. Pass raw pod logs through LogOptimizer (filter -> deduplicate -> scrub -> prepare_payload)
            payload = LogOptimizer.prepare_payload(logs=target_logs, pod_status=pod_status)

            # 2. Pass optimized payload to the AIProvider.analyze()
            anomalies = await self.provider.analyze(payload)

            # 3. Ensure resulting Anomaly objects have correct pod metadata
            for anomaly in anomalies:
                if not anomaly.pod_ip or anomaly.pod_ip in ("127.0.0.1", "[REDACTED_IP]", "unknown"):
                    anomaly.pod_ip = pod_status.ip
                if not anomaly.pod_name or anomaly.pod_name in ("mock-pod", "Unknown"):
                    anomaly.pod_name = pod_status.name

            # 4. Attach resulting Anomaly objects to PodStatus for UI rendering
            pod_status.anomalies = anomalies
            return anomalies

        except asyncio.TimeoutError:
            logger.error(f"AI analysis timed out for pod {pod_status.name}")
            pod_status.anomalies = []
            return []
        except aiohttp.ClientResponseError as e:
            if e.status == 429:
                logger.warning(f"AI provider rate limit reached (HTTP 429) for pod {pod_status.name}: {e}")
            else:
                logger.error(f"AI provider HTTP error {e.status} for pod {pod_status.name}: {e}")
            pod_status.anomalies = []
            return []
        except aiohttp.ClientError as e:
            logger.error(f"AI provider connection error for pod {pod_status.name}: {e}")
            pod_status.anomalies = []
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode AI response for pod {pod_status.name}: {e}")
            pod_status.anomalies = []
            return []
        except Exception as e:
            logger.error(f"Unexpected error during AI log analysis for pod {pod_status.name}: {e}", exc_info=True)
            pod_status.anomalies = []
            return []

    def generate_summary(self, anomalies: List[Anomaly]) -> str:
        """Generate a human-readable summary of anomalies."""
        if not anomalies:
            return "✅ No anomalies detected. Pod is healthy."

        summary = f"⚠️ {len(anomalies)} anomalies detected:\n\n"
        for i, anomaly in enumerate(anomalies[:5], 1):
            summary += f"{i}. [{anomaly.severity.value.upper()}] {anomaly.description}\n"
            if anomaly.suggestion:
                summary += f"   💡 {anomaly.suggestion}\n"

        if len(anomalies) > 5:
            summary += f"\n... and {len(anomalies) - 5} more anomalies"

        return summary
