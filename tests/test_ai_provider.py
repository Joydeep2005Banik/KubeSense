"""
Unit tests for AIProvider layer and AIAnalyzer.
"""

import json
import aiohttp
from datetime import datetime
from unittest.mock import AsyncMock, patch, MagicMock
import pytest

from pod_monitor.ai_analyzer import (
    AIProvider,
    MockProvider,
    OllamaProvider,
    GroqProvider,
    OpenAIProvider,
    get_ai_provider,
    AIAnalyzer,
    _parse_anomaly_json,
)
from pod_monitor.config import AIConfig
from pod_monitor.models import LogEntry, LogLevel, Anomaly, Severity, PodStatus, PodMetrics


@pytest.fixture
def sample_pod_status():
    return PodStatus(
        ip="10.244.0.15",
        name="order-service-9abc",
        namespace="production",
        healthy=False,
        restarts=3,
        metrics=PodMetrics(memory_usage=256.0, memory_limit=512.0, cpu_usage=45.0),
        error_count=5,
        total_logs=50
    )


@pytest.fixture
def sample_error_logs():
    now = datetime.now()
    return [
        LogEntry(
            timestamp=now,
            level=LogLevel.ERROR,
            message="Database connection pool exhausted at 192.168.1.100:5432",
            pod_ip="10.244.0.15"
        ),
        LogEntry(
            timestamp=now,
            level=LogLevel.CRITICAL,
            message="Fatal panic: OutOfMemoryError in worker thread",
            pod_ip="10.244.0.15"
        )
    ]


# ==========================================
# 1. JSON Parsing Helper Tests
# ==========================================

def test_parse_anomaly_json_standard():
    """Test parsing standard JSON array of anomalies."""
    raw_json = json.dumps([
        {
            "severity": "critical",
            "description": "Database crash",
            "suggestion": "Restart postgres",
            "log_context": ["FATAL error"]
        }
    ])
    anomalies = _parse_anomaly_json(raw_json, payload="Pod: test-pod (10.0.0.1)")
    assert len(anomalies) == 1
    assert anomalies[0].severity == Severity.CRITICAL
    assert anomalies[0].description == "Database crash"
    assert anomalies[0].suggestion == "Restart postgres"
    assert anomalies[0].pod_name == "test-pod"
    assert anomalies[0].pod_ip == "10.0.0.1"


def test_parse_anomaly_json_markdown_wrapped():
    """Test parsing JSON wrapped in markdown code blocks."""
    raw_text = """```json
[
  {
    "severity": "high",
    "description": "Connection timeout",
    "suggestion": "Check network policy"
  }
]
```"""
    anomalies = _parse_anomaly_json(raw_text)
    assert len(anomalies) == 1
    assert anomalies[0].severity == Severity.HIGH
    assert anomalies[0].description == "Connection timeout"


def test_parse_anomaly_json_wrapped_in_object():
    """Test parsing JSON when wrapped in an object with anomalies key."""
    raw_text = json.dumps({
        "anomalies": [
            {
                "severity": "medium",
                "description": "Memory leak potential",
                "suggestion": "Profile memory"
            }
        ]
    })
    anomalies = _parse_anomaly_json(raw_text)
    assert len(anomalies) == 1
    assert anomalies[0].severity == Severity.MEDIUM


def test_parse_anomaly_json_invalid():
    """Test parser resilience to invalid/empty inputs."""
    assert _parse_anomaly_json("") == []
    assert _parse_anomaly_json("This is not JSON") == []
    assert _parse_anomaly_json("[]") == []


# ==========================================
# 2. MockProvider Tests
# ==========================================

@pytest.mark.asyncio
async def test_mock_provider_critical():
    """Test MockProvider on critical/panic payload."""
    provider = MockProvider()
    payload = "Pod: payment-pod (10.0.0.2)\n[CRITICAL] Fatal panic: memory limit exceeded"
    anomalies = await provider.analyze(payload)
    assert len(anomalies) >= 1
    severities = [a.severity for a in anomalies]
    assert Severity.CRITICAL in severities
    assert anomalies[0].pod_name == "payment-pod"
    assert anomalies[0].pod_ip == "10.0.0.2"


@pytest.mark.asyncio
async def test_mock_provider_error():
    """Test MockProvider on database/connection error payload."""
    provider = MockProvider()
    payload = "Pod: auth-pod (10.0.0.3)\n[ERROR] Failed to connect to database"
    anomalies = await provider.analyze(payload)
    assert len(anomalies) >= 1
    severities = [a.severity for a in anomalies]
    assert Severity.HIGH in severities


@pytest.mark.asyncio
async def test_mock_provider_empty():
    """Test MockProvider with clean/empty payload."""
    provider = MockProvider()
    assert await provider.analyze("") == []
    assert await provider.analyze("Pod: test (10.0.0.1)\nNo critical logs found.") == []


@pytest.mark.asyncio
async def test_mock_provider_custom_sample():
    """Test MockProvider with custom sample anomalies."""
    custom = [
        Anomaly(
            id="custom-1",
            timestamp=datetime.now(),
            severity=Severity.LOW,
            description="Custom anomaly",
            pod_ip="10.0.0.1"
        )
    ]
    provider = MockProvider(sample_anomalies=custom)
    result = await provider.analyze("any payload")
    assert result == custom


# ==========================================
# 3. OllamaProvider Tests
# ==========================================

@pytest.mark.asyncio
async def test_ollama_provider_chat_success():
    """Test OllamaProvider making request to /api/chat enforcing format=json."""
    provider = OllamaProvider(
        ollama_url="http://localhost:11434",
        model="mistral",
        temperature=0.2
    )

    mock_response_data = {
        "model": "mistral",
        "message": {
            "role": "assistant",
            "content": json.dumps([
                {
                    "severity": "high",
                    "description": "Database deadlocks detected",
                    "suggestion": "Tune transaction isolation level",
                    "log_context": ["ERROR: deadlock detected"]
                }
            ])
        }
    }

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value=mock_response_data)

    mock_session = MagicMock()
    mock_session.__aenter__.return_value = mock_session
    mock_session.__aexit__.return_value = None
    mock_session.post.return_value.__aenter__.return_value = mock_response
    mock_session.post.return_value.__aexit__.return_value = None

    with patch("aiohttp.ClientSession", return_value=mock_session):
        anomalies = await provider.analyze("Pod: db-pod (10.0.0.5)\n[ERROR] deadlock detected")

        mock_session.post.assert_called_once()
        call_args = mock_session.post.call_args
        url = call_args[0][0]
        json_body = call_args[1]["json"]

        assert url == "http://localhost:11434/api/chat"
        assert json_body["model"] == "mistral"
        assert json_body["format"] == "json"
        assert json_body["stream"] is False
        assert json_body["options"]["temperature"] == 0.2

        assert len(anomalies) == 1
        assert anomalies[0].severity == Severity.HIGH
        assert anomalies[0].description == "Database deadlocks detected"


@pytest.mark.asyncio
async def test_ollama_provider_error_handling():
    """Test OllamaProvider handling HTTP errors gracefully."""
    provider = OllamaProvider(ollama_url="http://localhost:11434")

    mock_response = MagicMock()
    mock_response.status = 500
    mock_response.text = AsyncMock(return_value="Internal Server Error")

    mock_session = MagicMock()
    mock_session.__aenter__.return_value = mock_session
    mock_session.__aexit__.return_value = None
    mock_session.post.return_value.__aenter__.return_value = mock_response
    mock_session.post.return_value.__aexit__.return_value = None

    with patch("aiohttp.ClientSession", return_value=mock_session):
        anomalies = await provider.analyze("Payload")
        assert anomalies == []


# ==========================================
# 4. GroqProvider Tests
# ==========================================

@pytest.mark.asyncio
async def test_groq_provider_success():
    """Test GroqProvider making request to Groq endpoint with token and model."""
    provider = GroqProvider(
        groq_token="gsk_test123",
        groq_model="gemma2-9b-it",
        temperature=0.3,
        max_tokens=400
    )

    mock_response_data = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": json.dumps([
                        {
                            "severity": "critical",
                            "description": "Kernel OOM Killer invoked",
                            "suggestion": "Increase container memory limit or profile heap dump",
                            "log_context": ["Killed process 123 (java) total-vm:2048MB"]
                        }
                    ])
                }
            }
        ]
    }

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value=mock_response_data)

    mock_session = MagicMock()
    mock_session.__aenter__.return_value = mock_session
    mock_session.__aexit__.return_value = None
    mock_session.post.return_value.__aenter__.return_value = mock_response
    mock_session.post.return_value.__aexit__.return_value = None

    with patch("aiohttp.ClientSession", return_value=mock_session):
        anomalies = await provider.analyze("Pod: backend-pod (10.0.0.9)\n[CRITICAL] Out of memory")

        mock_session.post.assert_called_once()
        call_args = mock_session.post.call_args
        url = call_args[0][0]
        headers = call_args[1]["headers"]
        json_body = call_args[1]["json"]

        assert url == "https://api.groq.com/openai/v1/chat/completions"
        assert headers["Authorization"] == "Bearer gsk_test123"
        assert json_body["model"] == "gemma2-9b-it"
        assert json_body["temperature"] == 0.3
        assert json_body["max_tokens"] == 400
        # System prompt should demand strict JSON output
        system_msg = next(m["content"] for m in json_body["messages"] if m["role"] == "system")
        assert "strict JSON" in system_msg

        assert len(anomalies) == 1
        assert anomalies[0].severity == Severity.CRITICAL
        assert anomalies[0].description == "Kernel OOM Killer invoked"


@pytest.mark.asyncio
async def test_groq_provider_missing_token():
    """Test GroqProvider returns empty list when token is missing."""
    provider = GroqProvider(groq_token="")
    anomalies = await provider.analyze("Some payload")
    assert anomalies == []


# ==========================================
# 5. Factory get_ai_provider Tests
# ==========================================

def test_get_ai_provider_mock():
    """Test factory returning MockProvider."""
    config = AIConfig(provider="mock", mock_mode=True)
    provider = get_ai_provider(config)
    assert isinstance(provider, MockProvider)

    # Disabled config
    config_disabled = AIConfig(enabled=False)
    assert isinstance(get_ai_provider(config_disabled), MockProvider)


def test_get_ai_provider_ollama():
    """Test factory returning OllamaProvider."""
    config = AIConfig(
        provider="ollama",
        ollama_url="http://192.168.1.50:11434",
        ollama_model="llama3",
        mock_mode=False
    )
    provider = get_ai_provider(config)
    assert isinstance(provider, OllamaProvider)
    assert provider.ollama_url == "http://192.168.1.50:11434"
    assert provider.model == "llama3"


def test_get_ai_provider_groq():
    """Test factory returning GroqProvider."""
    config = AIConfig(
        provider="groq",
        groq_token="gsk_secret_123",
        groq_model="gemma2-9b-it",
        mock_mode=False
    )
    provider = get_ai_provider(config)
    assert isinstance(provider, GroqProvider)
    assert provider.groq_token == "gsk_secret_123"
    assert provider.groq_model == "gemma2-9b-it"


def test_get_ai_provider_openai():
    """Test factory returning OpenAIProvider."""
    config = AIConfig(
        provider="openai",
        openai_token="sk-test-token",
        openai_model="gpt-4o",
        mock_mode=False
    )
    provider = get_ai_provider(config)
    assert isinstance(provider, OpenAIProvider)
    assert provider.api_token == "sk-test-token"
    assert provider.model == "gpt-4o"


# ==========================================
# 6. AIAnalyzer Integration Tests
# ==========================================

@pytest.mark.asyncio
async def test_ai_analyzer_with_mock_provider(sample_error_logs, sample_pod_status):
    """Test AIAnalyzer pipeline coordination with MockProvider."""
    config = AIConfig(provider="mock", mock_mode=True)
    analyzer = AIAnalyzer(config=config)

    anomalies = await analyzer.analyze_logs(sample_error_logs, sample_pod_status)
    assert isinstance(anomalies, list)
    assert len(anomalies) >= 1
    assert anomalies[0].pod_ip == sample_pod_status.ip
    assert anomalies[0].pod_name == sample_pod_status.name


@pytest.mark.asyncio
async def test_ai_analyzer_custom_provider(sample_error_logs, sample_pod_status):
    """Test AIAnalyzer with custom injected provider."""
    mock_prov = AsyncMock(spec=AIProvider)
    mock_prov.analyze = AsyncMock(return_value=[
        Anomaly(
            id="injected-1",
            timestamp=datetime.now(),
            severity=Severity.HIGH,
            description="Custom injected anomaly",
            pod_ip=sample_pod_status.ip,
            pod_name=sample_pod_status.name
        )
    ])

    analyzer = AIAnalyzer(provider=mock_prov)
    anomalies = await analyzer.analyze_logs(sample_error_logs, sample_pod_status)

    mock_prov.analyze.assert_called_once()
    assert len(anomalies) == 1
    assert anomalies[0].description == "Custom injected anomaly"
    # Ensure anomalies are attached to pod_status
    assert sample_pod_status.anomalies == anomalies


@pytest.mark.asyncio
async def test_ai_analyzer_timeout_error_handling(sample_error_logs, sample_pod_status):
    """Test AIAnalyzer gracefully handles TimeoutError without raising."""
    mock_prov = AsyncMock(spec=AIProvider)
    mock_prov.analyze = AsyncMock(side_effect=TimeoutError("Request timed out"))

    analyzer = AIAnalyzer(provider=mock_prov)
    anomalies = await analyzer.analyze_logs(sample_error_logs, sample_pod_status)

    assert anomalies == []
    assert sample_pod_status.anomalies == []


@pytest.mark.asyncio
async def test_ai_analyzer_rate_limit_error_handling(sample_error_logs, sample_pod_status):
    """Test AIAnalyzer gracefully handles rate limit (429) ClientResponseError."""
    mock_prov = AsyncMock(spec=AIProvider)
    response_error = aiohttp.ClientResponseError(
        request_info=MagicMock(),
        history=(),
        status=429,
        message="Too Many Requests"
    )
    mock_prov.analyze = AsyncMock(side_effect=response_error)

    analyzer = AIAnalyzer(provider=mock_prov)
    anomalies = await analyzer.analyze_logs(sample_error_logs, sample_pod_status)

    assert anomalies == []
    assert sample_pod_status.anomalies == []


@pytest.mark.asyncio
async def test_ai_analyzer_json_decode_error_handling(sample_error_logs, sample_pod_status):
    """Test AIAnalyzer gracefully handles JSONDecodeError."""
    mock_prov = AsyncMock(spec=AIProvider)
    mock_prov.analyze = AsyncMock(side_effect=json.JSONDecodeError("Invalid JSON", "doc", 0))

    analyzer = AIAnalyzer(provider=mock_prov)
    anomalies = await analyzer.analyze_logs(sample_error_logs, sample_pod_status)

    assert anomalies == []
    assert sample_pod_status.anomalies == []


@pytest.mark.asyncio
async def test_ai_analyzer_generic_exception_handling(sample_error_logs, sample_pod_status):
    """Test AIAnalyzer gracefully handles generic runtime exceptions."""
    mock_prov = AsyncMock(spec=AIProvider)
    mock_prov.analyze = AsyncMock(side_effect=RuntimeError("Unexpected internal failure"))

    analyzer = AIAnalyzer(provider=mock_prov)
    anomalies = await analyzer.analyze_logs(sample_error_logs, sample_pod_status)

    assert anomalies == []
    assert sample_pod_status.anomalies == []


def test_ai_analyzer_summary_generation():
    """Test AIAnalyzer.generate_summary formatting."""
    analyzer = AIAnalyzer(mock_mode=True)

    # Empty anomalies
    assert "No anomalies detected" in analyzer.generate_summary([])

    # With anomalies
    anomalies = [
        Anomaly(
            id="1",
            timestamp=datetime.now(),
            severity=Severity.CRITICAL,
            description="Container crash",
            pod_ip="10.0.0.1",
            suggestion="Check memory limits"
        )
    ]
    summary = analyzer.generate_summary(anomalies)
    assert "1 anomalies detected" in summary
    assert "[CRITICAL] Container crash" in summary
    assert "Check memory limits" in summary
