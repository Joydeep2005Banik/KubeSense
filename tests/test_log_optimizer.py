"""
Unit tests for LogOptimizer pipeline.
"""

from datetime import datetime
import pytest

from pod_monitor.log_optimizer import LogOptimizer
from pod_monitor.models import LogEntry, LogLevel, PodStatus, PodMetrics


@pytest.fixture
def optimizer():
    return LogOptimizer()


@pytest.fixture
def sample_mixed_logs():
    now = datetime.now()
    return [
        LogEntry(
            timestamp=now,
            level=LogLevel.DEBUG,
            message="Debug trace: initialization details",
            pod_ip="10.244.0.5"
        ),
        LogEntry(
            timestamp=now,
            level=LogLevel.INFO,
            message="User session started for test@example.com",
            pod_ip="10.244.0.5"
        ),
        LogEntry(
            timestamp=now,
            level=LogLevel.WARNING,
            message="High memory pressure detected",
            pod_ip="10.244.0.5"
        ),
        LogEntry(
            timestamp=now,
            level=LogLevel.ERROR,
            message="Failed to connect to database at 192.168.1.50:5432",
            pod_ip="10.244.0.5"
        ),
        LogEntry(
            timestamp=now,
            level=LogLevel.ERROR,
            message="Failed to connect to database at 192.168.1.50:5432",
            pod_ip="10.244.0.5"
        ),
        LogEntry(
            timestamp=now,
            level=LogLevel.ERROR,
            message="Failed to connect to database at 192.168.1.50:5432",
            pod_ip="10.244.0.5"
        ),
        LogEntry(
            timestamp=now,
            level=LogLevel.CRITICAL,
            message="Fatal panic in worker 123e4567-e89b-12d3-a456-426614174000",
            pod_ip="10.244.0.5"
        ),
    ]


# ==========================================
# 1. PII Scrubbing Tests
# ==========================================

def test_scrub_pii_ipv4(optimizer):
    """Test masking of IPv4 addresses."""
    text = "Connection from 192.168.1.100:8080 to 10.0.0.1:443"
    result = optimizer.scrub_pii(text)
    assert result == "Connection from [REDACTED_IP]:8080 to [REDACTED_IP]:443"
    assert "192.168.1.100" not in result
    assert "10.0.0.1" not in result


def test_scrub_pii_ipv4_edge_cases(optimizer):
    """Test IPv4 edge cases like boundary values and invalid IPs."""
    text = "Valid: 0.0.0.0, 255.255.255.255, 127.0.0.1; Non-IP: 999.999.999.999, 1.2.3, version 1.0.0.0"
    result = optimizer.scrub_pii(text)
    assert "[REDACTED_IP]" in result
    assert "0.0.0.0" not in result
    assert "255.255.255.255" not in result
    assert "127.0.0.1" not in result
    assert "999.999.999.999" in result  # Invalid octet should not match
    assert "1.2.3" in result  # 3 octets should not match


def test_scrub_pii_uuid(optimizer):
    """Test masking of UUIDs (lowercase and uppercase)."""
    text = "Task c9bf9e57-1685-4c89-bafb-ff5af830be8a and Trace 123E4567-E89B-12D3-A456-426614174000"
    result = optimizer.scrub_pii(text)
    assert result == "Task [REDACTED_UUID] and Trace [REDACTED_UUID]"
    assert "c9bf9e57-1685-4c89-bafb-ff5af830be8a" not in result
    assert "123E4567-E89B-12D3-A456-426614174000" not in result


def test_scrub_pii_email(optimizer):
    """Test masking of email addresses."""
    text = "Alert sent to admin@k8s.local, dev.user+test@sub.example.com, and user123@domain.co.uk"
    result = optimizer.scrub_pii(text)
    assert result == "Alert sent to [REDACTED_EMAIL], [REDACTED_EMAIL], and [REDACTED_EMAIL]"
    assert "@" not in result


def test_scrub_pii_combined(optimizer):
    """Test masking of mixed PII in a single string."""
    text = "User alice@corp.com on 172.16.0.4 failed task 550e8400-e29b-41d4-a716-446655440000"
    result = optimizer.scrub_pii(text)
    assert result == "User [REDACTED_EMAIL] on [REDACTED_IP] failed task [REDACTED_UUID]"


def test_scrub_pii_empty_and_static_call():
    """Test scrub_pii on empty/None input and calling as staticmethod."""
    assert LogOptimizer.scrub_pii("") == ""
    assert LogOptimizer.scrub_pii(None) == ""
    assert LogOptimizer.scrub_pii("Clean log message") == "Clean log message"


# ==========================================
# 2. Deduplication Tests
# ==========================================

def test_deduplicate_empty():
    """Test deduplicate with empty list."""
    assert LogOptimizer.deduplicate([]) == []


def test_deduplicate_single_entry():
    """Test deduplicate with a single log entry."""
    entry = LogEntry(
        timestamp=datetime.now(),
        level=LogLevel.ERROR,
        message="Connection reset",
        pod_ip="10.0.0.1"
    )
    result = LogOptimizer.deduplicate([entry])
    assert len(result) == 1
    assert result[0].message == "Connection reset"


def test_deduplicate_consecutive_duplicates():
    """Test collapsing consecutive identical log messages."""
    now = datetime.now()
    logs = [
        LogEntry(timestamp=now, level=LogLevel.ERROR, message="Timeout", pod_ip="10.0.0.1"),
        LogEntry(timestamp=now, level=LogLevel.ERROR, message="Timeout", pod_ip="10.0.0.1"),
        LogEntry(timestamp=now, level=LogLevel.ERROR, message="Timeout", pod_ip="10.0.0.1"),
    ]
    result = LogOptimizer.deduplicate(logs)
    assert len(result) == 1
    assert result[0].message == "[Repeated 3 times] Timeout"
    assert result[0].level == LogLevel.ERROR
    assert result[0].pod_ip == "10.0.0.1"


def test_deduplicate_mixed_sequences():
    """Test deduplicate with mixed consecutive and non-consecutive duplicates."""
    now = datetime.now()
    logs = [
        LogEntry(timestamp=now, level=LogLevel.ERROR, message="Error A", pod_ip="10.0.0.1"),
        LogEntry(timestamp=now, level=LogLevel.ERROR, message="Error A", pod_ip="10.0.0.1"),
        LogEntry(timestamp=now, level=LogLevel.WARNING, message="Warning B", pod_ip="10.0.0.1"),
        LogEntry(timestamp=now, level=LogLevel.ERROR, message="Error A", pod_ip="10.0.0.1"),
        LogEntry(timestamp=now, level=LogLevel.CRITICAL, message="Critical C", pod_ip="10.0.0.1"),
        LogEntry(timestamp=now, level=LogLevel.CRITICAL, message="Critical C", pod_ip="10.0.0.1"),
        LogEntry(timestamp=now, level=LogLevel.CRITICAL, message="Critical C", pod_ip="10.0.0.1"),
        LogEntry(timestamp=now, level=LogLevel.CRITICAL, message="Critical C", pod_ip="10.0.0.1"),
    ]
    result = LogOptimizer.deduplicate(logs)
    assert len(result) == 4
    assert result[0].message == "[Repeated 2 times] Error A"
    assert result[1].message == "Warning B"
    assert result[2].message == "Error A"
    assert result[3].message == "[Repeated 4 times] Critical C"


# ==========================================
# 3. Critical Logs Filter Tests
# ==========================================

def test_filter_critical_logs():
    """Test filtering logs to only WARNING, ERROR, CRITICAL levels."""
    now = datetime.now()
    logs = [
        LogEntry(timestamp=now, level=LogLevel.DEBUG, message="Debug 1", pod_ip="10.0.0.1"),
        LogEntry(timestamp=now, level=LogLevel.INFO, message="Info 1", pod_ip="10.0.0.1"),
        LogEntry(timestamp=now, level=LogLevel.WARNING, message="Warn 1", pod_ip="10.0.0.1"),
        LogEntry(timestamp=now, level=LogLevel.ERROR, message="Error 1", pod_ip="10.0.0.1"),
        LogEntry(timestamp=now, level=LogLevel.CRITICAL, message="Crit 1", pod_ip="10.0.0.1"),
    ]
    filtered = LogOptimizer.filter_critical_logs(logs)
    assert len(filtered) == 3
    levels = [log.level for log in filtered]
    assert levels == [LogLevel.WARNING, LogLevel.ERROR, LogLevel.CRITICAL]


def test_filter_critical_logs_empty():
    """Test filtering empty log list or list without critical logs."""
    assert LogOptimizer.filter_critical_logs([]) == []

    now = datetime.now()
    info_logs = [
        LogEntry(timestamp=now, level=LogLevel.INFO, message="Info only", pod_ip="10.0.0.1"),
        LogEntry(timestamp=now, level=LogLevel.DEBUG, message="Debug only", pod_ip="10.0.0.1"),
    ]
    assert LogOptimizer.filter_critical_logs(info_logs) == []


# ==========================================
# 4. Pipeline & Payload Preparation Tests
# ==========================================

def test_optimize_logs(sample_mixed_logs):
    """Test the full optimization pipeline."""
    optimized = LogOptimizer.optimize_logs(sample_mixed_logs)
    # DEBUG and INFO are filtered out (2 removed)
    # 3 identical ERRORs are collapsed into 1 (2 removed)
    # Total remaining: 3 entries (WARNING, collapsed ERROR, CRITICAL)
    assert len(optimized) == 3
    assert optimized[0].message == "High memory pressure detected"
    assert optimized[1].message == "[Repeated 3 times] Failed to connect to database at [REDACTED_IP]:5432"
    assert optimized[2].message == "Fatal panic in worker [REDACTED_UUID]"


def test_prepare_payload_with_pod_status(sample_mixed_logs):
    """Test generating prompt payload with full pod metadata and logs."""
    pod_status = PodStatus(
        ip="192.168.1.50",
        name="payment-processor-7c6df",
        namespace="production",
        healthy=False,
        restarts=4,
        metrics=PodMetrics(
            memory_usage=384.2,
            memory_limit=512.0,
            cpu_usage=78.5,
        ),
        error_count=8,
        total_logs=120,
        status_reason="CrashLoopBackOff"
    )

    payload = LogOptimizer.prepare_payload(sample_mixed_logs, pod_status)

    assert "=== Pod Metadata ===" in payload
    assert "=== Optimized Logs ===" in payload
    assert "Pod: payment-processor-7c6df ([REDACTED_IP]) [Namespace: production]" in payload
    assert "Restarts: 4" in payload
    assert "Memory Usage: 384.2 MiB / 512.0 MiB" in payload
    assert "CPU Usage: 78.5%" in payload
    assert "Status Reason: CrashLoopBackOff" in payload
    assert "[WARNING] High memory pressure detected" in payload
    assert "[ERROR] [Repeated 3 times] Failed to connect to database at [REDACTED_IP]:5432" in payload
    assert "[CRITICAL] Fatal panic in worker [REDACTED_UUID]" in payload


def test_prepare_payload_fallback():
    """Test payload generation with minimal / None inputs."""
    payload = LogOptimizer.prepare_payload(logs=[], pod_status=None)
    assert "Pod: Unknown" in payload
    assert "Restarts: N/A" in payload
    assert "Memory Usage: N/A" in payload
    assert "No critical logs found." in payload
