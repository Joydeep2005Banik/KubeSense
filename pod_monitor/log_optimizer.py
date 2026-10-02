"""
Log Optimizer for Pod Monitor.

Optimizes logs and pod metadata for LLM analysis by:
- Scrubbing sensitive PII (IPv4 addresses, UUIDs, email addresses)
- Deduplicating consecutive identical log messages
- Filtering for critical log levels (WARNING, ERROR, CRITICAL)
- Preparing clean, token-efficient payloads for LLM prompts
"""

import re
import copy
from dataclasses import replace, is_dataclass
from typing import List, Optional, Any, Union
from datetime import datetime

from .models import LogEntry, LogLevel, PodStatus, PodMetrics

# Regular expressions for PII masking
# IPv4 address matching valid octets (0-255)
IPV4_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b'
)

# Standard UUID: 8-4-4-4-12 hexadecimal digits
UUID_REGEX = re.compile(
    r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
)

# Email address pattern
EMAIL_REGEX = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
)

# Critical log levels to preserve
CRITICAL_LOG_LEVELS = {LogLevel.WARNING, LogLevel.ERROR, LogLevel.CRITICAL}
CRITICAL_LOG_LEVEL_NAMES = {"WARNING", "WARN", "ERROR", "ERR", "CRITICAL", "FATAL"}


class LogOptimizer:
    """
    Pipeline for optimizing Kubernetes pod logs before LLM processing.
    Reduces token usage and protects privacy by sanitizing PII, deduplicating,
    and filtering relevant log entries.
    """

    IP_PLACEHOLDER = "[REDACTED_IP]"
    UUID_PLACEHOLDER = "[REDACTED_UUID]"
    EMAIL_PLACEHOLDER = "[REDACTED_EMAIL]"

    def __init__(
        self,
        redact_ip: str = "[REDACTED_IP]",
        redact_uuid: str = "[REDACTED_UUID]",
        redact_email: str = "[REDACTED_EMAIL]",
    ):
        self.redact_ip = redact_ip
        self.redact_uuid = redact_uuid
        self.redact_email = redact_email

    @staticmethod
    def scrub_pii(log_string: str) -> str:
        """
        Mask IPv4 addresses, UUIDs, and email addresses with placeholders.

        Args:
            log_string: Raw log message text

        Returns:
            Sanitized log string with PII replaced by placeholders
        """
        if not log_string:
            return "" if log_string is None else log_string

        if not isinstance(log_string, str):
            log_string = str(log_string)

        # Scrub email addresses first
        sanitized = EMAIL_REGEX.sub(LogOptimizer.EMAIL_PLACEHOLDER, log_string)

        # Scrub UUIDs
        sanitized = UUID_REGEX.sub(LogOptimizer.UUID_PLACEHOLDER, sanitized)

        # Scrub IPv4 addresses
        sanitized = IPV4_REGEX.sub(LogOptimizer.IP_PLACEHOLDER, sanitized)

        return sanitized

    @staticmethod
    def _format_deduplicated_entry(entry: LogEntry, count: int) -> LogEntry:
        """Helper to create a LogEntry with repetition prefix if count > 1."""
        if count <= 1:
            return entry

        original_msg = getattr(entry, "message", "")
        new_msg = f"[Repeated {count} times] {original_msg}"

        if is_dataclass(entry):
            return replace(entry, message=new_msg)
        else:
            new_entry = copy.copy(entry)
            new_entry.message = new_msg
            return new_entry

    @classmethod
    def deduplicate(cls, logs: List[LogEntry]) -> List[LogEntry]:
        """
        Collapse consecutive identical log messages into a single entry with a
        '[Repeated X times]' prefix.

        Args:
            logs: List of LogEntry objects

        Returns:
            New list of LogEntry objects with consecutive duplicates collapsed
        """
        if not logs:
            return []

        result: List[LogEntry] = []
        current_entry = logs[0]
        count = 1

        for next_entry in logs[1:]:
            current_msg = getattr(current_entry, "message", "")
            next_msg = getattr(next_entry, "message", "")

            if next_msg == current_msg:
                count += 1
            else:
                result.append(cls._format_deduplicated_entry(current_entry, count))
                current_entry = next_entry
                count = 1

        # Flush final entry
        result.append(cls._format_deduplicated_entry(current_entry, count))
        return result

    @staticmethod
    def filter_critical_logs(logs: List[LogEntry]) -> List[LogEntry]:
        """
        Filter logs to only return entries with levels WARNING, ERROR, or CRITICAL.

        Args:
            logs: List of LogEntry objects

        Returns:
            Filtered list of LogEntry objects
        """
        if not logs:
            return []

        filtered: List[LogEntry] = []
        for log in logs:
            level = getattr(log, "level", None)
            if isinstance(level, LogLevel) and level in CRITICAL_LOG_LEVELS:
                filtered.append(log)
            elif isinstance(level, str) and level.upper() in CRITICAL_LOG_LEVEL_NAMES:
                filtered.append(log)
        return filtered

    @classmethod
    def optimize_logs(
        cls,
        logs: List[LogEntry],
        filter_critical: bool = True,
        deduplicate: bool = True,
        scrub_pii: bool = True,
    ) -> List[LogEntry]:
        """
        Run the optimization pipeline on a list of LogEntry objects.

        Args:
            logs: List of LogEntry objects
            filter_critical: Whether to filter only WARNING, ERROR, CRITICAL logs
            deduplicate: Whether to collapse consecutive identical logs
            scrub_pii: Whether to scrub PII from log messages

        Returns:
            List of optimized LogEntry objects
        """
        if not logs:
            return []

        result = list(logs)
        if filter_critical:
            result = cls.filter_critical_logs(result)
        if deduplicate:
            result = cls.deduplicate(result)
        if scrub_pii:
            scrubbed: List[LogEntry] = []
            for entry in result:
                msg = getattr(entry, "message", "")
                new_msg = cls.scrub_pii(msg)
                if is_dataclass(entry):
                    scrubbed.append(replace(entry, message=new_msg))
                else:
                    new_entry = copy.copy(entry)
                    new_entry.message = new_msg
                    scrubbed.append(new_entry)
            result = scrubbed
        return result

    @classmethod
    def prepare_payload(
        cls,
        logs: Optional[List[LogEntry]] = None,
        pod_status: Optional[PodStatus] = None,
        filter_critical: bool = True,
        deduplicate: bool = True,
        scrub_pii: bool = True,
        max_logs: Optional[int] = None,
    ) -> str:
        """
        Generate a clean, batched string representation of optimized logs and
        pod metadata (restarts, memory usage) ready to be injected into an LLM prompt.

        Args:
            logs: Optional list of LogEntry objects (defaults to pod_status.logs if None)
            pod_status: Optional PodStatus object containing pod metadata
            filter_critical: Whether to filter for critical log levels (default True)
            deduplicate: Whether to deduplicate consecutive identical logs (default True)
            scrub_pii: Whether to mask PII (default True)
            max_logs: Optional cap on the number of log lines to include

        Returns:
            Formatted string payload for LLM prompt
        """
        # Determine logs source
        target_logs = logs
        if target_logs is None and pod_status is not None:
            target_logs = getattr(pod_status, "logs", [])
        if target_logs is None:
            target_logs = []

        # Run optimization pipeline on logs
        optimized = cls.optimize_logs(
            target_logs,
            filter_critical=filter_critical,
            deduplicate=deduplicate,
            scrub_pii=scrub_pii,
        )

        if max_logs is not None and max_logs > 0:
            optimized = optimized[-max_logs:]

        # Build Metadata section
        meta_lines = []
        if pod_status is not None:
            name = getattr(pod_status, "name", "Unknown")
            namespace = getattr(pod_status, "namespace", "default")
            ip = getattr(pod_status, "ip", getattr(pod_status, "pod_ip", "Unknown"))
            if scrub_pii and ip:
                ip = cls.scrub_pii(ip)

            restarts = getattr(pod_status, "restarts", None)
            restarts_str = str(restarts) if restarts is not None else "0"

            # Memory metrics
            metrics = getattr(pod_status, "metrics", None)
            mem_str = "N/A"
            cpu_str = "N/A"
            if metrics is not None:
                mem_usage = getattr(metrics, "memory_usage", None)
                mem_limit = getattr(metrics, "memory_limit", None)
                if mem_usage is not None:
                    if mem_limit is not None and mem_limit > 0:
                        mem_str = f"{mem_usage:.1f} MiB / {mem_limit:.1f} MiB"
                    else:
                        mem_str = f"{mem_usage:.1f} MiB"

                cpu_usage = getattr(metrics, "cpu_usage", None)
                if cpu_usage is not None:
                    cpu_str = f"{cpu_usage:.1f}%"

            phase = getattr(pod_status, "phase", "")
            healthy = getattr(pod_status, "healthy", True)
            status_desc = phase if phase else ("Healthy" if healthy else "Unhealthy")

            error_count = getattr(pod_status, "error_count", 0)
            total_logs = getattr(pod_status, "total_logs", len(target_logs))

            meta_lines.append(f"Pod: {name} ({ip}) [Namespace: {namespace}]")
            meta_lines.append(f"Status: {status_desc}")
            meta_lines.append(f"Restarts: {restarts_str}")
            meta_lines.append(f"Memory Usage: {mem_str}")
            if cpu_str != "N/A":
                meta_lines.append(f"CPU Usage: {cpu_str}")
            meta_lines.append(f"Error Count: {error_count} / Total Logs: {total_logs}")

            status_reason = getattr(pod_status, "status_reason", None)
            if status_reason:
                meta_lines.append(f"Status Reason: {status_reason}")
            error_msg = getattr(pod_status, "error_message", None)
            if error_msg:
                meta_lines.append(f"Error Message: {cls.scrub_pii(error_msg) if scrub_pii else error_msg}")
        else:
            meta_lines.append("Pod: Unknown")
            meta_lines.append("Restarts: N/A")
            meta_lines.append("Memory Usage: N/A")

        # Format Logs section
        if optimized:
            formatted_logs = []
            for log in optimized:
                level = getattr(log, "level", "UNKNOWN")
                level_str = level.value.upper() if isinstance(level, LogLevel) else str(level).upper()
                msg = getattr(log, "message", "")
                formatted_logs.append(f"[{level_str}] {msg}")
            logs_section = "\n".join(formatted_logs)
        else:
            logs_section = "No critical logs found."

        payload = (
            "=== Pod Metadata ===\n"
            + "\n".join(meta_lines)
            + "\n\n=== Optimized Logs ===\n"
            + logs_section
        )
        return payload
