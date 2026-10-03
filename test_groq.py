import asyncio
from pod_monitor.config import load_config
from pod_monitor.ai_analyzer import get_ai_provider
from pod_monitor.log_optimizer import LogOptimizer
from pod_monitor.models import PodStatus, LogEntry, LogLevel
from datetime import datetime

async def main():
    config = load_config()
    print("Provider:", config.ai.provider)
    provider = get_ai_provider(config.ai)
    
    logs = [
        LogEntry(timestamp=datetime.now(), level=LogLevel.INFO, message="Request #5 processed", pod_name="log-generator", pod_ip="10.0.0.1"),
        LogEntry(timestamp=datetime.now(), level=LogLevel.WARNING, message="High memory usage detected: 78%", pod_name="log-generator", pod_ip="10.0.0.1"),
        LogEntry(timestamp=datetime.now(), level=LogLevel.ERROR, message="Failed to authenticate user_id=9", pod_name="log-generator", pod_ip="10.0.0.1")
    ]
    pod = PodStatus(name="log-generator", namespace="default", ip="10.0.0.1")
    pod.logs = logs
    
    payload = LogOptimizer.prepare_payload(logs=logs, pod_status=pod)
    print("Payload:\n", payload)
    
    print("\nCalling AI...")
    anomalies = await provider.analyze(payload)
    print("\nAnomalies:", anomalies)

asyncio.run(main())
