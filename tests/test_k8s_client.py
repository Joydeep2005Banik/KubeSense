import pytest
from pod_monitor.k8s_client import parse_k8s_memory

def test_parse_k8s_memory_ki():
    assert parse_k8s_memory("1024Ki") == 1.0
    assert parse_k8s_memory("2048Ki") == 2.0

def test_parse_k8s_memory_mi():
    assert parse_k8s_memory("1Mi") == 1.0
    assert parse_k8s_memory("500Mi") == 500.0

def test_parse_k8s_memory_gi():
    assert parse_k8s_memory("1Gi") == 1024.0
    assert parse_k8s_memory("2Gi") == 2048.0

def test_parse_k8s_memory_ti():
    assert parse_k8s_memory("1Ti") == 1048576.0

def test_parse_k8s_memory_m():
    # m is millibytes (used for cpu usually, but just testing parser)
    # 1000m = 1 byte = 1 / (1024 * 1024) MiB
    val = parse_k8s_memory("1000m")
    assert pytest.approx(val, 0.000001) == 1 / (1024 * 1024)

def test_parse_k8s_memory_k():
    val = parse_k8s_memory("1000K")
    assert pytest.approx(val, 0.001) == 0.976


def test_parse_k8s_memory_raw_bytes():
    # 1048576 bytes = 1 MiB
    assert parse_k8s_memory("1048576") == 1.0
    assert parse_k8s_memory(1048576) == 1.0

def test_parse_k8s_memory_invalid():
    assert parse_k8s_memory("") == 0.0
    assert parse_k8s_memory(None) == 0.0
    assert parse_k8s_memory("invalid") == 0.0
