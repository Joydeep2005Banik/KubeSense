import pytest
from pod_monitor.ui import (
    _format_age, _status_tag, _severity_tag, 
    _log_level_tag, _sparkline, make_bar, _bar
)
from pod_monitor.models import Severity, LogLevel

def test_format_age():
    assert _format_age(None) == "--"
    assert _format_age(0) == "--"
    assert _format_age(-10) == "--"
    
    assert _format_age(45) == "45s"
    assert _format_age(60) == "1m 0s"
    assert _format_age(125) == "2m 5s"
    assert _format_age(3600) == "1h 0m"
    assert _format_age(3665) == "1h 1m"
    assert _format_age(86400) == "1d 0h"
    assert _format_age(90000) == "1d 1h"

def test_status_tag():
    assert "OK" in _status_tag(True)
    assert "!!" in _status_tag(False)
    assert "green" in _status_tag(True)
    assert "red" in _status_tag(False)

def test_severity_tag():
    assert "CRIT" in _severity_tag(Severity.CRITICAL)
    assert "red" in _severity_tag(Severity.CRITICAL)
    
    assert "HIGH" in _severity_tag(Severity.HIGH)
    assert "MED" in _severity_tag(Severity.MEDIUM)
    assert "LOW" in _severity_tag(Severity.LOW)

def test_log_level_tag():
    assert "CRIT" in _log_level_tag(LogLevel.CRITICAL)
    assert "ERR" in _log_level_tag(LogLevel.ERROR)
    assert "WARN" in _log_level_tag(LogLevel.WARNING)
    assert "INFO" in _log_level_tag(LogLevel.INFO)
    assert "DBG" in _log_level_tag(LogLevel.DEBUG)

def test_sparkline():
    # Empty
    assert _sparkline([], length=5) == "     "
    
    # Padding
    assert _sparkline([100.0], length=3) == "  █"
    
    # Values
    spark = _sparkline([0.0, 50.0, 100.0], length=3)
    assert len(spark) == 3
    assert spark[0] == " " # 0 is space
    assert spark[2] == "█" # 100 is full block

def test_make_bar():
    # 0 ratio
    bar = make_bar(0.0, width=10)
    assert "0.0%" in bar
    
    # 0.5 ratio
    bar = make_bar(0.5, width=10)
    assert "50.0%" in bar
    
    # 1.0 ratio
    bar = make_bar(1.0, width=10)
    assert "100.0%" in bar
    
    # clamps > 1.0
    bar = make_bar(1.5, width=10)
    assert "100.0%" in bar
    
    # clamps < 0.0
    bar = make_bar(-0.5, width=10)
    assert "0.0%" in bar

def test_bar():
    # Uses percentage out of 100
    bar = _bar(0.0, width=10)
    assert "0.0%" in bar
    
    bar = _bar(50.0, width=10)
    assert "50.0%" in bar
    
    bar = _bar(100.0, width=10)
    assert "100.0%" in bar
    
    bar = _bar(150.0, width=10)
    assert "100.0%" in bar
