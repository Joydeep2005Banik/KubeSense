import pytest
import os
from pathlib import Path
from pod_monitor.config import Config, SSHConfig, AIConfig, MonitorConfig, AlertConfig, load_config, get_default_config, create_default_config

def test_default_config():
    config = get_default_config()
    assert config.ssh.user == "root"
    assert config.ssh.port == 22
    assert config.ai.enabled == True
    assert config.ai.provider == "mock"
    assert config.monitor.mode == "kubectl"
    assert config.monitor.namespaces == ["default"]
    assert config.alerts.enabled == False

def test_config_validation_openai():
    config = get_default_config()
    config.ai.provider = "openai"
    config.ai.openai_token = None
    with pytest.raises(ValueError, match="OpenAI token required"):
        config.validate()

def test_config_validation_ollama():
    config = get_default_config()
    config.ai.provider = "ollama"
    config.ai.ollama_url = None
    with pytest.raises(ValueError, match="Ollama URL required"):
        config.validate()

def test_config_validation_groq():
    config = get_default_config()
    config.ai.provider = "groq"
    config.ai.groq_token = None
    with pytest.raises(ValueError, match="Groq token required"):
        config.validate()

def test_groq_config_defaults_and_env(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-groq-key")
    config = AIConfig.from_dict({})
    assert config.groq_token == "test-groq-key"
    assert config.groq_model == "gemma2-9b-it"

def test_create_and_load_config(tmp_path):
    config_file = tmp_path / "test_config.yaml"
    create_default_config(str(config_file))
    
    assert config_file.exists()
    
    loaded_config = load_config(str(config_file))
    assert loaded_config.ssh.user == "root"
    assert loaded_config.monitor.mode == "kubectl"
    assert loaded_config.monitor.refresh_interval == 10
    
def test_config_from_dict():
    data = {
        'monitor': {
            'mode': 'ssh',
            'refresh_interval': 5,
            'namespaces': ['kube-system', 'default']
        },
        'alerts': {
            'enabled': True,
            'severity_threshold': 'critical'
        }
    }
    
    config = Config.from_dict(data)
    assert config.monitor.mode == "ssh"
    assert config.monitor.refresh_interval == 5
    assert config.monitor.namespaces == ['kube-system', 'default']
    assert config.alerts.enabled == True
    assert config.alerts.severity_threshold == "critical"
    # Ensure others have defaults
    assert config.ssh.user == "root"
    assert config.ai.provider == "mock"
