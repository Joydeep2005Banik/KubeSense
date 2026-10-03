# KubeSense Architecture

KubeSense is a terminal-based UI (TUI) designed to monitor Kubernetes pods, fetch real-time metrics, stream logs, and leverage AI for log anomaly detection. 

## System Architecture

The core architecture of KubeSense is divided into distinct, decoupled components. At the center is the `PodMonitor` engine which orchestrates data collection and interfaces with the Textual-based UI.

```mermaid
graph TD
    subgraph UI Layer
        A[Terminal UI<br/>ui.py]
    end

    subgraph Core Logic
        B[Configuration<br/>config.py]
        C[Monitor Engine<br/>monitor.py]
    end

    subgraph Data Sources
        D[Kubernetes API<br/>k8s_client.py]
        E[SSH Fallback<br/>ssh_client.py]
    end

    subgraph AI Processing
        F[AI Analyzer<br/>ai_analyzer.py]
        G[Log Optimizer<br/>log_optimizer.py]
        H[LLM Providers<br/>Groq / OpenAI / Ollama]
    end

    B -->|Provides Settings| C
    C <-->|State Updates & Events| A
    C -->|Fetch Metrics & Logs| D
    C -->|Fallback Metrics| E
    
    C -->|Raw Logs| F
    F -->|Compress / Format| G
    G -->|Optimized Context| F
    F -->|Query| H
    H -->|Analysis Results| F
    F -->|Alerts| A
```

## Detailed Sub-System Mechanisms

### 1. Log Optimization Pipeline
Before logs are sent to the AI for analysis, they are aggressively filtered to save context tokens and protect privacy using the `LogOptimizer`.

```mermaid
flowchart LR
    A[Raw Log Stream] --> B{Severity Filter}
    B -- Drop INFO/DEBUG --> X[Discard]
    B -- Keep WARNING+ --> C[Deduplication]
    C -->|Collapse consecutive<br/>repeated errors| D[PII Scrubbing]
    D -->|Mask IPs & UUIDs| E[Optimized Payload]
```

### 2. Multi-Provider AI Engine
KubeSense does not rely on a single backend. The `ai_analyzer.py` module uses an abstract factory pattern to seamlessly switch between cloud inference and fully offline local analysis.

```mermaid
flowchart TD
    A[Optimized Payload] --> B{AI Factory Config}
    B -->|groq| C[GroqProvider<br/>Cloud API]
    B -->|openai| D[OpenAIProvider<br/>Cloud API]
    B -->|ollama| E[OllamaProvider<br/>Local/Air-gapped]
    B -->|mock| F[MockProvider<br/>Heuristics Fallback]
    
    C & D & E & F --> G[JSON Enforcement & Parser]
    G --> H[Anomaly Alerts to UI]
```

### 3. Graceful Fallback Metrics
If the Kubernetes Metrics Server is unavailable, KubeSense intelligently bypasses the API and connects directly to the underlying node to scrape system resources.

```mermaid
sequenceDiagram
    participant M as Monitor
    participant K as K8s Metrics API
    participant S as SSH Fallback
    participant N as Node Shell
    
    M->>K: Fetch Pod CPU/Mem
    alt Metrics Server Unavailable
        K-->>M: HTTP 404 / Error
        M->>S: Engage Fallback (asyncssh)
        S->>N: Connect to Node via SSH
        N-->>S: Execute `top` & parse usage
        S-->>M: Return hardware metrics
    else Success
        K-->>M: Standard API Metrics
    end
```

### 4. Reactive UI Binding (Textual)
The terminal interface uses Textual's event-driven reactive properties, ensuring lightning-fast updates without screen-tearing "while loops". 

```mermaid
flowchart LR
    A[Monitor Engine] -->|Sends updated<br/>Metrics Object| B(Reactive Variable)
    B -->|Triggers Auto-Update| C[UI Node / Widget]
    C -->|Only redraws changed region| D[Terminal Display]
```

## Execution Flow

The following sequence demonstrates how KubeSense starts up, collects metrics, and processes AI log anomaly detection.

```mermaid
sequenceDiagram
    participant U as User (CLI)
    participant M as Monitor Engine
    participant K as Kubernetes API
    participant UI as Textual UI
    participant AI as AI Analyzer

    U->>M: Launch (python -m pod_monitor)
    M->>M: Load Config (config.yaml)
    M->>K: Authenticate Cluster
    M->>UI: Initialize Interface
    
    loop Every `refresh_interval`
        M->>K: Request Pod Metrics & Status
        K-->>M: Return Resource Usage
        M->>UI: Update Dashboard UI
        
        M->>K: Request Live Logs
        K-->>M: Return Log Stream
        M->>UI: Stream Logs to Panel
        
        alt AI Analysis Enabled
            M->>AI: Send recent log batches
            AI->>AI: Optimize & Compress (LogOptimizer)
            AI->>LLM API: Analyze for Anomalies
            LLM API-->>AI: Return Insights
            AI->>UI: Trigger Anomaly Alert
        end
    end
```

## Configuration Management

Configuration is handled gracefully via `config.py`. The application first attempts to load settings from `config.yaml` and falls back to environment variables (like `OPENAI_API_KEY`) if explicitly set. This provides maximum flexibility for running KubeSense in local, headless, or CI/CD environments.
