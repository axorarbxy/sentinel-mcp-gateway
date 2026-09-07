\# 🛡️ Sentinel-MCP Gateway



\### AI/ML Security Monitoring Framework for MCP-Connected Ecosystems



\[!\[Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

\[!\[FastAPI](https://img.shields.io/badge/FastAPI-0.115.0-green.svg)](https://fastapi.tiangolo.com/)

\[!\[Research](https://img.shields.io/badge/Research-SECUREVENT%202026-red.svg)](https://arxiv.org/abs/2606.01741)

\[!\[License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)



\---



\## 📋 Overview



\*\*Sentinel-MCP\*\* is a cutting-edge security monitoring framework for AI agents using the Model Context Protocol (MCP). Built on 2026 research foundations, it provides \*\*three-layer defense\*\*:



1\. \*\*Rule-based Policy Engine\*\* - Blocks dangerous operations (path traversal, malicious commands, SQL injection)

2\. \*\*Behavioral Analysis\*\* - Detects suspicious patterns (rapid requests, unusual timing, operation chains)

3\. \*\*ML Anomaly Detection\*\* - Uses Isolation Forest to identify behavioral deviations



\### 🎯 Why This Matters



> \*"MCP servers wrapping offensive tools introduce higher risk than skill-based resources"\* - 2026 MCP Security Research



As AI agents gain access to more tools (filesystem, shell, databases, network), securing the \*\*MCP communication layer\*\* becomes critical. Sentinel-MCP acts as a \*\*security proxy\*\* between AI agents and their tools, ensuring every operation is validated, monitored, and audited.



\---



\## 🔬 Research Foundation



This project implements the hybrid approach proposed in:



| Paper | Year | Contribution |

|-------|------|--------------|

| \*\*SECUREVENT\*\* (arXiv 2606.01741) | 2026 | Hybrid AI/ML monitoring for distributed event systems |

| \*\*MCP Security Analysis\*\* | 2026 | MCP attack surface identification |

| \*\*Agentic SOC Evolution\*\* | 2026 | AI-powered security operations |



\*\*Key Research Contributions:\*\*

\- ✅ Online anomaly detection for event-based systems

\- ✅ Graph-aware behavioral feature extraction

\- ✅ Policy-as-code integration with model scoring

\- ✅ MITRE ATLAS mapping for AI-specific threats



\---



\## ✨ Features



\### 🔒 Security Policies

\- \*\*Path Traversal Prevention\*\* - Blocks access to `/etc/passwd`, `.env`, `.git`, etc.

\- \*\*Command Whitelisting\*\* - Only allows safe commands (`ls`, `pwd`, `whoami`, etc.)

\- \*\*SQL Injection Protection\*\* - Detects `DROP`, `DELETE`, `TRUNCATE`, and other dangerous patterns

\- \*\*Zero-Trust Architecture\*\* - Block by default, allow explicitly



\### 🧠 ML Anomaly Detection

\- \*\*Behavioral Profiling\*\* - Learns normal agent behavior patterns

\- \*\*Isolation Forest\*\* - Unsupervised anomaly detection

\- \*\*Feature Engineering\*\* - Extracts 15+ behavioral features:

&#x20; - Request frequency and timing

&#x20; - Method type distribution

&#x20; - Parameter complexity

&#x20; - Command length and structure

&#x20; - SQL complexity patterns

\- \*\*Real-time Detection\*\* - Identifies anomalies within milliseconds



\### 📊 Monitoring \& Auditing

\- \*\*Request Logging\*\* - Complete audit trail of all MCP operations

\- \*\*Alert System\*\* - Real-time anomaly alerts

\- \*\*Statistics Dashboard\*\* - Visualize block rates, method distribution, anomaly counts

\- \*\*Agent Profiling\*\* - Per-agent behavioral models



\### 🎯 MITRE ATLAS Ready

Maps security violations to MITRE ATLAS techniques:

\- AML.T0086 - Exfiltration via AI Agent Tool Invocation

\- AML.T0043 - Adversarial AI System Compromise

\- AML.T0010 - Data Poisoning via AI System Input



\---



\## 🚀 Quick Start



\### Prerequisites

\- Python 3.11 or higher

\- Git



\### Installation



```bash

\# Clone the repository

git clone https://github.com/axorarbxy/sentinel-mcp-gateway.git

cd sentinel-mcp-gateway



\# Create virtual environment

python -m venv venv



\# Activate virtual environment

\# Windows:

venv\\Scripts\\activate

\# Mac/Linux:

source venv/bin/activate



\# Install dependencies

pip install -r requirements.txt

