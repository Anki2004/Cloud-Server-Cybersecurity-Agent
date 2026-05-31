# 🛡️ MACIS — Multi-Agent Cybersecurity Intelligence System

> A production-grade, AI-powered cybersecurity threat detection and intelligence platform built with CrewAI, LangChain, Groq (LLaMA-3-70B), FastAPI, and deployed on AWS EC2 via Docker Compose and Terraform.

---

## 📌 Overview

MACIS is a multi-agent AI system designed to automate end-to-end cybersecurity threat detection, analysis, and reporting. It reduces manual threat analysis time by **70%** through a two-phase conditional agent architecture — moving from raw log/network/filesystem data to structured intelligence reports with zero human intervention.

Built as a final-year B.Tech project at **Maharaja Surajmal Institute of Technology (MSIT), Delhi**, the system demonstrates production-grade MLOps practices including cloud deployment, automated scheduling, real-time alerting, and observability.

---

## 🏗️ Architecture

MACIS uses a **two-phase conditional pipeline**:

### Phase 1 — Detection Agents (Parallel)
| Agent | Role |
|---|---|
| **Log Analysis Agent** | Parses system/application logs for anomalies and suspicious patterns |
| **Network Monitor Agent** | Analyzes network traffic metadata for intrusion signals |
| **Filesystem Agent** | Detects unauthorized file access, modifications, and anomalies |

> If Phase 1 detects a threat above the confidence threshold, Phase 2 is triggered automatically.

### Phase 2 — Intelligence Agents (Sequential)
| Agent | Role |
|---|---|
| **Threat Classifier** | Categorizes threat type, severity, and attack vector |
| **CVE Lookup Agent** | Cross-references vulnerabilities using EXA API for real-time intelligence |
| **Mitigation Strategist** | Generates actionable remediation steps |
| **Report Compiler** | Structures all findings into a standardized threat report |
| **Alert Dispatcher** | Sends Slack notifications with report summary |

---

## 🧰 Tech Stack

| Layer | Tools |
|---|---|
| **Agent Orchestration** | CrewAI, LangChain |
| **LLM Backend** | Groq API — LLaMA-3-70B |
| **Threat Intelligence** | EXA API (real-time web search) |
| **API Layer** | FastAPI |
| **Frontend Dashboard** | Streamlit |
| **Job Queue & Storage** | Redis |
| **Scheduling** | APScheduler |
| **Containerization** | Docker, Docker Compose |
| **Cloud Deployment** | AWS EC2 (t2.medium), AWS Systems Manager Session Manager |
| **Infrastructure as Code** | Terraform |
| **Observability** | AWS CloudWatch (log ingestion), Slack Alerting |
| **CI/CD** | GitHub Actions |

---

## ✨ Key Features

- **Automated threat scans** via APScheduler — runs on configurable intervals without manual triggers
- **Real-time Slack alerts** on threat detection with severity level and summary
- **CloudWatch log ingestion** for centralized observability on AWS
- **Redis-backed job storage** for persistent scan history and job state
- **Enhanced Streamlit dashboard** — live scan status, threat history, agent trace logs
- **EXA API integration** — agents pull live CVE data and threat advisories during analysis
- **Conditional Phase 2 activation** — intelligence pipeline only runs when Phase 1 confirms a threat, reducing compute cost

---

## 🚀 Deployment

### Prerequisites
- AWS account with EC2 and SSM permissions
- Terraform installed locally
- Docker and Docker Compose on the EC2 instance
- API keys: `GROQ_API_KEY`, `EXA_API_KEY`, `SLACK_WEBHOOK_URL`

### Infrastructure Setup (Terraform)
```bash
cd terraform/
terraform init
terraform plan
terraform apply
```

### Environment Variables
Create a `.env` file in the project root:
```env
GROQ_API_KEY=your_groq_api_key
EXA_API_KEY=your_exa_api_key
SLACK_WEBHOOK_URL=your_slack_webhook_url
REDIS_URL=redis://redis:6379
CLOUDWATCH_LOG_GROUP=macis-logs
```

### Run with Docker Compose
```bash
docker compose up --build -d
```

### Access the Dashboard
```
Streamlit UI  →  http://<EC2_PUBLIC_IP>:8501
FastAPI Docs  →  http://<EC2_PUBLIC_IP>:8000/docs
```

### Connect via AWS SSM (no SSH required)
```bash
aws ssm start-session --target <instance-id>
```

---

## 📁 Project Structure

```
MACIS/
├── agents/
│   ├── detection/
│   │   ├── log_agent.py
│   │   ├── network_agent.py
│   │   └── filesystem_agent.py
│   └── intelligence/
│       ├── threat_classifier.py
│       ├── cve_lookup.py
│       ├── mitigation_agent.py
│       ├── report_compiler.py
│       └── alert_dispatcher.py
├── api/
│   └── main.py                  # FastAPI app
├── dashboard/
│   └── app.py                   # Streamlit UI
├── scheduler/
│   └── jobs.py                  # APScheduler config
├── tools/
│   ├── log_tools.py
│   ├── network_tools.py
│   └── filesystem_tools.py
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   └── outputs.tf
├── tests/
│   └── test_detection_tools.py  # pytest suite
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── .env.example
```

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

Tests cover all Phase 1 detection tool functions with mocked inputs.

---

## 📊 Results

| Metric | Value |
|---|---|
| Manual threat analysis time reduction | **70%** |
| Phase 1 detection agents | 3 (parallel) |
| Phase 2 intelligence agents | 5 (sequential) |
| Deployment target | AWS EC2 (t2.medium) |
| Scheduling interval | Configurable (default: every 6 hours) |

---

## 🔮 Future Scope

- Fine-tune a custom LLM on cybersecurity-specific threat data
- Add SIEM integration (Splunk, Elastic SIEM)
- Expand detection to cloud-native environments (S3 access logs, VPC flow logs)
- Build multi-tenant support for enterprise deployment
- Add ML-based anomaly detection as a pre-filter before LLM agents

---

## 👤 Author

**Ankit Sharma**  
B.Tech — Information Technology, MSIT Delhi (2022–2026)  
IEEE Software Lead, MSIT  
📧 ankitsharma082004@gmail.com  
🔗 [LinkedIn](https://linkedin.com/in/ankit082004) | [GitHub](https://github.com/Anki2004)

---

## 📄 License

This project is for academic and portfolio purposes.  
© 2026 Ankit Sharma — All rights reserved.
