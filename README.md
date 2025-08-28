# 🚀 InnoIgnitersAI – Cybersecurity Chatbot Backend API

**InnoIgnitersAI** is a powerful backend API designed to power an advanced cybersecurity chatbot. It provides real-time threat analysis, log inspection, compliance guidance, and actionable security insights for technical teams and end-users alike. Built with a multi-agent architecture, it integrates external tools and frameworks to deliver accurate cybersecurity intelligence.

---

## 🔹 Features

- **Multi-Agent Architecture**

  - **Knowledge Agent** – General cybersecurity Q&A, with specialized sub-agents:
    - **CVE & MITRE ATT&CK Agent** – Vulnerability intelligence and attack mapping.
    - **Compliance & Policy Agent** – NIST, ISO, GDPR guidance.
    - **Law Agent** – Regional (Myanmar) and international cybersecurity law.

- **Detection Agent** – Malware, phishing, and threat analysis.
- **Threat Intelligence Integration**
  - VirusTotal scanning for files, URLs, and domains.
  - Suspicious IP & domain analysis.
- **Security Log Analysis**

  - Supports system, firewall, IDS/IPS, and application logs.
  - Highlights suspicious activity, severity, and mitigation steps.

- **Incident Response Guidance**

  - Step-by-step remediation recommendations.
  - Risk assessment for urgent and long-term actions.

- **User Awareness Support**
  - Explains cybersecurity concepts in simple terms.
  - Identifies phishing or unsafe patterns.

---

## ⚙️ Tech Stack

- **Backend Framework:** FastAPI (Python)
- **Database:** PostgreSQL / SQLite
- **Auth & Security:** JWT-based authentication, role-based access
- **Integrations:** VirusTotal, MITRE ATT&CK, CVE databases, web search tools
- **Deployment:** Docker-ready, scalable for cloud or on-premise

---

## 🚀 Getting Started

1. **Clone the repository**

```bash
git clone https://github.com/yourusername/InnoIgnitersAI-backend.git
cd InnoIgnitersAI-backend
```

2. **Install dependencies**

```bash
pip install -r requirements.txt
```

3. **Setup environment**
   Create a .env file with required credentials (JWT secret, database URL, API keys).

4. **Run the server**

```bash
uvicorn main:app --reload
```
