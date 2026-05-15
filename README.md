# 🚀 BYOD (Build Your Own DAST)
**Autonomous AI-Powered DAST & SAST Security Platform**

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Docker](https://img.shields.io/badge/docker-ready-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Next.js](https://img.shields.io/badge/Next.js-Frontend-black)
![License](https://img.shields.io/badge/license-MIT-green)

**BYOD (Build Your Own DAST)** is an advanced, open-source security testing platform that merges traditional pentesting tools with cutting-edge Artificial Intelligence. By utilizing a **Multi-Agent System**, BYOD orchestrates reconnaissance, exploitation, and reporting phases, dynamically analyzing findings to drastically reduce false positives and provide actionable security insights.

---

## ✨ Key Features

- 🧠 **AI-Driven Orchestration:** Uses advanced LLMs to act as an automated security auditor, understanding context, chaining vulnerabilities, and making intelligent decisions during scans.
- 🕵️ **Multi-Agent Architecture:** Dedicated AI agents for Reconnaissance, Exploitation, Correlation, and Reporting.
- 🐳 **Isolated Docker Sandbox:** Executes traditional pentesting tools securely within containerized environments.
- ⚡ **Real-Time Execution Engine:** Powered by FastAPI, Celery, and Redis for asynchronous job processing and WebSockets for live terminal feedback in the UI.
- 📊 **Modern Dashboard:** A sleek frontend built with Next.js and TailwindCSS to manage projects, launch scans, and review correlated findings.
- 🔗 **Smart Correlation Engine:** Automatically deduplicates and correlates outputs from multiple tools (SAST & DAST) into unified vulnerability reports.

---

## 🏗️ Architecture Stack

- **Frontend:** Next.js (React), TailwindCSS
- **Backend:** FastAPI (Python), SQLAlchemy, WebSockets
- **Task Queue:** Celery, Redis
- **Database:** PostgreSQL
- **Infrastructure:** Docker & Docker Compose

---

## 🚀 Getting Started

### Prerequisites

Make sure you have the following installed on your host machine:

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)
- Git

### Installation & Build

1. **Clone the repository:**

```bash
git clone https://github.com/yourusername/BYOD.git
cd BYOD
```

2. **Configure Environment Variables:**

Copy the example environment file and configure your API keys and database credentials.

```bash
cp .env.example .env
```

3. **Build and Run the Stack:**

Launch the entire platform (Frontend, Backend, Postgres, Redis, Celery Workers) using Docker Compose.

```bash
docker compose up -d --build
```

4. **Access the Platform:**
   - **Frontend UI:** `http://localhost:3000`
   - **Backend API Docs (Swagger):** `http://localhost:8000/docs`

---

## 🤖 Supported LLM Models

BYOD is highly flexible and model-agnostic. You can configure different Large Language Models (LLMs) to power the multi-agent system depending on your budget, privacy requirements, and desired performance.

Configure your preferred provider in the `.env` file or via the UI's **AI Settings** panel.

---

### 1. 🟢 OpenAI (ChatGPT)

The industry standard for complex reasoning and agentic workflows.

```env
LLM_PROVIDER=openai
LLM_MODEL=
OPENAI_API_KEY=sk-your-openai-api-key
```

---

### 2. 🟠 Anthropic (Claude)

Excellent for handling massive context windows (like reading huge codebase logs or tool outputs) with highly accurate, safe reasoning.

```env
LLM_PROVIDER=anthropic
LLM_MODEL=
ANTHROPIC_API_KEY=sk-ant-your-anthropic-api-key
```

---

### 3. 🔵 Google (Gemini)

Extremely fast processing and great multimodal capabilities. Perfect for quick log analysis and code review.

```env
LLM_PROVIDER=gemini
LLM_MODEL=
GEMINI_API_KEY=AIzaSyYourGeminiKeyHere
```

---

### 4. 🟣 Hugging Face (Inference API)

Use any open-source model hosted on Hugging Face without downloading it locally. No GPU required.

```env
LLM_PROVIDER=huggingface
LLM_MODEL=mistralai/Mistral-7B-Instruct-v0.1    # Or: HuggingFaceH4/zephyr-7b-beta
HUGGINGFACE_API_KEY=hf_your-huggingface-token
```

> 💡 Get your free API token at [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens)

---

### 5. 🖥️ Local / Self-Hosted (Ollama)

For high-security environments where data **cannot leave your infrastructure**. Run models like Llama 3 or Mistral fully offline.

```env
LLM_PROVIDER=local
LLM_MODEL=llama3:8b
LOCAL_LLM_ENDPOINT=http://host.docker.internal:11434/v1
```

> 💡 Requires [Ollama](https://ollama.com/) running on your host machine.  
> Pull a model first: `ollama pull llama3:8b`

---

## 💻 Usage

1. **Create a Project:** Log into the UI and create a new target project (e.g., `example.com`).
2. **Configure AI Auditor:** Select your preferred LLM and set the aggressiveness level (Passive, Normal, Intrusive).
3. **Launch Scan:** Start the scan. The Celery workers will spin up isolated Docker containers for the required tools (Nmap, ZAP, Nuclei, etc.).
4. **Monitor Live:** Watch the WebSocket-powered terminal stream the agent's thought process and raw tool output in real-time.
5. **Review Findings:** Once complete, check the `Findings` tab. The AI Correlation engine will have grouped duplicates, verified exploits, and mapped vulnerabilities to CWE/CVSS standards.

---

## 🛠️ Development

To develop locally or add new security tools:

1. Check the `docs/` folder for in-depth architecture explanations.
2. New AI agents can be added in `backend/agents/`.
3. New security tool wrappers go into `backend/tools/`.

---

## 🛡️ Disclaimer

Please read our [Threat Model](docs/THREAT-MODEL.md) documentation to understand how BYOD isolates tool execution and handles sensitive data.

> ⚠️ **Do not use this tool on systems you do not own or have explicit written permission to test.**

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for more information.
