# AI-Native Multi-Agent Pentest Architecture v2

## 🎯 Visión

AutoPentest funciona como un **equipo de pentesters AI especializados** que colaboran usando **múltiples LLMs simultáneamente** con **fallback automático**.

```
┌────────────────────────────────────────────────────────────────┐
│                    USER REQUEST                                │
│                  "Pentest this URL"                            │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│              MULTI-AGENT ORCHESTRATOR                          │
│  Coordinates the entire workflow                               │
└────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌──────────────┐      ┌──────────────┐     ┌──────────────┐
│ RECON AGENT  │ ──▶  │EXPLOIT AGENT │ ──▶ │ANALYSIS AGENT│
│              │      │              │     │              │
│ • Crawl      │      │ • SQLi       │     │ • Validate   │
│ • Enumerate  │      │ • XSS        │     │ • Prioritize │
│ • Map        │      │ • SSRF       │     │ • CVSS Score │
│ • Tech stack │      │ • XXE,JWT,etc│     │ • Dedup      │
└──────────────┘      └──────────────┘     └──────────────┘
        │                     │                     │
        └─────────────────────┴─────────────────────┘
                              │
                              ▼
                      ┌──────────────┐
                      │ REPORT AGENT │
                      │ Final report │
                      └──────────────┘
                              │
                              ▼
                  ┌─────────────────────┐
                  │   LLM ORCHESTRATOR  │
                  │  (Multi-LLM router) │
                  └─────────────────────┘
                              │
        ┌─────┬───────┬───────┴────────┬───────┬─────┐
        ▼     ▼       ▼                ▼       ▼     ▼
     Gemini OpenAI Claude          Ollama   vLLM  .gguf
```

## 🤖 Agentes Especializados

### 1. ReconAgent
**Rol**: Reconocimiento y mapeo de superficie de ataque
**LLM Preferred**: Gemini Flash (rápido y económico)
**Herramientas usadas**:
- `extract_links` - Crawling
- `directory_bruteforce` - Hidden paths
- `subdomain_enum` - Subdomains
- `graphql_introspection_test` - GraphQL discovery
- `http_request` - Custom probes

### 2. ExploitAgent
**Rol**: Explotación activa de vulnerabilidades
**LLM Preferred**: GPT-4o o Claude Sonnet (mejores en razonamiento creativo)
**Herramientas usadas**: TODAS las 22+ disponibles, especialmente:
- `sql_injection_test`, `xss_test`
- `ssrf_test`, `xxe_test`, `ssti_test`
- `jwt_analyze`, `jwt_crack`
- `idor_test`, `path_traversal_test`
- `command_injection_test`
- `execute_python_code` - Custom exploits

### 3. AnalysisAgent
**Rol**: Validación y priorización
**LLM Preferred**: Claude Sonnet (excelente análisis)
**Tareas**:
- Elimina falsos positivos
- Calcula CVSS 3.1
- Asigna CWE IDs
- Mapea a OWASP Top 10
- Deduplica

### 4. ReportAgent
**Rol**: Generación de reporte profesional
**LLM Preferred**: GPT-4o (excelente escritura)
**Output**: Reporte markdown profesional

## 🔧 Herramientas Disponibles (22+)

### Básicas (7)
- `http_request` - Requests HTTP custom
- `extract_links` - Crawling
- `sql_injection_test` - SQLi
- `xss_test` - XSS
- `directory_bruteforce` - Fuzzing paths
- `execute_python_code` - Python custom
- `run_nuclei_template` - Nuclei templates

### Avanzadas (15)
- `ssrf_test` - SSRF + cloud metadata
- `xxe_test` - XML External Entity
- `jwt_analyze` - JWT vulnerability analysis
- `jwt_crack` - JWT secret cracking
- `idor_test` - Insecure Direct Object References
- `ssti_test` - Server-Side Template Injection (8 engines)
- `command_injection_test` - OS command injection
- `open_redirect_test` - Open redirects
- `cors_test` - CORS misconfiguration
- `file_upload_test` - Web shell upload
- `auth_bypass_test` - Header-based auth bypass
- `path_traversal_test` - LFI / path traversal
- `graphql_introspection_test` - GraphQL info leak
- `subdomain_enum` - Subdomain discovery
- `deserialization_test` - PHP/Java/.NET/Pickle

## 🧠 Multi-LLM con Fallback Automático

El sistema soporta **múltiples LLMs simultáneamente**:

### Modos de operación

**1. Fallback Automático**
```
Try LLM #1 (Gemini) ──fail──> Try LLM #2 (OpenAI) ──fail──> Try LLM #3 (Claude)
```

**2. Especialización por rol**
```
ReconAgent    → Gemini Flash (rápido, barato)
ExploitAgent  → GPT-4o (creativo, potente)
AnalysisAgent → Claude Sonnet (analítico)
ReportAgent   → GPT-4o (escritura)
```

**3. Consenso (opcional)**
```
Pregunta crítica → 3 LLMs responden → Tomar respuesta mayoritaria
```

### Configuración automática

Detecta automáticamente:
- ✅ `GEMINI_API_KEY` → Configura Gemini
- ✅ `OPENAI_API_KEY` → Configura GPT-4o, GPT-4o-mini
- ✅ `ANTHROPIC_API_KEY` → Configura Claude Sonnet
- ✅ Ollama corriendo → Detecta modelos locales
- ✅ `VLLM_BASE_URL` → vLLM server
- ✅ `LOCAL_GGUF_PATH` → Modelos GGUF locales

## 🚀 Uso

### Opción 1: Con todas las APIs

```bash
export GEMINI_API_KEY="tu-key"
export OPENAI_API_KEY="tu-key"
export ANTHROPIC_API_KEY="tu-key"

cd backend
python example_multi_agent.py
```

El sistema usará:
- Gemini para recon (rápido)
- GPT-4o para exploit (creativo)
- Claude para analysis (analítico)
- GPT-4o para report (escritura)
- Fallback automático si alguno falla

### Opción 2: Solo local (sin APIs)

```bash
# Iniciar Ollama
ollama serve

# Descargar modelos
ollama pull llama3.1:8b
ollama pull codellama:13b

# Ejecutar
python example_multi_agent.py
```

### Opción 3: Modelo .gguf personalizado

```bash
# Crear Modelfile
cat > Modelfile << EOF
FROM ./mi-modelo.gguf
EOF

# Registrar con Ollama
ollama create mi-modelo -f Modelfile

# Usar
python example_multi_agent.py
```

### Opción 4: Configuración mixta

```bash
# 1 API + Local fallback
export GEMINI_API_KEY="tu-key"
ollama serve  # Fallback local

python example_multi_agent.py
```

Si Gemini falla por rate limit → automáticamente usa Ollama local.

## 📊 Comparación con sistema anterior

| Característica | v1 (Tool-driven) | v2 (Multi-Agent) |
|---------------|------------------|-------------------|
| Decisión de qué testear | Scripts fijos | LLM autónomo |
| Tools disponibles | Scanner standalone | 22+ AI-callable |
| LLMs simultáneos | 1 | Múltiples |
| Fallback | ❌ | ✅ Automático |
| Especialización | ❌ | ✅ 4 agentes |
| Custom exploits | ❌ | ✅ Python on-the-fly |
| Adaptabilidad | Baja | Alta |
| Falsos positivos | Muchos | Validados por AI |

## 🎯 Ejemplo de flujo real

```
[ORCHESTRATOR] Starting Multi-Agent Pentest on http://target.com
[ORCHESTRATOR] LLM Status: {active: 4, by_role: {recon:1, exploit:2, analysis:1, report:1}}

[RECON] Starting reconnaissance
[RECON] Trying LLM: gemini:gemini-2.0-flash-exp:recon
[RECON] Tool: extract_links({"url": "http://target.com"})
[RECON] Found 47 links
[RECON] Tool: directory_bruteforce({"url": "http://target.com", "wordlist": "common"})
[RECON] Found /admin, /api, /backup.zip
[RECON] Tool: graphql_introspection_test({"url": "http://target.com/graphql"})
[RECON] Introspection enabled - leaked schema

[EXPLOIT] Starting exploitation phase
[EXPLOIT] Trying LLM: openai:gpt-4o:exploit
[EXPLOIT] Thinking: "I see /admin endpoint. Let me test auth bypass..."
[EXPLOIT] Tool: auth_bypass_test({"url": "/admin"})
[EXPLOIT] FOUND: [HIGH] Auth bypass via X-Original-URL

[EXPLOIT] Thinking: "Backup.zip exposed. Downloading..."
[EXPLOIT] Tool: http_request({"url": "/backup.zip"})
[EXPLOIT] Got backup file - contains DB credentials!
[EXPLOIT] FOUND: [CRITICAL] Database credentials in backup.zip

[ANALYSIS] Analyzing 7 raw findings
[ANALYSIS] Trying LLM: anthropic:claude-3-5-sonnet:analysis
[ANALYSIS] Validated: 5 real, 2 false positives
[ANALYSIS] CVSS calculated, CWE assigned

[REPORT] Generating final report
[REPORT] Trying LLM: openai:gpt-4o:reporting
[REPORT] Report generated (5,243 words)

✅ DONE: 5 validated findings, full report ready
```

## 🔮 Próximas mejoras

- [ ] Agentes que se comunican entre sí (no solo en cadena)
- [ ] Memory persistente (aprender de auditorías anteriores)
- [ ] Modo "swarm" - agentes en paralelo
- [ ] UI en tiempo real para ver el thinking de cada agente
- [ ] Plugin system para tools custom del usuario
- [ ] Integración con Burp Suite via API

## 📁 Archivos Clave

```
backend/services/
├── llm_provider.py           # Abstracción multi-LLM
├── llm_orchestrator.py       # Orquestador con fallback
├── pentest_tools.py          # Herramientas básicas
├── pentest_tools_advanced.py # 15 herramientas avanzadas
├── ai_auditor.py             # Auditor single-agent (legacy)
└── multi_agent_system.py     # Sistema multi-agente NUEVO

backend/workers/tasks/
└── ai_audit_tasks.py         # Tareas Celery (ambos modos)

backend/
├── example_ai_audit.py       # Demo single-agent
└── example_multi_agent.py    # Demo multi-agent
```
