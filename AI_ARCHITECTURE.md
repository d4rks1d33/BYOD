# AI-Native Penetration Testing Architecture

## Overview

AutoPentest has been redesigned to use **LLMs as autonomous pentesters**, not just analysis tools. The LLM acts as the brain that decides what to test, how to test it, and creates custom exploits when needed.

## Key Concept

```
┌─────────────────────────────────────────┐
│  Traditional Approach (OLD):            │
│  1. Tools scan → Find vulns             │
│  2. LLM analyzes results                │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│  AI-Native Approach (NEW):              │
│  1. LLM thinks: "What should I test?"   │
│  2. LLM executes tests & exploits       │
│  3. LLM adapts based on results         │
│  4. Tools are helpers, not drivers      │
└─────────────────────────────────────────┘
```

## Architecture Components

### 1. LLM Provider Abstraction (`services/llm_provider.py`)

Supports multiple LLM providers out of the box:

- **Gemini** (Google AI)
- **OpenAI** (GPT-4/GPT-4o)
- **Anthropic** (Claude)
- **Ollama** (Local models)
- **vLLM** (Local model serving)
- **Any .gguf model** via Ollama

Example usage:
```python
from services.llm_provider import get_llm_provider

# Use Gemini
llm = get_llm_provider("gemini", "gemini-2.0-flash-exp")

# Use local model
llm = get_llm_provider("ollama", "llama3.1:8b", host="http://localhost:11434")

# Use GPT-4
llm = get_llm_provider("openai", "gpt-4o")
```

### 2. Pentest Tools (`services/pentest_tools.py`)

Tools that the LLM can use via function calling:

- `http_request` - Make custom HTTP requests
- `extract_links` - Crawl and map application
- `sql_injection_test` - Test for SQLi
- `xss_test` - Test for XSS
- `directory_bruteforce` - Discover hidden paths
- `execute_python_code` - Write & run custom exploits
- `run_nuclei_template` - Run specific nuclei templates

The LLM decides **when** and **how** to use these tools.

### 3. AI Auditor (`services/ai_auditor.py`)

The autonomous pentester brain:

```python
from services.ai_auditor import AIAuditor
from services.llm_provider import get_llm_provider

llm = get_llm_provider("gemini", "gemini-2.0-flash-exp")
auditor = AIAuditor(llm, target_url="https://target.com", max_iterations=50)

result = auditor.run_audit()
# Returns: {findings, statistics, status}
```

**How it works:**

1. **System Prompt**: LLM is given pentester persona and methodology
2. **Tool Access**: LLM can call tools via function calling
3. **Autonomous Loop**: 
   - LLM analyzes target
   - Decides what to test next
   - Executes tests
   - Evaluates results
   - Adapts strategy
   - Reports findings
4. **Proof of Concept**: LLM creates working exploits for findings

### 4. Celery Task (`workers/tasks/ai_audit_tasks.py`)

Runs the AI audit asynchronously:

```python
from workers.tasks.ai_audit_tasks import run_ai_audit

result = run_ai_audit.delay(scan_id, config)
```

## Configuration

### Setting the LLM Provider

**Method 1: Database (Recommended)**

Configure via the web UI or database `ai_model_configs` table:

```sql
INSERT INTO ai_model_configs (
  name, provider, model_ref, is_active, is_default
) VALUES (
  'Gemini Flash', 'gemini', 'gemini-2.0-flash-exp', true, true
);
```

**Method 2: Environment Variables**

```bash
# Gemini
export GEMINI_API_KEY="your-key"

# OpenAI
export OPENAI_API_KEY="your-key"

# Anthropic
export ANTHROPIC_API_KEY="your-key"

# Ollama (local)
export OLLAMA_HOST="http://localhost:11434"
```

### Scan Configuration

When starting a scan, you can choose AI-native or legacy mode:

```python
{
  "use_ai_auditor": true,  # AI-native (default)
  "max_iterations": 50,     # Max LLM thinking loops
  "target_url": "https://target.com"
}

# Legacy mode (traditional tools)
{
  "use_ai_auditor": false
}
```

## How the AI Auditor Thinks

The LLM follows this methodology:

1. **Reconnaissance**
   - Crawl the application
   - Identify endpoints, forms, parameters
   - Map the attack surface

2. **Analysis**
   - Identify potential vulnerabilities
   - Prioritize high-impact vectors
   - Plan testing strategy

3. **Testing**
   - Execute targeted tests (SQLi, XSS, IDOR, etc.)
   - Create custom exploits when needed
   - Test edge cases and bypass attempts

4. **Verification**
   - Confirm findings with PoCs
   - Avoid false positives
   - Document evidence

5. **Reporting**
   - Format: `FINDING: [severity] [title] - [description]`
   - Includes evidence and reproduction steps
   - CVSS scoring

## Example AI Audit Flow

```
User: Start scan on https://vulnerable-app.com

AI Auditor: "Let me understand this application first."
  → Calls extract_links(url)
  → Discovers login form, search page, admin panel

AI Auditor: "I see a search parameter. Let me test for SQLi."
  → Calls sql_injection_test(url, param="q")
  → Detects SQL error messages

AI Auditor: "SQL injection confirmed. Creating PoC exploit."
  → Calls execute_python_code() with custom SQLi exploit
  → Extracts database schema

AI Auditor: "FINDING: [CRITICAL] SQL Injection in search - 
             The search parameter is vulnerable to SQL injection..."

AI Auditor: "Now testing the admin panel for access control..."
  → Calls http_request() with various payloads
  → Discovers IDOR vulnerability

[... continues autonomously ...]
```

## Adding New Tools

To add a new tool the AI can use:

1. **Add method to `PentestTools` class:**

```python
def custom_test(self, url: str, param: str) -> Dict[str, Any]:
    # Your tool logic
    return {"result": "...", "error": None}
```

2. **Add to tool definitions:**

```python
def get_available_tools():
    return [
        # ... existing tools ...
        {
            "name": "custom_test",
            "description": "What this tool does",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "param": {"type": "string"},
                },
                "required": ["url", "param"],
            },
        },
    ]
```

3. **Register in AIAuditor:**

```python
tool_map = {
    # ... existing tools ...
    "custom_test": self.tools.custom_test,
}
```

## Custom Exploits

The AI can write Python code to create custom exploits:

```python
# Example: LLM writes this code during audit
code = """
import requests

url = "https://target.com/api/user"
headers = {"Authorization": "Bearer stolen_token"}

response = requests.get(url, headers=headers)
print("User data:", response.json())
"""

result = tools.execute_python_code(code)
```

## Advantages over Traditional Scanning

1. **Adaptive**: LLM adjusts strategy based on what it finds
2. **Creative**: Can chain exploits and think outside the box
3. **Contextual**: Understands application logic, not just patterns
4. **Custom Exploits**: Writes code for unique vulnerabilities
5. **Efficient**: Doesn't waste time on irrelevant tests
6. **Multi-LLM**: Works with any LLM (cloud or local)

## Limitations & Considerations

1. **Cost**: API-based LLMs cost money per audit
2. **Speed**: More thorough but slower than traditional scanners
3. **Token Limits**: Long conversations may hit context limits
4. **Non-deterministic**: Results may vary between runs
5. **Tool Quality**: As good as the tools you give it

## Fallback to Legacy Mode

If you need traditional tool-driven scanning:

```python
config = {
    "use_ai_auditor": false,  # Use old tools-first approach
    "target_url": "https://target.com"
}
```

## Future Enhancements

- [ ] Multi-agent collaboration (recon agent, exploit agent, etc.)
- [ ] Learning from past audits (RAG/vector memory)
- [ ] Automatic report generation in natural language
- [ ] Interactive mode (user can guide the AI)
- [ ] Exploit marketplace (share custom tools)

## Questions?

The AI-native architecture makes AutoPentest a true **autonomous security researcher**, not just a tool orchestrator.

For issues or questions, see the main README or create an issue on GitHub.
