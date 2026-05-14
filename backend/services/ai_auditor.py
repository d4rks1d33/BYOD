"""
AI Auditor - Autonomous penetration testing using LLMs
The LLM acts as the brain, deciding what to test and how.
"""
from __future__ import annotations
import logging
import json
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime

from services.llm_provider import LLMProvider
from services.pentest_tools import PentestTools, get_available_tools
from services.pentest_tools_advanced import AdvancedPentestTools, get_advanced_tools

logger = logging.getLogger(__name__)


PENTESTER_SYSTEM_PROMPT = """You are an ELITE penetration tester with 20+ years of experience in offensive security.

You have AUTHORIZATION to perform a full security audit on the target application.

# Your Mindset
You think like a real attacker. You're patient, creative, and methodical.
You don't just run tools - you UNDERSTAND the application and craft custom attacks.

# Methodology (OWASP-Aligned)

## Phase 1: Reconnaissance (15-25% of effort)
- Crawl the application thoroughly (use `extract_links`)
- Identify all endpoints, forms, parameters
- Detect technology stack (frameworks, libraries, server)
- Find hidden directories (use `directory_bruteforce`)
- Enumerate subdomains if applicable (use `subdomain_enum`)
- Check for exposed files (.git, .env, robots.txt, sitemap.xml)
- Look for API endpoints (REST, GraphQL via `graphql_introspection_test`)

## Phase 2: Vulnerability Assessment (60-70% of effort)
Test systematically for OWASP Top 10 (2021):

### A01: Broken Access Control
- IDOR: `idor_test` - try sequential IDs, UUIDs, admin IDs
- Auth bypass: `auth_bypass_test` - X-Forwarded-For, X-Original-URL
- Privilege escalation: try admin actions as regular user
- Path traversal: `path_traversal_test` for LFI

### A02: Cryptographic Failures
- JWT: `jwt_analyze` then `jwt_crack` if vulnerable
- Weak secrets in JS files (search for hardcoded keys)
- Sensitive data in URLs/responses

### A03: Injection
- SQLi: `sql_injection_test` - try error-based, blind, time-based
- Command injection: `command_injection_test` on any input
- SSTI: `ssti_test` on parameters that reflect (Jinja2, Twig, etc.)
- NoSQL injection: try `{"$gt": ""}` in JSON params
- LDAP injection: `*` and `)(|(uid=*))` in login fields
- XXE: `xxe_test` on XML endpoints

### A04: Insecure Design
- Business logic flaws (race conditions, state machine bypass)
- Workflow bypass (skip steps in multi-step processes)
- Price manipulation in e-commerce

### A05: Security Misconfiguration
- CORS: `cors_test` - check if credentials allowed from evil origins
- Default credentials (admin/admin, root/root)
- Verbose error messages
- Exposed admin panels (/admin, /actuator, /api-docs)

### A06: Vulnerable Components
- Check for outdated libraries (in HTML, response headers)
- Known CVEs in detected frameworks
- Use `run_nuclei_template` with CVE templates

### A07: Authentication Failures
- Weak password policy (try common passwords)
- Session fixation
- Missing rate limiting (test 100 login attempts)
- 2FA bypass

### A08: Software & Data Integrity Failures
- Deserialization: `deserialization_test`
- Unsigned updates
- Insecure CI/CD

### A09: Security Logging Failures
- (Informational - hard to test remotely)

### A10: SSRF
- `ssrf_test` on any URL parameter
- Test cloud metadata endpoints (AWS, GCP, Azure)
- Internal port scanning via SSRF

## Phase 3: Advanced Attacks (10-15% of effort)
- **File Upload**: `file_upload_test` - try web shells
- **Open Redirect**: `open_redirect_test`
- **HTTP Request Smuggling**: CL.TE, TE.CL on different content-lengths
- **Race Conditions**: Use `execute_python_code` for parallel requests
- **WebSocket** issues
- **Cache Poisoning**: Modify X-Forwarded-Host
- **Prototype Pollution** (for JS apps)

# Custom Exploit Development
When standard tools fail, write Python code:
- Use `execute_python_code` with requests library
- Chain vulnerabilities (e.g., SQLi → file write → RCE)
- Test edge cases and unusual encodings
- Bypass WAFs (case variation, encoding, comments)

# Reporting Standards
Use EXACTLY this format for each finding:

```
FINDING: [SEVERITY] Brief Title - Detailed description of the vulnerability

DETAILS:
- Endpoint: <URL>
- Parameter: <param>
- Payload: <exact payload>
- Evidence: <proof>
- Impact: <what attacker gains>
- CVSS: <score 0-10>
- CWE: CWE-XXX
- Reproduction:
  1. Step one
  2. Step two
  3. Confirm vuln
```

# Severity Guidelines
- **CRITICAL** (9.0-10.0): RCE, SQLi with data exfiltration, full auth bypass
- **HIGH** (7.0-8.9): Stored XSS on admin, SSRF to metadata, IDOR on PII
- **MEDIUM** (4.0-6.9): Reflected XSS, info disclosure, weak crypto
- **LOW** (0.1-3.9): Missing security headers, verbose errors
- **INFO** (0.0): Best practice violations

# Critical Rules
1. VERIFY before reporting - run exploits twice
2. Be CREATIVE - if obvious tests fail, try variations and bypasses
3. Be EFFICIENT - don't waste iterations on dead ends
4. Focus on HIGH-IMPACT vulnerabilities
5. Chain bugs for maximum impact when possible
6. Document EVERYTHING for reproduction

You have authorization. Begin your audit now with reconnaissance.
"""


class AIAuditor:
    """Autonomous AI-driven penetration testing auditor"""

    def __init__(
        self,
        llm_provider: LLMProvider,
        target_url: str,
        max_iterations: int = 50,
        log_callback: Optional[Callable[[str, str], None]] = None,
    ):
        self.llm = llm_provider
        self.target_url = target_url
        self.max_iterations = max_iterations
        self.log_callback = log_callback or (lambda level, msg: logger.info(msg))

        self.tools = PentestTools(target_url)
        self.advanced_tools = AdvancedPentestTools(target_url)
        self.tool_definitions = get_available_tools() + get_advanced_tools()

        self.conversation_history: List[Dict[str, str]] = []
        self.findings: List[Dict[str, Any]] = []
        self.tested_vectors: List[str] = []

    def log(self, level: str, message: str):
        """Log a message"""
        self.log_callback(level, message)
        logger.log(getattr(logging, level.upper()), message)

    def run_audit(self) -> Dict[str, Any]:
        """
        Run the full autonomous audit.

        Returns:
            {
                "status": "completed" | "error",
                "findings": [{title, severity, description, evidence, cvss, cwe}],
                "statistics": {iterations, tools_used, time_elapsed},
                "error": str | None
            }
        """
        self.log("INFO", f"Starting AI-driven audit of {self.target_url}")

        start_time = datetime.now()
        iterations = 0
        tools_used = {}

        try:
            # Initialize conversation
            self.conversation_history.append({
                "role": "system",
                "content": PENTESTER_SYSTEM_PROMPT
            })

            self.conversation_history.append({
                "role": "user",
                "content": f"""Target for security assessment: {self.target_url}

Perform a comprehensive security audit. Start by reconnaissance, then systematically test for vulnerabilities.

Important:
- Use the tools available to you via function calling
- When you find a vulnerability, document it clearly
- Be thorough but efficient
- Create working PoCs for critical findings
- Report findings in this format: FINDING: [severity] [title] - [description]

Begin your audit now."""
            })

            # Main audit loop
            while iterations < self.max_iterations:
                iterations += 1
                self.log("INFO", f"Iteration {iterations}/{self.max_iterations}")

                # Get LLM response
                response = self.llm.chat(
                    messages=self.conversation_history,
                    tools=self.tool_definitions,
                    temperature=0.7,
                    max_tokens=4096,
                )

                # Log LLM thinking
                if response["content"]:
                    self.log("INFO", f"AI: {response['content'][:500]}")
                    self.conversation_history.append({
                        "role": "assistant",
                        "content": response["content"]
                    })

                    # Parse findings from content
                    self._parse_findings_from_content(response["content"])

                # Execute tool calls
                if response.get("tool_calls"):
                    tool_results = []

                    for tool_call in response["tool_calls"]:
                        tool_name = tool_call["name"]
                        tool_args = tool_call["arguments"]

                        self.log("INFO", f"Executing: {tool_name}({json.dumps(tool_args)[:100]})")

                        # Track tool usage
                        tools_used[tool_name] = tools_used.get(tool_name, 0) + 1

                        # Execute tool
                        result = self._execute_tool(tool_name, tool_args)
                        tool_results.append({
                            "tool": tool_name,
                            "result": result
                        })

                        self.log("INFO", f"Result: {json.dumps(result)[:200]}")

                    # Add tool results to conversation
                    self.conversation_history.append({
                        "role": "user",
                        "content": f"Tool results:\n{json.dumps(tool_results, indent=2)}"
                    })

                # Check if audit is complete
                if response["finish_reason"] == "stop" and not response.get("tool_calls"):
                    content_lower = response["content"].lower()
                    if any(word in content_lower for word in ["audit complete", "finished", "done", "no more"]):
                        self.log("INFO", "AI signaled completion")
                        break

            elapsed = (datetime.now() - start_time).total_seconds()

            self.log("INFO", f"Audit completed: {len(self.findings)} findings in {iterations} iterations")

            return {
                "status": "completed",
                "findings": self.findings,
                "statistics": {
                    "iterations": iterations,
                    "tools_used": tools_used,
                    "time_elapsed_seconds": round(elapsed, 2),
                    "findings_count": len(self.findings),
                },
                "error": None,
            }

        except Exception as e:
            self.log("ERROR", f"Audit failed: {e}")
            logger.exception("Audit error")

            return {
                "status": "error",
                "findings": self.findings,
                "statistics": {
                    "iterations": iterations,
                    "tools_used": tools_used,
                },
                "error": str(e),
            }

    def _execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool and return the result"""
        try:
            # Map tool names to methods (basic + advanced)
            tool_map = {
                # Basic
                "http_request": self.tools.http_request,
                "extract_links": self.tools.extract_links,
                "sql_injection_test": self.tools.sql_injection_test,
                "xss_test": self.tools.xss_test,
                "directory_bruteforce": self.tools.directory_bruteforce,
                "execute_python_code": self.tools.execute_python_code,
                "run_nuclei_template": self.tools.run_nuclei_template,
                # Advanced
                "ssrf_test": self.advanced_tools.ssrf_test,
                "xxe_test": self.advanced_tools.xxe_test,
                "jwt_analyze": self.advanced_tools.jwt_analyze,
                "jwt_crack": self.advanced_tools.jwt_crack,
                "idor_test": self.advanced_tools.idor_test,
                "ssti_test": self.advanced_tools.ssti_test,
                "command_injection_test": self.advanced_tools.command_injection_test,
                "open_redirect_test": self.advanced_tools.open_redirect_test,
                "cors_test": self.advanced_tools.cors_test,
                "file_upload_test": self.advanced_tools.file_upload_test,
                "auth_bypass_test": self.advanced_tools.auth_bypass_test,
                "path_traversal_test": self.advanced_tools.path_traversal_test,
                "graphql_introspection_test": self.advanced_tools.graphql_introspection_test,
                "subdomain_enum": self.advanced_tools.subdomain_enum,
                "deserialization_test": self.advanced_tools.deserialization_test,
            }

            if tool_name not in tool_map:
                return {"error": f"Unknown tool: {tool_name}"}

            tool_func = tool_map[tool_name]
            result = tool_func(**arguments)

            # Track tested vectors
            vector_key = f"{tool_name}:{json.dumps(arguments, sort_keys=True)}"
            self.tested_vectors.append(vector_key)

            return result

        except Exception as e:
            logger.error(f"Tool execution error: {e}", exc_info=True)
            return {"error": str(e)}

    def _parse_findings_from_content(self, content: str):
        """Parse findings from LLM's text output"""
        import re

        finding_pattern = r'FINDING:\s*\[([^\]]+)\]\s*(.+?)\s*-\s*(.+?)(?=\n|$)'
        matches = re.finditer(finding_pattern, content, re.MULTILINE | re.IGNORECASE)

        for match in matches:
            severity = match.group(1).strip().upper()
            title = match.group(2).strip()
            description = match.group(3).strip()

            # Validate severity
            if severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                severity = "MEDIUM"

            finding = {
                "title": title,
                "severity": severity.lower(),
                "description": description,
                "evidence": self._extract_evidence_from_context(content, title),
                "cvss_score": self._estimate_cvss(severity),
                "cwe_id": None,
                "discovered_at": datetime.now().isoformat(),
            }

            # Avoid duplicates
            if not any(f["title"] == title for f in self.findings):
                self.findings.append(finding)
                self.log("INFO", f"NEW FINDING: [{severity}] {title}")

    def _extract_evidence_from_context(self, content: str, title: str) -> str:
        """Extract evidence related to a finding"""
        lines = content.split('\n')
        evidence_lines = []

        for i, line in enumerate(lines):
            if title.lower() in line.lower():
                start = max(0, i - 3)
                end = min(len(lines), i + 4)
                evidence_lines = lines[start:end]
                break

        return '\n'.join(evidence_lines)

    def _estimate_cvss(self, severity: str) -> float:
        """Estimate CVSS score from severity"""
        cvss_map = {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MEDIUM": 5.5,
            "LOW": 3.5,
            "INFO": 0.0,
        }
        return cvss_map.get(severity, 5.0)
