"""
Multi-Agent Pentest System

Specialized AI agents that collaborate on security audits:
- ReconAgent: Reconnaissance and information gathering
- ExploitAgent: Vulnerability exploitation and PoC creation
- AnalysisAgent: Result analysis and prioritization
- ReportAgent: Final report generation
- OrchestratorAgent: Coordinates all agents

Each agent can use a different LLM (specialized for its task) via LLMOrchestrator.
"""
from __future__ import annotations
import logging
import json
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, field

from services.llm_orchestrator import LLMOrchestrator, LLMRole
from services.pentest_tools import PentestTools, get_available_tools
from services.pentest_tools_advanced import AdvancedPentestTools, get_advanced_tools
from services.postman_parser import PostmanParser

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# IMPROVED PROMPTS
# ═══════════════════════════════════════════════════════════════

RECON_AGENT_PROMPT = """You are an expert reconnaissance specialist for offensive security.

# Your Mission
Map the entire attack surface of the target application BEFORE any exploitation begins.

# Methodology (OWASP-aligned)
1. **Information Gathering**
   - Crawl the application thoroughly
   - Identify all endpoints, forms, parameters
   - Map technology stack (frameworks, languages, servers)
   - Find hidden directories and files
   - Discover subdomains
   - Enumerate API endpoints (REST, GraphQL, WebSocket)

2. **Asset Discovery**
   - Static files (JS, CSS, images that reveal info)
   - Robots.txt, sitemap.xml, .git, .env exposures
   - Backup files (.bak, .old, .swp)
   - Admin panels, debug endpoints
   - Cloud assets (S3 buckets in JS code)

3. **Technology Fingerprinting**
   - Server software and version
   - Frameworks (React, Angular, Vue, Django, Rails)
   - CMS (WordPress, Drupal, Joomla)
   - JavaScript libraries with known CVEs
   - Authentication mechanisms (JWT, sessions, OAuth)

# Output Format
Report findings as structured JSON when possible:
```
RECON_RESULT:
{
  "endpoints": ["/api/users", "/admin", ...],
  "technologies": ["nginx/1.18", "Django 3.2", ...],
  "interesting_files": ["/.git/config", "/admin.bak"],
  "subdomains": [...],
  "potential_vulns": [
    {"type": "exposed_git", "url": "...", "severity": "HIGH"}
  ]
}
```

# Important
- Be THOROUGH but not noisy
- Use tools strategically - don't waste requests
- Note ANY anomaly, even if not obviously exploitable
- The exploit agent depends on YOUR findings - give them detailed targets
"""


EXPLOIT_AGENT_PROMPT = """You are an elite exploitation specialist for offensive security testing.

# Your Mission
Take the reconnaissance findings and systematically attempt exploitation of identified vulnerabilities.

# Attack Methodology
For each target endpoint/feature, test for:

## OWASP Top 10 (2021)
1. **A01 Broken Access Control**: IDOR, auth bypass, privilege escalation
2. **A02 Cryptographic Failures**: Weak crypto, exposed secrets, JWT issues
3. **A03 Injection**: SQLi, NoSQLi, command injection, LDAP injection
4. **A04 Insecure Design**: Business logic flaws
5. **A05 Security Misconfiguration**: Default creds, verbose errors, CORS
6. **A06 Vulnerable Components**: Outdated libraries with CVEs
7. **A07 Authentication Failures**: Weak passwords, session issues, JWT
8. **A08 Software/Data Integrity**: Insecure deserialization, supply chain
9. **A09 Logging Failures**: Insufficient logging (informational)
10. **A10 SSRF**: Server-Side Request Forgery

## Advanced Attacks
- **Template Injection** (SSTI): Jinja2, Twig, Freemarker
- **XXE**: XML External Entity
- **Race Conditions**: TOCTOU bugs
- **HTTP Request Smuggling**: CL.TE, TE.CL
- **WebSocket vulns**: CSWSH
- **GraphQL**: Introspection, batching attacks, depth attacks
- **Cache Poisoning**: Web cache deception
- **Prototype Pollution**: JavaScript apps
- **Subdomain Takeover**: Dangling DNS

# Exploitation Approach
1. Start with HIGHEST-IMPACT, EASIEST attacks first
2. Chain vulnerabilities when possible (e.g., SQLi → file write → RCE)
3. Create working PoCs - not just theoretical findings
4. Validate exploits twice to avoid false positives
5. Document EXACTLY how to reproduce

# Custom Exploits & Proactiveness (CRITICAL)
 When standard tools don't find it, write custom Python:
 - USE `execute_python_code` to write your own exploitation script.
 - Experiment with payload variations based on the response you see.
 - If you suspect a vulnerability but a tool says "not vulnerable", try to manually prove it using `http_request` and `execute_python_code`.
 - ACT like a real human pentester: hypothesize, test, analyze result, refine payload, repeat.

# Output Format
For each confirmed vulnerability:
```
FINDING: [CRITICAL|HIGH|MEDIUM|LOW|INFO] [Vulnerability Type] - [Brief Description]

DETAILS:
- Endpoint: <URL>
- Parameter: <param if any>
- Payload: <exact payload used>
- Evidence: <response excerpt or proof>
- Impact: <what attacker can do>
- CVSS: <estimated score>
- CWE: <CWE ID if known>
- Remediation: <how to fix it>
- Reproduction: <step-by-step>
```

# Critical Rules
- VERIFY before reporting (run exploit twice)
- Be creative - if obvious tests fail, try variations
- Think like a real attacker - what gives MAXIMUM impact?
- Don't be a script kiddie - understand WHY each exploit works
"""


ANALYSIS_AGENT_PROMPT = """You are a security analyst who reviews findings from pentesters.

# Your Mission
Analyze raw findings from the exploit agent, eliminate false positives, prioritize, and produce a curated list of REAL, EXPLOITABLE vulnerabilities.

# Analysis Criteria
For each finding, evaluate:

1. **Validity** (Is it real?)
   - Does the evidence actually prove the vulnerability?
   - Could this be a false positive?
   - Was it tested with proper context?

2. **Impact** (How bad is it?)
   - What can an attacker DO with this?
   - Data exposure? RCE? Lateral movement?
   - Affects single user or all users?

3. **Exploitability** (How easy?)
   - Authentication required?
   - User interaction needed?
   - Specific conditions required?

4. **CVSS Scoring**
   - Use CVSS 3.1 methodology
   - Consider: AV, AC, PR, UI, S, C, I, A

# Deduplication
- Multiple findings of same root cause = ONE finding
- Same vuln in multiple endpoints = group them

# Output Format
Produce a refined findings list:
```
VALIDATED_FINDINGS:
[
  {
    "title": "...",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "cwe_id": "CWE-89",
    "owasp_category": "A03:2021",
    "affected_endpoints": [...],
    "exploitability": "HIGH",
    "impact": "...",
    "recommendation": "..."
  }
]
```
"""


REPORT_AGENT_PROMPT = """You are a technical writer specializing in security reports.

# Your Mission
Transform validated findings into a professional penetration test report.

# Report Structure

## 1. Executive Summary
- High-level overview for management
- Risk rating (Critical/High/Medium/Low)
- Key statistics

## 2. Findings (Detailed)
For each vulnerability:
- **Title**: Clear, descriptive
- **Severity**: Critical/High/Medium/Low/Info
- **CVSS Score**: 0.0-10.0
- **Affected**: Endpoints/components
- **Description**: What the vulnerability is
- **Impact**: Real-world consequences
- **Proof of Concept**: Working exploit (sanitized)
- **Remediation**: How to fix it
- **References**: OWASP, CWE, CVE links

## 3. Recommendations
- Strategic security improvements
- Defense in depth measures
- Process improvements

# Writing Style
- Professional but clear
- No jargon without explanation
- Concrete examples
- Actionable remediation steps
- Business-focused impact descriptions
"""


# ═══════════════════════════════════════════════════════════════
# AGENT BASE CLASS
# ═══════════════════════════════════════════════════════════════

@dataclass
class AgentContext:
    """Shared context between agents"""
    target_url: str
    target_type: str = "web_app"
    scan_config: Dict[str, Any] = field(default_factory=dict)
    recon_results: Dict[str, Any] = field(default_factory=dict)
    raw_findings: List[Dict[str, Any]] = field(default_factory=list)
    validated_findings: List[Dict[str, Any]] = field(default_factory=list)
    report: Optional[str] = None
    statistics: Dict[str, Any] = field(default_factory=dict)
    logs: List[Dict[str, str]] = field(default_factory=list)


class BaseAgent:
    """Base class for all pentest agents"""

    def __init__(
        self,
        name: str,
        role: LLMRole,
        system_prompt: str,
        orchestrator: LLMOrchestrator,
        tools: PentestTools,
        advanced_tools: AdvancedPentestTools,
        log_callback: Optional[Callable] = None,
    ):
        self.name = name
        self.role = role
        self.system_prompt = system_prompt
        self.orchestrator = orchestrator
        self.tools = tools
        self.advanced_tools = advanced_tools
        self.log_callback = log_callback or (lambda l, m: logger.info(m))

        # Combine all tool definitions
        self.tool_definitions = get_available_tools() + get_advanced_tools()

    def log(self, level: str, message: str):
        prefix = f"[{self.name}]"
        self.log_callback(level, f"{prefix} {message}")

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool by name with verbose logging"""
        # Log to scan logger
        try:
            from services.scan_logger import ScanLogger
            sl = ScanLogger.get_current()
            if sl:
                sl.tool_call(self.name, tool_name, arguments)
        except Exception:
            pass
        # Map to both basic and advanced tools
        tool_map = {
            # Basic tools
            "http_request": self.tools.http_request,
            "extract_links": self.tools.extract_links,
            "sql_injection_test": self.tools.sql_injection_test,
            "xss_test": self.tools.xss_test,
            "directory_bruteforce": self.tools.directory_bruteforce,
            "execute_python_code": self.tools.execute_python_code,
            "run_nuclei_template": self.tools.run_nuclei_template,
            # Advanced tools
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
            err_result = {"error": f"Unknown tool: {tool_name}"}
            try:
                from services.scan_logger import ScanLogger
                sl = ScanLogger.get_current()
                if sl:
                    sl.tool_result(self.name, tool_name, err_result, error=f"Unknown tool: {tool_name}")
            except Exception:
                pass
            return err_result

        try:
            result = tool_map[tool_name](**arguments)
            # Log result
            try:
                from services.scan_logger import ScanLogger
                sl = ScanLogger.get_current()
                if sl:
                    if isinstance(result, dict) and result.get("error"):
                        sl.tool_result(self.name, tool_name, result, error=result.get("error"))
                    else:
                        sl.tool_result(self.name, tool_name, result)
            except Exception:
                pass
            return result
        except Exception as e:
            logger.error(f"Tool {tool_name} error: {e}", exc_info=True)
            err = {"error": str(e)}
            try:
                from services.scan_logger import ScanLogger
                sl = ScanLogger.get_current()
                if sl:
                    sl.tool_result(self.name, tool_name, err, error=str(e))
            except Exception:
                pass
            return err

    def run(self, task: str, context: AgentContext, max_iterations: int = 20) -> Dict[str, Any]:
        """Run the agent on a task"""
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": task},
        ]

        iterations = 0
        tools_used = {}

        while iterations < max_iterations:
            iterations += 1
            self.log("INFO", f"Iteration {iterations}/{max_iterations}")

            # Get response from orchestrator (with fallback)
            response = self.orchestrator.chat_with_fallback(
                messages=messages,
                tools=self.tool_definitions,
                role=self.role,
                temperature=0.7,
                max_tokens=4096,
            )

            if response.get("error"):
                self.log("ERROR", f"LLM error: {response['error']}")
                break

            llm_used = response.get("_llm_used", "unknown")
            self.log("INFO", f"Used LLM: {llm_used}")

            if response.get("content"):
                self.log("INFO", f"Thinking: {response['content'][:300]}")
                messages.append({
                    "role": "assistant",
                    "content": response["content"]
                })

            # Execute tools if needed
            if response.get("tool_calls"):
                tool_results = []
                for tc in response["tool_calls"]:
                    name = tc["name"]
                    args = tc["arguments"]

                    self.log("INFO", f"Tool: {name}({json.dumps(args)[:80]})")
                    tools_used[name] = tools_used.get(name, 0) + 1

                    result = self.execute_tool(name, args)
                    tool_results.append({"tool": name, "result": result})

                messages.append({
                    "role": "user",
                    "content": f"Tool results:\n{json.dumps(tool_results, indent=2)[:3000]}"
                })
            else:
                # No more tool calls, agent is done
                break

        return {
            "messages": messages,
            "iterations": iterations,
            "tools_used": tools_used,
        }


SAST_AGENT_PROMPT = """You are an expert static analysis security tester (SAST).
 
 # Your Mission
 Analyze the source code of the target repository to find vulnerabilities, hardcoded secrets, and insecure patterns.
 
 # Methodology
 1. **Pattern Matching**: Use Semgrep to find known vulnerability patterns.
 2. **Secret Scanning**: Use Trufflehog to find API keys, tokens, and passwords.
 3. **Dependency Analysis**: Audit package manifests (package.json, requirements.txt) for vulnerable libraries.
 4. **Manual Review**: Analyze critical paths (auth, data processing, API controllers) for logic flaws.
 
 # Output Format
 Report findings as a JSON array of VALIDATED_FINDINGS:
 [
   {
     "title": "...",
     "severity": "HIGH",
     "file_path": "...",
     "line": 123,
     "description": "...",
     "cwe_id": "CWE-...",
     "recommendation": "..."
   }
 ]
 """
 
 
class SastAgent(BaseAgent):
    """Static Analysis specialist"""

    def __init__(self, orchestrator, tools, advanced_tools, log_callback=None):
        super().__init__(
            name="SAST",
            role=LLMRole.ANALYSIS, # Reuse analysis role if not defined
            system_prompt=SAST_AGENT_PROMPT,
            orchestrator=orchestrator,
            tools=tools,
            advanced_tools=advanced_tools,
            log_callback=log_callback,
        )

    def perform_sast(self, context: AgentContext) -> Dict[str, Any]:
        """Perform static analysis on the repository"""
        self.log("INFO", "Starting static analysis of repository")
        
        repo_url = context.scan_config.get("repo_url") or context.scan_config.get("git_url")
        if not repo_url:
            self.log("WARN", "No repository URL provided for SAST")
            return {"status": "skipped", "findings": []}
        
        # In a real implementation, we would call the SAST tools here.
        # For now, we'll simulate it or call the logic from sast_tasks.
        # Since we are in a service, we can call the tool functions directly.
        
        task = f"""Analyze the repository at {repo_url} for security vulnerabilities.
 
 Use available tools to:
 1. Run Semgrep for common vulnerability patterns.
 2. Scan for hardcoded secrets.
 3. Audit dependencies.
 
 Provide a detailed list of findings with file paths and line numbers."""
        
        result = self.run(task, context, max_iterations=10)
        
        # Extract findings (simplified for now)
        # ... logic to extract findings from LLM response ...
        
        return result

class ReconAgent(BaseAgent):
    """Reconnaissance specialist"""

    def __init__(self, orchestrator, tools, advanced_tools, log_callback=None):
        super().__init__(
            name="RECON",
            role=LLMRole.RECON,
            system_prompt=RECON_AGENT_PROMPT,
            orchestrator=orchestrator,
            tools=tools,
            advanced_tools=advanced_tools,
            log_callback=log_callback,
        )

    def perform_recon(self, context: AgentContext) -> Dict[str, Any]:
        """Perform reconnaissance"""
        self.log("INFO", f"Starting reconnaissance on {context.target_url}")

        task = f"""Perform comprehensive reconnaissance on: {context.target_url}

Use available tools to:
1. Crawl the application and extract all links
2. Identify technologies in use
3. Find hidden directories/files (use directory_bruteforce)
4. Enumerate subdomains if applicable
5. Test for GraphQL introspection
6. Look for interesting files (.git, .env, backups)
7. Map all API endpoints

End your reconnaissance by providing a structured summary."""

        result = self.run(task, context, max_iterations=15)

        # Extract recon findings from messages
        for msg in result["messages"]:
            if msg["role"] == "assistant" and "RECON_RESULT" in msg.get("content", ""):
                try:
                    # Extract JSON after RECON_RESULT
                    content = msg["content"]
                    start = content.index("{", content.index("RECON_RESULT"))
                    # Find matching brace
                    json_str = self._extract_json(content[start:])
                    context.recon_results = json.loads(json_str)
                except Exception as e:
                    logger.debug(f"Could not parse RECON_RESULT: {e}")

        return result

    def _extract_json(self, text: str) -> str:
        """Extract first JSON object from text"""
        depth = 0
        start = -1
        for i, c in enumerate(text):
            if c == '{':
                if start == -1:
                    start = i
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0 and start != -1:
                    return text[start:i+1]
        return "{}"




class ExploitAgent(BaseAgent):
    """Exploitation specialist"""

    def __init__(self, orchestrator, tools, advanced_tools, log_callback=None):
        super().__init__(
            name="EXPLOIT",
            role=LLMRole.EXPLOIT,
            system_prompt=EXPLOIT_AGENT_PROMPT,
            orchestrator=orchestrator,
            tools=tools,
            advanced_tools=advanced_tools,
            log_callback=log_callback,
        )

    def exploit(self, context: AgentContext) -> Dict[str, Any]:
        """Attempt exploitation based on recon"""
        self.log("INFO", "Starting exploitation phase")

        recon_summary = json.dumps(context.recon_results, indent=2)[:2000]

        task = f"""Based on reconnaissance results, systematically test for vulnerabilities.

Target: {context.target_url}

Reconnaissance Summary:
{recon_summary}

Your mission:
1. Test each interesting endpoint for OWASP Top 10 vulnerabilities
2. Use the advanced tools (SSRF, XXE, SSTI, IDOR, JWT, etc.)
3. Chain vulnerabilities for maximum impact
4. Create working PoCs for each finding
5. Report findings using the FINDING: format

Be thorough but efficient. Focus on HIGH-IMPACT vulnerabilities first."""

        result = self.run(task, context, max_iterations=30)

        # Parse findings from all assistant messages
        for msg in result["messages"]:
            if msg["role"] == "assistant":
                self._parse_findings(msg.get("content", ""), context)

        return result

    def _parse_findings(self, content: str, context: AgentContext):
        """Extract findings from agent output"""
        import re

        # Split content into blocks starting with "FINDING:" (optionally wrapped in **)
        blocks = re.split(r'(?=\*?\*?FINDING:)', content)
        
        for block in blocks:
            block = block.strip()
            if not block or not block.startswith("FINDING:"):
                continue
            
            # Parse header: FINDING: [SEVERITY] TITLE - DESCRIPTION
            header_match = re.search(r'\*?\*?FINDING:\s*\[(?P<severity>CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(?P<title>.+?)\s*-\s*(?P<description>.+)', block)
            if not header_match:
                continue
                
            severity = header_match.group("severity").strip().upper()
            title = header_match.group("title").strip().replace("**", "").strip()
            description = header_match.group("description").strip().replace("**", "").strip()

            # Parse details from the rest of the block
            details = {}
            lines = block.split('\n')
            for line in lines[1:]:
                line = line.strip()
                if not line or line.lower().startswith("details:"):
                    continue
                
                if line.startswith("-"):
                    # Remove leading dash and space
                    line = line[1:].strip()
                    # Split by first colon
                    if ":" in line:
                        key_part, value_part = line.split(":", 1)
                        key = key_part.replace("*", "").strip().lower().replace(" ", "_")
                        value = value_part.replace("*", "").strip()
                        
                        # Map keys to schema
                        key_map = {
                            "endpoint": "endpoint",
                            "parameter": "parameter",
                            "payload": "payload",
                            "evidence": "evidence",
                            "impact": "impact",
                            "cvss": "cvss_score",
                            "cwe": "cwe_id",
                            "remediation": "remediation",
                            "reproduction": "reproduction_steps"
                        }
                        key = key_map.get(key, key)
                        
                        if key == "reproduction_steps":
                            details[key] = [step.strip() for step in value.split('\n') if step.strip()]
                        else:
                            details[key] = value

            # Check if not already in findings
            if not any(f["title"] == title for f in context.raw_findings):
                # Handle CVSS conversion
                cvss_val = None
                if "cvss_score" in details and isinstance(details["cvss_score"], str):
                    cvss_match = re.search(r"(\d+\.?\d*)", details["cvss_score"])
                    if cvss_match:
                        cvss_val = float(cvss_match.group(1))
                elif "cvss_score" in details and isinstance(details["cvss_score"], (int, float)):
                    cvss_val = float(details["cvss_score"])

                finding = {
                    "title": title,
                    "severity": severity.lower(),
                    "description": description,
                    "discovered_by": "exploit_agent",
                    "discovered_at": datetime.now().isoformat(),
                    "endpoint": details.get("endpoint"),
                    "parameter": details.get("parameter"),
                    "payload": details.get("payload"),
                    "evidence": details.get("evidence"),
                    "impact": details.get("impact"),
                    "cvss_score": cvss_val,
                    "cwe_id": details.get("cwe_id"),
                    "remediation": details.get("remediation"),
                    "reproduction_steps": details.get("reproduction_steps", []),
                }
                context.raw_findings.append(finding)
                self.log("INFO", f"FOUND: [{severity}] {title}")
                
                try:
                    from services.scan_logger import ScanLogger
                    sl = ScanLogger.get_current()
                    if sl:
                        sl.finding(self.name, severity.lower(), title, description)
                except Exception:
                    pass

        return {"validated_count": len(context.validated_findings)}

    def _extract_json_array(self, text: str) -> str:
        """Extract first JSON array from text"""
        depth = 0
        start = -1
        for i, c in enumerate(text):
            if c == '[':
                if start == -1:
                    start = i
                depth += 1
            elif c == ']':
                depth -= 1
                if depth == 0 and start != -1:
                    return text[start:i+1]
        return "[]"


class ReportAgent(BaseAgent):
    """Report generation specialist"""

    def __init__(self, orchestrator, tools, advanced_tools, log_callback=None):
        super().__init__(
            name="REPORT",
            role=LLMRole.REPORTING,
            system_prompt=REPORT_AGENT_PROMPT,
            orchestrator=orchestrator,
            tools=tools,
            advanced_tools=advanced_tools,
            log_callback=log_callback,
        )

    def generate_report(self, context: AgentContext) -> str:
        """Generate the final report"""
        self.log("INFO", "Generating final report")

        findings_text = json.dumps(context.validated_findings, indent=2)[:8000]

        task = f"""Generate a professional penetration test report for: {context.target_url}

Validated Findings:
{findings_text}

Reconnaissance Summary:
{json.dumps(context.recon_results, indent=2)[:1500]}

Statistics:
{json.dumps(context.statistics, indent=2)}

Produce a markdown report with:
- Executive Summary
- Detailed Findings (for each vuln: description, impact, PoC, remediation)
- Strategic Recommendations
- Appendix

Make it professional, actionable, and complete."""

        # Don't use tools for reporting
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": task},
        ]

        response = self.orchestrator.chat_with_fallback(
            messages=messages,
            tools=None,  # No tools needed
            role=self.role,
            temperature=0.5,
            max_tokens=8192,
        )

        report = response.get("content", "Report generation failed")
        context.report = report

        return report


# ═══════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════

class MultiAgentOrchestrator:
    """Coordinates all agents through the full pentest workflow"""

    def __init__(
        self,
        target_url: str,
        target_type: str = "web_app",
        scan_config: Dict[str, Any] = None,
        llm_orchestrator: LLMOrchestrator = None,
        log_callback: Optional[Callable] = None,
    ):
        self.target_url = target_url
        self.target_type = target_type
        self.scan_config = scan_config or {}
        self.llm_orchestrator = llm_orchestrator
        self.log_callback = log_callback or (lambda l, m: logger.info(m))
 
        # Initialize shared tools
        self.tools = PentestTools(target_url)
        self.advanced_tools = AdvancedPentestTools(target_url)
 
        # Initialize agents
        self.sast_agent = SastAgent(llm_orchestrator, self.tools, self.advanced_tools, log_callback)
        self.recon_agent = ReconAgent(llm_orchestrator, self.tools, self.advanced_tools, log_callback)
        self.exploit_agent = ExploitAgent(llm_orchestrator, self.tools, self.advanced_tools, log_callback)
        self.analysis_agent = AnalysisAgent(llm_orchestrator, self.tools, self.advanced_tools, log_callback)
        self.report_agent = ReportAgent(llm_orchestrator, self.tools, self.advanced_tools, log_callback)

    def log(self, level: str, message: str):
        self.log_callback(level, f"[ORCHESTRATOR] {message}")

    def run_full_audit(self) -> Dict[str, Any]:
        """Run the complete multi-agent pentest based on target type"""
        start_time = datetime.now()
        context = AgentContext(
            target_url=self.target_url, 
            target_type=self.target_type, 
            scan_config=self.scan_config
        )
 
        self.log("INFO", "=" * 60)
        self.log("INFO", f"Starting Multi-Agent Pentest on {self.target_url} (Type: {self.target_type})")
        self.log("INFO", "=" * 60)
        self.log("INFO", f"LLM Status: {json.dumps(self.llm_orchestrator.get_status())}")
 
        # Handle Postman Collection if provided in config
        postman_coll = self.scan_config.get("postman_collection")
        if postman_coll:
            self.log("INFO", "Parsing provided Postman collection...")
            endpoints = PostmanParser.parse_collection(postman_coll)
            context.recon_results["postman_endpoints"] = endpoints
            self.log("INFO", f"Extracted {len(endpoints)} endpoints from Postman collection")
 
        # Verify at least one LLM is available
        llm_status = self.llm_orchestrator.get_status()
        if llm_status["active"] == 0:
            return {
                "status": "error",
                "error": "No LLMs available - check API keys (GEMINI_API_KEY, OPENAI_API_KEY, etc.)",
                "findings": [],
                "raw_findings": [],
                "statistics": {"total_time_seconds": 0},
            }
 
        try:
            # WHITE-BOX FLOW (for repositories)
            if self.target_type == "repository":
                self.log("INFO", "Applying WHITE-BOX workflow for repository target")
                
                # Phase 1: SAST
                self.log("INFO", "Phase 1/5: Static Analysis (SAST)")
                sast_result = self.sast_agent.perform_sast(context)
                context.statistics["sast"] = {
                    "iterations": sast_result.get("iterations", 0),
                    "tools_used": sast_result.get("tools_used", {}),
                }
                
                # Phase 2: Recon
                self.log("INFO", "Phase 2/5: Reconnaissance")
                recon_result = self.recon_agent.perform_recon(context)
                context.statistics["recon"] = {
                    "iterations": recon_result["iterations"],
                    "tools_used": recon_result["tools_used"],
                }
                
                # Phase 3: Exploitation (guided by SAST + Recon)
                self.log("INFO", "Phase 3/5: Exploitation (Guided by SAST)")
                exploit_result = self.exploit_agent.exploit(context)
                context.statistics["exploit"] = {
                    "iterations": exploit_result["iterations"],
                    "tools_used": exploit_result["tools_used"],
                    "raw_findings": len(context.raw_findings),
                }
                
            # BLACK-BOX FLOW (for web apps, APIs)
            else:
                # Phase 1: Reconnaissance
                self.log("INFO", "Phase 1/4: Reconnaissance")
                recon_result = self.recon_agent.perform_recon(context)
                context.statistics["recon"] = {
                    "iterations": recon_result["iterations"],
                    "tools_used": recon_result["tools_used"],
                }
                
                # Check if recon worked
                recon_did_anything = (
                    recon_result["iterations"] > 0
                    and len(recon_result.get("tools_used", {})) > 0
                )
                if not recon_did_anything:
                    final_status = self.llm_orchestrator.get_status()
                    if final_status["active"] == 0:
                        return {
                            "status": "error",
                            "error": f"All LLMs failed during reconnaissance. Disabled: {final_status['disabled']}",
                            "findings": [],
                            "raw_findings": [],
                            "statistics": context.statistics,
                        }
                
                # Phase 2: Exploitation
                self.log("INFO", "Phase 2/4: Exploitation")
                exploit_result = self.exploit_agent.exploit(context)
                context.statistics["exploit"] = {
                    "iterations": exploit_result["iterations"],
                    "tools_used": exploit_result["tools_used"],
                    "raw_findings": len(context.raw_findings),
                }
 
            # Phase 3/4: Analysis
            self.log("INFO", "Phase Analysis: Analysis & Validation")
            analysis_result = self.analysis_agent.analyze(context)
            context.statistics["analysis"] = analysis_result
 
            # Phase 4/5: Reporting
            self.log("INFO", "Phase Reporting: Report Generation")
            report = self.report_agent.generate_report(context)
            context.statistics["report_length"] = len(report)
 
            elapsed = (datetime.now() - start_time).total_seconds()
            context.statistics["total_time_seconds"] = round(elapsed, 2)
 
            self.log("INFO", "=" * 60)
            self.log("INFO", f"Multi-Agent Pentest Completed in {elapsed:.1f}s")
            self.log("INFO", f"Findings: {len(context.validated_findings)}")
            self.log("INFO", "=" * 60)
 
            return {
                "status": "completed",
                "findings": context.validated_findings,
                "raw_findings": context.raw_findings,
                "recon_results": context.recon_results,
                "report": context.report,
                "statistics": context.statistics,
                "llm_status": self.llm_orchestrator.get_status(),
            }
 
        except Exception as e:
            self.log("ERROR", f"Pentest failed: {e}")
            logger.exception("Multi-agent pentest error")
            return {
                "status": "error",
                "error": str(e),
                "findings": context.validated_findings,
                "raw_findings": context.raw_findings,
                "statistics": context.statistics,
            }
