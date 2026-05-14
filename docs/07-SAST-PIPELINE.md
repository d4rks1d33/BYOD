# AutoPentest — SAST Pipeline Design

## Pipeline Overview

```
Source Input (Git URL / Local Path)
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  SAST Worker (queue.sast)                            │
│                                                      │
│  1. Clone / Mount repo                              │
│  2. Detect languages + frameworks                   │
│  3. Install dependencies (for build analysis)       │
│     │                                               │
│     ├──► Semgrep (code pattern matching)           │
│     ├──► CodeQL (semantic code analysis)           │
│     ├──► trufflehog (secret detection)             │
│     ├──► Dependency audit (npm audit / pip-audit)  │
│     ├──► IaC scanner (Dockerfile, K8s, Terraform)  │
│     ├──► CI/CD scanner (GitHub Actions, GitLab CI) │
│     └──► AI Code Review Agent (contextual LLM)     │
│                           │                         │
│  5. Normalize all outputs │                         │
│  6. Store findings         │                         │
│  7. Emit checkpoint → DAST bridge                   │
└─────────────────────────────────────────────────────┘
```

---

## Repository Manager

```python
# backend/engines/sast/repo_manager.py
import subprocess
import os
import tempfile
from pathlib import Path

class RepoManager:
    """
    Handles cloning, mounting, and preparing repositories for SAST analysis.
    All operations run inside a Docker sandbox with no network access post-clone.
    """

    async def prepare(self, config: dict, working_dir: str) -> str:
        """
        Returns path to prepared repository on disk.
        config contains: repo_url, branch, ssh_key (encrypted), local_path
        """
        if config.get("local_path"):
            return config["local_path"]  # Already on disk

        # Clone from remote
        repo_path = os.path.join(working_dir, "repo")
        os.makedirs(repo_path, exist_ok=True)

        # Prepare git credentials
        env = os.environ.copy()
        if config.get("ssh_key_dec"):
            key_file = os.path.join(working_dir, "deploy_key")
            with open(key_file, "w") as f:
                f.write(config["ssh_key_dec"])
            os.chmod(key_file, 0o600)
            env["GIT_SSH_COMMAND"] = f"ssh -i {key_file} -o StrictHostKeyChecking=no"
        elif config.get("github_token"):
            # Inject token into URL
            url = config["repo_url"]
            token = config["github_token"]
            # Replace https://github.com/ with https://token@github.com/
            url = url.replace("https://", f"https://{token}@")
            config = {**config, "repo_url": url}

        cmd = [
            "git", "clone",
            "--depth", "1",             # Shallow clone for speed
            "--branch", config.get("branch", "main"),
            config["repo_url"],
            repo_path
        ]

        result = subprocess.run(
            cmd, capture_output=True, text=True, env=env, timeout=300
        )
        if result.returncode != 0:
            raise RuntimeError(f"Clone failed: {result.stderr}")

        return repo_path

    async def detect_languages(self, repo_path: str) -> dict:
        """
        Detect languages and frameworks using file extension analysis + config file detection.
        Returns: {language: file_count, frameworks: [...], build_tool: str}
        """
        lang_extensions = {
            "javascript": [".js", ".jsx", ".mjs", ".cjs"],
            "typescript": [".ts", ".tsx"],
            "python": [".py"],
            "java": [".java"],
            "go": [".go"],
            "rust": [".rs"],
            "php": [".php"],
            "csharp": [".cs"],
            "kotlin": [".kt"],
            "ruby": [".rb"],
        }
        framework_indicators = {
            "next.js": ["next.config.js", "next.config.ts"],
            "react": ["package.json:react"],
            "vue": ["package.json:vue"],
            "angular": ["angular.json"],
            "express": ["package.json:express"],
            "nestjs": ["package.json:@nestjs/core"],
            "django": ["manage.py", "settings.py"],
            "flask": ["requirements.txt:flask"],
            "fastapi": ["requirements.txt:fastapi"],
            "spring": ["pom.xml", "build.gradle"],
            "laravel": ["artisan", "composer.json:laravel/framework"],
        }

        counts = {lang: 0 for lang in lang_extensions}
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "dist")]
            for f in files:
                ext = Path(f).suffix.lower()
                for lang, exts in lang_extensions.items():
                    if ext in exts:
                        counts[lang] += 1

        # Detect frameworks
        detected_frameworks = []
        for framework, indicators in framework_indicators.items():
            for indicator in indicators:
                if ":" in indicator:
                    file, package = indicator.split(":", 1)
                    file_path = os.path.join(repo_path, file)
                    if os.path.exists(file_path):
                        content = open(file_path).read()
                        if package in content:
                            detected_frameworks.append(framework)
                            break
                else:
                    if os.path.exists(os.path.join(repo_path, indicator)):
                        detected_frameworks.append(framework)
                        break

        primary_lang = max(counts, key=counts.get) if any(counts.values()) else "unknown"

        return {
            "primary_language": primary_lang,
            "all_languages": {k: v for k, v in counts.items() if v > 0},
            "frameworks": detected_frameworks,
            "build_tool": self._detect_build_tool(repo_path),
        }

    def _detect_build_tool(self, repo_path: str) -> str:
        BUILD_FILES = {
            "package.json": "npm",
            "yarn.lock": "yarn",
            "pnpm-lock.yaml": "pnpm",
            "requirements.txt": "pip",
            "Pipfile": "pipenv",
            "pyproject.toml": "poetry/uv",
            "pom.xml": "maven",
            "build.gradle": "gradle",
            "Cargo.toml": "cargo",
            "go.mod": "go_modules",
            "composer.json": "composer",
        }
        for filename, tool in BUILD_FILES.items():
            if os.path.exists(os.path.join(repo_path, filename)):
                return tool
        return "unknown"
```

---

## Semgrep Integration

```python
# backend/integrations/semgrep.py
import subprocess, json

class SemgrepRunner:
    """
    Runs Semgrep with curated security rulesets.
    All rulesets are bundled locally (no registry calls in air-gapped mode).
    """

    RULESET_MAP = {
        "javascript": [
            "p/javascript",
            "p/nodejs",
            "p/express",
            "p/react",
            "p/secrets",
        ],
        "typescript": ["p/typescript", "p/react", "p/nodejs"],
        "python": ["p/python", "p/django", "p/flask", "p/fastapi"],
        "java": ["p/java", "p/spring"],
        "go": ["p/golang"],
        "php": ["p/php"],
        "ruby": ["p/ruby"],
    }

    def __init__(self, rules_dir: str = "/opt/semgrep-rules"):
        self.rules_dir = rules_dir

    async def run(self, repo_path: str, languages: list[str]) -> list[dict]:
        """Returns normalized list of findings."""
        rules = self._select_rules(languages)

        cmd = [
            "semgrep", "scan",
            "--json",
            "--no-rewrite-rule-ids",
            "--timeout", "300",
            "--max-memory", "2048",  # MB
        ]
        for rule in rules:
            rule_path = os.path.join(self.rules_dir, rule.replace("/", "_") + ".yaml")
            if os.path.exists(rule_path):
                cmd += ["--config", rule_path]

        cmd.append(repo_path)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=360)
        if result.returncode not in (0, 1):  # 1 = findings found (normal)
            raise RuntimeError(f"Semgrep failed: {result.stderr[:500]}")

        output = json.loads(result.stdout)
        return [self._normalize(r) for r in output.get("results", [])]

    def _normalize(self, raw: dict) -> dict:
        return {
            "tool": "semgrep",
            "rule_id": raw["check_id"],
            "finding_type": self._classify_rule(raw["check_id"]),
            "severity": self._map_severity(raw["extra"].get("severity", "WARNING")),
            "message": raw["extra"].get("message", ""),
            "source_file": raw["path"],
            "source_line": raw["start"]["line"],
            "source_end_line": raw["end"]["line"],
            "source_code": raw["extra"].get("lines", ""),
            "cwe_id": self._extract_cwe(raw),
            "fix": raw["extra"].get("fix", ""),
            "metadata": raw["extra"].get("metadata", {}),
        }

    def _map_severity(self, semgrep_sev: str) -> str:
        return {
            "ERROR": "high",
            "WARNING": "medium",
            "INFO": "low",
            "INVENTORY": "info",
        }.get(semgrep_sev.upper(), "medium")

    def _extract_cwe(self, raw: dict) -> Optional[str]:
        metadata = raw.get("extra", {}).get("metadata", {})
        cwe = metadata.get("cwe", "")
        if isinstance(cwe, list):
            return cwe[0] if cwe else None
        return cwe or None

    def _classify_rule(self, rule_id: str) -> str:
        lower = rule_id.lower()
        for vuln_type in ["sqli", "sql", "xss", "ssrf", "rce", "exec",
                          "path-traversal", "secret", "crypto", "auth"]:
            if vuln_type in lower:
                return vuln_type.replace("-", "_")
        return "code_quality"
```

---

## Secret Scanner (trufflehog)

```python
# backend/integrations/trufflehog.py
import subprocess, json

class TrufflehogRunner:
    async def scan_repo(self, repo_path: str) -> list[dict]:
        """
        Scan for secrets using trufflehog v3's regex + entropy detection.
        Returns normalized finding list.
        """
        cmd = [
            "trufflehog",
            "filesystem",
            "--json",
            "--no-update",          # No version check in air-gapped mode
            "--exclude-paths", ".trufflehog_ignore",
            repo_path
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        findings = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                raw = json.loads(line)
                if raw.get("SourceMetadata"):
                    findings.append(self._normalize(raw))
            except json.JSONDecodeError:
                pass

        return findings

    def _normalize(self, raw: dict) -> dict:
        src = raw.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        return {
            "tool": "trufflehog",
            "finding_type": "secret",
            "severity": "critical",  # All confirmed secrets are critical
            "detector_name": raw.get("DetectorName", "unknown"),
            "verified": raw.get("Verified", False),
            "raw_secret": "[REDACTED]",      # Never store raw secret
            "secret_type": raw.get("DetectorType", ""),
            "source_file": src.get("file", ""),
            "source_line": src.get("line", 0),
            "cwe_id": "CWE-798",
            "message": f"Hardcoded secret detected: {raw.get('DetectorName')}",
        }
```

---

## Dependency Vulnerability Analysis

```python
# backend/engines/sast/dep_audit.py
class DependencyAuditor:
    """
    Checks installed dependencies against vulnerability databases.
    Uses bundled CVE data for air-gapped operation.
    """

    async def audit(self, repo_path: str, build_tool: str) -> list[dict]:
        auditors = {
            "npm": self._npm_audit,
            "yarn": self._yarn_audit,
            "pip": self._pip_audit,
            "poetry/uv": self._pip_audit,
            "pipenv": self._pip_audit,
        }
        auditor = auditors.get(build_tool)
        if not auditor:
            return []
        return await auditor(repo_path)

    async def _npm_audit(self, repo_path: str) -> list[dict]:
        # Install dependencies first (sandbox only, no outbound net for scan)
        subprocess.run(["npm", "install", "--ignore-scripts", "--no-fund"],
                       cwd=repo_path, capture_output=True, timeout=300)

        result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=repo_path, capture_output=True, text=True, timeout=120
        )
        data = json.loads(result.stdout)

        findings = []
        for vuln_name, vuln in data.get("vulnerabilities", {}).items():
            findings.append({
                "tool": "npm_audit",
                "finding_type": "vulnerable_dependency",
                "severity": vuln.get("severity", "medium"),
                "package": vuln_name,
                "version": vuln.get("range", "unknown"),
                "cve_ids": [v for v in vuln.get("via", []) if isinstance(v, str)],
                "cwe_id": "CWE-1035",    # CWE for using vulnerable component
                "fix": vuln.get("fixAvailable", {}).get("version", ""),
                "message": f"Vulnerable dependency: {vuln_name}",
            })
        return findings

    async def _pip_audit(self, repo_path: str) -> list[dict]:
        # Use pip-audit with offline mode (bundled vulnerability DB)
        result = subprocess.run(
            ["pip-audit", "--format", "json", "--local",
             "--vulnerability-service", "osv"],  # Can work offline with cached DB
            cwd=repo_path, capture_output=True, text=True, timeout=300
        )
        data = json.loads(result.stdout or "[]")
        findings = []
        for dep in data:
            for vuln in dep.get("vulns", []):
                findings.append({
                    "tool": "pip_audit",
                    "finding_type": "vulnerable_dependency",
                    "severity": "medium",
                    "package": dep["name"],
                    "version": dep["version"],
                    "cve_ids": [vuln["id"]] if vuln.get("id") else [],
                    "cwe_id": "CWE-1035",
                    "fix": vuln.get("fix_versions", [""])[0],
                    "message": f"Vulnerable package: {dep['name']} {dep['version']}",
                })
        return findings
```

---

## IaC and CI/CD Scanner

```python
# backend/engines/sast/iac_scanner.py
import os, re

class IaCSanner:
    """
    Scans Infrastructure-as-Code files for security misconfigurations.
    Covers: Dockerfiles, Kubernetes manifests, GitHub Actions, GitLab CI, Terraform.
    """

    DOCKERFILE_RULES = [
        {
            "id": "no-root-user",
            "description": "Container runs as root",
            "pattern": re.compile(r'^USER\s+root\s*$', re.MULTILINE),
            "negate": True,  # Flag if NOT found (no USER directive = root)
            "severity": "high",
            "cwe": "CWE-250",
        },
        {
            "id": "add-instruction",
            "description": "ADD instruction used instead of COPY (security risk with URLs)",
            "pattern": re.compile(r'^ADD\s+https?://', re.MULTILINE),
            "negate": False,
            "severity": "medium",
            "cwe": "CWE-829",
        },
        {
            "id": "curl-bash-pipe",
            "description": "curl | bash pattern detected (supply chain risk)",
            "pattern": re.compile(r'curl.+\|.+(?:bash|sh)', re.MULTILINE),
            "negate": False,
            "severity": "critical",
            "cwe": "CWE-829",
        },
        {
            "id": "hardcoded-secret-arg",
            "description": "ARG used to pass secrets (visible in image history)",
            "pattern": re.compile(r'^ARG\s+(?:PASSWORD|SECRET|TOKEN|KEY)\s*=', re.MULTILINE | re.IGNORECASE),
            "negate": False,
            "severity": "high",
            "cwe": "CWE-312",
        },
    ]

    GITHUB_ACTIONS_RULES = [
        {
            "id": "pull-request-env",
            "description": "PR head ref set in environment (script injection risk)",
            "pattern": re.compile(r'github\.event\.pull_request\.head\.(ref|sha)'),
            "severity": "high",
            "cwe": "CWE-78",
        },
        {
            "id": "insecure-pull-request-target",
            "description": "pull_request_target trigger with checkout of PR head",
            "pattern": re.compile(r'pull_request_target'),
            "severity": "high",
            "cwe": "CWE-284",
        },
        {
            "id": "debug-logging",
            "description": "ACTIONS_STEP_DEBUG may expose secrets in logs",
            "pattern": re.compile(r'ACTIONS_STEP_DEBUG.*true', re.IGNORECASE),
            "severity": "medium",
            "cwe": "CWE-532",
        },
    ]

    async def scan(self, repo_path: str) -> list[dict]:
        findings = []

        for root, _, files in os.walk(repo_path):
            for fname in files:
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, repo_path)

                if fname == "Dockerfile" or fname.startswith("Dockerfile."):
                    content = open(fpath).read()
                    findings.extend(self._check_dockerfile(content, rel))

                elif rel.startswith(".github/workflows") and fname.endswith((".yml", ".yaml")):
                    content = open(fpath).read()
                    findings.extend(self._check_github_actions(content, rel))

                elif fname.endswith((".tf",)) or "terraform" in root.lower():
                    findings.extend(await self._check_terraform(fpath, rel))

        return findings

    def _check_dockerfile(self, content: str, rel_path: str) -> list[dict]:
        findings = []
        for rule in self.DOCKERFILE_RULES:
            match = bool(rule["pattern"].search(content))
            triggered = match if not rule.get("negate") else not match
            if triggered:
                findings.append({
                    "tool": "iac_scanner",
                    "finding_type": "iac_misconfiguration",
                    "severity": rule["severity"],
                    "rule_id": rule["id"],
                    "message": rule["description"],
                    "source_file": rel_path,
                    "cwe_id": rule["cwe"],
                })
        return findings
```

---

## SAST Output Normalization

All SAST tools produce different output formats. The normalizer converts everything to a standard `SASTFinding` schema before storage.

```python
# backend/engines/sast/output_normalizer.py
from dataclasses import dataclass
from typing import Optional

@dataclass
class NormalizedSASTFinding:
    tool: str
    finding_type: str        # "sqli", "xss", "secret", "vulnerable_dependency", etc.
    severity: str            # "critical", "high", "medium", "low", "info"
    title: str
    message: str
    source_file: Optional[str]
    source_line: Optional[int]
    source_code: Optional[str]
    cwe_id: Optional[str]
    cve_ids: list[str]
    fix: Optional[str]
    metadata: dict

class SASTOutputNormalizer:
    def normalize(self, raw_findings: list[dict], tool: str) -> list[NormalizedSASTFinding]:
        normalizer = {
            "semgrep": self._from_semgrep,
            "codeql": self._from_codeql,
            "trufflehog": self._from_trufflehog,
            "npm_audit": self._from_npm_audit,
            "pip_audit": self._from_pip_audit,
            "iac_scanner": self._from_iac,
        }.get(tool, self._passthrough)

        return [normalizer(r) for r in raw_findings]

    def _from_semgrep(self, r: dict) -> NormalizedSASTFinding:
        return NormalizedSASTFinding(
            tool="semgrep",
            finding_type=r.get("finding_type", "code_issue"),
            severity=r.get("severity", "medium"),
            title=r.get("rule_id", "Semgrep Finding"),
            message=r.get("message", ""),
            source_file=r.get("source_file"),
            source_line=r.get("source_line"),
            source_code=r.get("source_code"),
            cwe_id=r.get("cwe_id"),
            cve_ids=[],
            fix=r.get("fix"),
            metadata=r.get("metadata", {}),
        )

    def _from_codeql(self, r: dict) -> NormalizedSASTFinding:
        location = r.get("locations", [{}])[0].get("physicalLocation", {})
        return NormalizedSASTFinding(
            tool="codeql",
            finding_type=self._map_codeql_type(r.get("ruleId", "")),
            severity=self._map_codeql_severity(r.get("level", "warning")),
            title=r.get("message", {}).get("text", ""),
            message=r.get("message", {}).get("text", ""),
            source_file=location.get("artifactLocation", {}).get("uri"),
            source_line=location.get("region", {}).get("startLine"),
            source_code=None,
            cwe_id=self._extract_codeql_cwe(r),
            cve_ids=[],
            fix=None,
            metadata={"rule_id": r.get("ruleId")},
        )
```

---

## SAST → DAST Bridge

After SAST completes, it emits structured signals to guide DAST:

```python
# backend/engines/sast/dast_bridge.py
class SASTToDASTBridge:
    """
    Converts SAST findings into DAST scan hints:
    - Priority endpoints to test
    - Specific parameters to fuzz
    - Vulnerability types confirmed in code
    - Framework routes that have vulnerable handlers
    """

    def build_hints(
        self,
        sast_findings: list[NormalizedSASTFinding],
        framework_routes: dict[str, str]
    ) -> dict:
        hints = {
            "priority_endpoints": [],     # URLs/routes to test first
            "priority_params": [],        # {param: str, vuln_type: str}
            "confirmed_vuln_types": [],   # SAST-confirmed vuln types to focus on
            "skip_vuln_types": [],        # Types not seen in code (save time)
        }

        code_vuln_types = {f.finding_type for f in sast_findings}
        hints["confirmed_vuln_types"] = list(code_vuln_types)

        for finding in sast_findings:
            if finding.finding_type in ("sqli", "xss", "ssrf", "rce", "lfi"):
                # Find the API route for the vulnerable function
                func_route = framework_routes.get(finding.source_file)
                if func_route:
                    hints["priority_endpoints"].append({
                        "route": func_route,
                        "vuln_type": finding.finding_type,
                        "reason": f"SAST confirmed {finding.finding_type} sink in handler",
                        "priority": "critical" if finding.severity in ("critical","high") else "high"
                    })

        return hints
```
