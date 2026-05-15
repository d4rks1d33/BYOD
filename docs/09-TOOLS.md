# AutoPentest — External Tool Integrations

## Tool Orchestrator

All external tools are wrapped in a unified interface. Output is normalized to the `NormalizedToolFinding` schema before storage.

```python
# backend/integrations/base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class NormalizedToolFinding:
    tool: str
    finding_type: str
    severity: str
    title: str
    description: str
    endpoint_url: Optional[str]
    source_file: Optional[str]
    cwe_id: Optional[str]
    cve_ids: list[str]
    evidence: dict
    raw_output: str   # Original tool output line for audit trail

class BaseToolRunner(ABC):
    @abstractmethod
    async def run(self, target: str, config: dict) -> list[NormalizedToolFinding]:
        pass

    def run_in_sandbox(self, cmd: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
        """All tool execution runs inside Firejail sandbox."""
        sandboxed_cmd = [
            "firejail",
            f"--profile=/etc/firejail/{self.__class__.__name__.lower()}.profile",
            "--",
        ] + cmd
        return subprocess.run(sandboxed_cmd, capture_output=True, text=True, timeout=timeout)
```

---

## Nuclei Integration

```python
# backend/integrations/nuclei.py
class NucleiRunner(BaseToolRunner):
    """
    Runs Nuclei with AI-selected template categories.
    Templates are bundled locally for air-gapped operation.
    """

    SEVERITY_MAP = {"info": "info", "low": "low", "medium": "medium",
                    "high": "high", "critical": "critical"}

    def __init__(self, templates_dir: str = "/opt/nuclei-templates"):
        self.templates_dir = templates_dir

    async def run(self, target: str, config: dict) -> list[NormalizedToolFinding]:
        # Select template categories based on scan type and AI hints
        tags = config.get("nuclei_tags", ["cves", "vulnerabilities", "misconfigurations",
                                           "exposures", "default-logins"])

        cmd = [
            "nuclei",
            "-u", target,
            "-t", self.templates_dir,
            "-tags", ",".join(tags),
            "-json",
            "-silent",
            "-timeout", "10",
            "-rate-limit", str(config.get("rate_limit", 10)),
            "-no-update-check",          # Air-gapped mode
        ]

        # Add auth headers if available
        auth_result = config.get("auth_result", {})
        for header, value in auth_result.get("headers", {}).items():
            cmd += ["-H", f"{header}: {value}"]

        for cookie_name, cookie_value in auth_result.get("cookies", {}).items():
            cmd += ["-H", f"Cookie: {cookie_name}={cookie_value}"]

        result = self.run_in_sandbox(cmd, timeout=600)
        findings = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                raw = json.loads(line)
                findings.append(self._normalize(raw))
            except json.JSONDecodeError:
                pass

        return findings

    def _normalize(self, raw: dict) -> NormalizedToolFinding:
        info = raw.get("info", {})
        return NormalizedToolFinding(
            tool="nuclei",
            finding_type=self._classify(raw.get("template-id", "")),
            severity=self.SEVERITY_MAP.get(info.get("severity", "medium"), "medium"),
            title=info.get("name", raw.get("template-id", "")),
            description=info.get("description", ""),
            endpoint_url=raw.get("matched-at"),
            source_file=None,
            cwe_id=self._extract_cwe(info),
            cve_ids=info.get("classification", {}).get("cve-id", []) or [],
            evidence={
                "template_id": raw.get("template-id"),
                "matcher_name": raw.get("matcher-name"),
                "extracted": raw.get("extracted-results", []),
                "curl_command": raw.get("curl-command"),
            },
            raw_output=json.dumps(raw),
        )

    def _extract_cwe(self, info: dict) -> Optional[str]:
        cwes = info.get("classification", {}).get("cwe-id", [])
        return cwes[0] if cwes else None
```

---

## ffuf Integration

```python
# backend/integrations/ffuf.py
class FfufRunner(BaseToolRunner):
    """
    Directory and parameter fuzzing with ffuf.
    Supports custom wordlists uploaded by analysts.
    """

    BUILTIN_WORDLISTS = {
        "directories": "/opt/wordlists/directories-medium.txt",
        "parameters": "/opt/wordlists/burp-parameter-names.txt",
        "backup_files": "/opt/wordlists/backup-files.txt",
        "api_endpoints": "/opt/wordlists/api-endpoints.txt",
    }

    async def fuzz_directories(self, target_url: str, config: dict) -> list[NormalizedToolFinding]:
        wordlist = config.get("wordlist_path") or self.BUILTIN_WORDLISTS["directories"]
        auth_result = config.get("auth_result", {})

        cmd = [
            "ffuf",
            "-u", f"{target_url.rstrip('/')}/FUZZ",
            "-w", wordlist,
            "-json",
            "-mc", "200,201,301,302,401,403,405",  # Match codes
            "-fs", "0",         # Filter empty responses
            "-timeout", "10",
            "-rate", str(config.get("rate_limit", 20)),
            "-t", "10",         # 10 threads
        ]

        # Add auth
        for header, value in auth_result.get("headers", {}).items():
            cmd += ["-H", f"{header}: {value}"]

        result = self.run_in_sandbox(cmd, timeout=600)
        findings = []
        try:
            data = json.loads(result.stdout)
            for r in data.get("results", []):
                if r["status"] != 200:  # Non-200 but accessible — potential finding
                    findings.append(NormalizedToolFinding(
                        tool="ffuf",
                        finding_type="exposed_path",
                        severity=self._status_severity(r["status"]),
                        title=f"Accessible path: {r['url']}",
                        description=f"Path {r['input']['FUZZ']} returned HTTP {r['status']}",
                        endpoint_url=r["url"],
                        source_file=None,
                        cwe_id="CWE-552",
                        cve_ids=[],
                        evidence={"status": r["status"], "size": r["length"], "words": r["words"]},
                        raw_output=json.dumps(r)
                    ))
        except Exception:
            pass
        return findings

    def _status_severity(self, status: int) -> str:
        if status == 401:
            return "low"  # Exists but protected
        if status == 403:
            return "medium"  # Exists, forbidden — may be bypassable
        if status in range(200, 300):
            return "high"  # Fully accessible
        return "info"
```

---

## OWASP ZAP Integration

```python
# backend/integrations/zap.py
class ZAPRunner(BaseToolRunner):
    """
    Uses ZAP in daemon mode with REST API for deep scanning.
    ZAP runs as a background service in the worker-scan container.
    """

    def __init__(self, zap_host: str = "http://localhost:8090", api_key: str = "autopentest"):
        self.base_url = zap_host
        self.api_key = api_key

    async def run_ajax_spider(self, target: str, config: dict) -> list[str]:
        """Use ZAP's AJAX spider for JS-heavy applications."""
        async with httpx.AsyncClient() as client:
            # Start AJAX spider
            r = await client.get(f"{self.base_url}/JSON/ajaxSpider/action/scan/", params={
                "url": target,
                "apikey": self.api_key
            })
            r.raise_for_status()

            # Poll until complete
            while True:
                status = await client.get(f"{self.base_url}/JSON/ajaxSpider/view/status/",
                                          params={"apikey": self.api_key})
                if status.json().get("status") == "stopped":
                    break
                await asyncio.sleep(5)

            # Get results
            results = await client.get(f"{self.base_url}/JSON/ajaxSpider/view/results/",
                                       params={"apikey": self.api_key})
            return [r["url"] for r in results.json().get("results", [])]

    async def run_active_scan(self, target: str, config: dict) -> list[NormalizedToolFinding]:
        """Run ZAP active scanner."""
        async with httpx.AsyncClient() as client:
            # Start active scan
            r = await client.get(f"{self.base_url}/JSON/ascan/action/scan/", params={
                "url": target,
                "apikey": self.api_key,
                "scanPolicyName": "Default Policy"
            })
            scan_id = r.json().get("scan")

            # Poll for completion
            while True:
                progress = await client.get(f"{self.base_url}/JSON/ascan/view/status/",
                                            params={"scanId": scan_id, "apikey": self.api_key})
                if int(progress.json().get("status", 0)) >= 100:
                    break
                await asyncio.sleep(10)

            # Get alerts
            alerts = await client.get(f"{self.base_url}/JSON/core/view/alerts/",
                                      params={"apikey": self.api_key, "baseurl": target})
            return [self._normalize_alert(a) for a in alerts.json().get("alerts", [])]

    def _normalize_alert(self, alert: dict) -> NormalizedToolFinding:
        return NormalizedToolFinding(
            tool="zap",
            finding_type=alert.get("name", "").lower().replace(" ", "_"),
            severity=["info", "low", "medium", "high"][int(alert.get("risk", 1))],
            title=alert.get("name", "ZAP Finding"),
            description=alert.get("description", ""),
            endpoint_url=alert.get("url"),
            source_file=None,
            cwe_id=f"CWE-{alert['cweid']}" if alert.get("cweid") else None,
            cve_ids=[],
            evidence={"evidence": alert.get("evidence"), "solution": alert.get("solution"),
                      "reference": alert.get("reference"), "param": alert.get("param")},
            raw_output=json.dumps(alert)
        )
```

---

## Burp Suite Integration

```python
# backend/integrations/burp.py
class BurpSuiteRunner(BaseToolRunner):
    """
    Integrates with Burp Suite Professional via its REST API.
    Requires Burp Suite Pro + REST API enabled in project options.
    Optional integration — gracefully disabled if Burp is not available.
    """

    def __init__(self, burp_host: str = "http://localhost:1337",
                 api_key: str = None):
        self.base_url = burp_host
        self.api_key = api_key
        self.headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient() as client:
                r = await client.get(f"{self.base_url}/v0.1/", headers=self.headers, timeout=5)
                return r.status_code == 200
        except Exception:
            return False

    async def run_scan(self, target: str, config: dict) -> list[NormalizedToolFinding]:
        """Launch Burp scan via REST API and collect issues."""
        if not await self.is_available():
            return []  # Graceful degradation

        async with httpx.AsyncClient() as client:
            # Create scan
            scan_config = {
                "urls": [target],
                "scope": {"exclude": [], "include": [{"rule": target, "type": "SimpleScope"}]},
                "application_logins": [],
            }
            r = await client.post(f"{self.base_url}/v0.1/scan",
                                  json=scan_config, headers=self.headers)
            task_id = r.headers.get("Location", "").split("/")[-1]

            # Poll until complete
            while True:
                status = await client.get(f"{self.base_url}/v0.1/scan/{task_id}",
                                          headers=self.headers)
                data = status.json()
                if data.get("scan_status") in ("succeeded", "failed"):
                    break
                await asyncio.sleep(15)

            # Get issues
            issues = await client.get(f"{self.base_url}/v0.1/scan/{task_id}/issues",
                                      headers=self.headers)
            return [self._normalize_issue(i) for i in issues.json().get("issue_events", [])]
```

---

## katana Integration

```python
# backend/integrations/katana.py
class KatanaRunner(BaseToolRunner):
    """
    Fast, JavaScript-aware web crawler for endpoint discovery.
    Preferred over ffuf for initial discovery phase.
    """

    async def crawl(self, target: str, config: dict) -> list[str]:
        cmd = [
            "katana",
            "-u", target,
            "-depth", str(config.get("depth", 3)),
            "-jc",              # JavaScript crawling enabled
            "-silent",
            "-json",
            "-rate-limit", str(config.get("rate_limit", 20)),
            "-timeout", "10",
            "-no-color",
        ]

        auth_result = config.get("auth_result", {})
        for header, value in auth_result.get("headers", {}).items():
            cmd += ["-H", f"{header}: {value}"]

        result = self.run_in_sandbox(cmd, timeout=300)
        urls = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                urls.append(data.get("endpoint", ""))
            except json.JSONDecodeError:
                urls.append(line.strip())

        return [u for u in urls if u]
```

---

## Tool Execution Orchestrator

```python
# backend/engines/tool_orchestrator.py
class ToolOrchestrator:
    """
    Manages parallel execution of multiple tools with resource limits.
    Tools run in separate Firejail processes with CPU/memory limits.
    """

    def __init__(self, max_parallel_tools: int = 4):
        self.semaphore = asyncio.Semaphore(max_parallel_tools)
        self.runners = {
            "nuclei": NucleiRunner(),
            "ffuf": FfufRunner(),
            "zap": ZAPRunner(),
            "katana": KatanaRunner(),
            "burp": BurpSuiteRunner(),
        }

    async def run_selected_tools(
        self,
        tools: list[str],
        target: str,
        config: dict
    ) -> list[NormalizedToolFinding]:
        """Run selected tools in parallel with semaphore limiting."""
        tasks = [
            self._run_with_semaphore(tool, target, config)
            for tool in tools
            if tool in self.runners
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings = []
        for tool, result in zip(tools, results):
            if isinstance(result, Exception):
                # Log error but don't fail the scan
                logger.error(f"Tool {tool} failed: {result}")
            else:
                all_findings.extend(result)

        return all_findings

    async def _run_with_semaphore(
        self, tool: str, target: str, config: dict
    ) -> list[NormalizedToolFinding]:
        async with self.semaphore:
            runner = self.runners[tool]
            logger.info(f"Starting tool: {tool} against {target}")
            findings = await runner.run(target, config)
            logger.info(f"Tool {tool} completed: {len(findings)} findings")
            return findings
```

---

## Tool Firejail Profiles

### `/etc/firejail/nuclei.profile`

```
# Nuclei Firejail profile
noblacklist ~/.nuclei-templates
whitelist ~/.nuclei-templates
whitelist /opt/nuclei-templates
whitelist /tmp/nuclei-output
read-only /opt/nuclei-templates
private-tmp
net none             # No network — runs inside container with outbound access configured
noroot
caps.drop all
seccomp
```

### `/etc/firejail/semgrep.profile`

```
# Semgrep Firejail profile
private-tmp
whitelist /opt/semgrep-rules
whitelist /scan/repo
read-only /opt/semgrep-rules
read-only /scan/repo
net none
noroot
caps.drop all
seccomp
```
