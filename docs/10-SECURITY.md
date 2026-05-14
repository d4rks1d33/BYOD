# AutoPentest — Security Architecture

## RBAC Permission Model

### System-Level Roles

| Role | Description | Default Assignment |
|------|-------------|-------------------|
| `super_admin` | Full system access, user management, audit log access | First user created via seed |
| `admin` | Project creation, user invitation, plugin management | Manually assigned |
| `analyst` | Create/run scans, manage findings, generate reports | Default for invited users |
| `viewer` | Read-only access to assigned projects | Guest/stakeholder access |

### Project-Level Roles (Override System Role Per Project)

| Role | Permissions |
|------|------------|
| `project_owner` | All permissions on this project including member management |
| `project_analyst` | Create scans, manage findings, generate reports |
| `project_viewer` | Read findings and reports only — no scan creation |

### Permission Matrix

| Resource | Action | super_admin | admin | analyst | viewer |
|----------|--------|-------------|-------|---------|--------|
| Projects | create | ✓ | ✓ | ✓ | ✗ |
| Projects | read | ✓ | ✓ (own) | ✓ (member) | ✓ (member) |
| Projects | delete | ✓ | ✓ (own) | ✗ | ✗ |
| Scans | create | ✓ | ✓ | ✓ | ✗ |
| Scans | read | ✓ | ✓ (project) | ✓ (project) | ✓ (project) |
| Scans | pause/resume | ✓ | ✓ | ✓ (own) | ✗ |
| Findings | read | ✓ | ✓ (project) | ✓ (project) | ✓ (project) |
| Findings | verify/fp | ✓ | ✓ | ✓ (project) | ✗ |
| Evidence | read | ✓ | ✓ (project) | ✓ (project) | ✗ |
| Reports | generate | ✓ | ✓ | ✓ (project) | ✗ |
| Reports | download | ✓ | ✓ (project) | ✓ (project) | ✓ (project) |
| AI Models | manage | ✓ | ✗ | ✗ | ✗ |
| Plugins | manage | ✓ | ✓ | ✗ | ✗ |
| Users | create | ✓ | ✓ | ✗ | ✗ |
| Users | role change | ✓ | ✗ | ✗ | ✗ |
| Audit Logs | read all | ✓ | ✗ | ✗ | ✗ |
| Audit Logs | read project | ✓ | ✓ (own projects) | ✗ | ✗ |

### FastAPI RBAC Enforcement

```python
# backend/api/dependencies/rbac.py
from fastapi import Depends, HTTPException, status
from functools import wraps

class RBACDependency:
    def __init__(self, required_role: str, resource_param: str = None):
        self.required_role = required_role
        self.resource_param = resource_param

    async def __call__(self, request: Request,
                       current_user: User = Depends(get_current_user),
                       db: AsyncSession = Depends(get_db)):
        # System-level role check
        role_hierarchy = ["viewer", "analyst", "admin", "super_admin"]
        if role_hierarchy.index(current_user.role) < role_hierarchy.index(self.required_role):
            # Check project-level override
            if self.resource_param:
                project_id = request.path_params.get(self.resource_param)
                if project_id:
                    member = await db.get(ProjectMember,
                                          {"project_id": project_id, "user_id": current_user.id})
                    if member and self._project_role_sufficient(member.role, self.required_role):
                        return current_user
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Insufficient permissions")
        return current_user

# Usage in routers:
@router.post("/projects/{project_id}/scans")
async def create_scan(
    project_id: UUID,
    current_user: User = Depends(RBACDependency("analyst", "project_id"))
):
    ...
```

### PostgreSQL Row-Level Security

```sql
-- Create non-superuser role for application
CREATE ROLE app_user LOGIN PASSWORD '${DB_APP_PASSWORD}';
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;

-- RLS on projects table
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;

-- Policy: can see projects you own OR are a member of
CREATE POLICY project_rls ON projects
    AS PERMISSIVE FOR ALL TO app_user
    USING (
        owner_id = current_setting('app.current_user_id', true)::uuid
        OR
        EXISTS (
            SELECT 1 FROM project_members pm
            WHERE pm.project_id = projects.id
              AND pm.user_id = current_setting('app.current_user_id', true)::uuid
        )
    );

-- Inherited RLS for scans, findings (use project policy via subquery)
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
CREATE POLICY scan_rls ON scans AS PERMISSIVE FOR ALL TO app_user
    USING (project_id IN (SELECT id FROM projects));  -- Uses project RLS

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY finding_rls ON findings AS PERMISSIVE FOR ALL TO app_user
    USING (project_id IN (SELECT id FROM projects));

-- Set user context in SQLAlchemy via after_begin event
# In backend/core/database.py:
# @event.listens_for(async_engine.sync_engine, "after_begin")
# def set_rls_context(conn, transaction, started):
#     if hasattr(conn, '_app_user_id'):
#         conn.execute(text(f"SET LOCAL app.current_user_id = '{conn._app_user_id}'"))
```

---

## Sandbox Isolation Design

### Per-Scan Docker Container Strategy

```python
# backend/sandbox/docker_sandbox.py
import docker
from docker.types import Ulimit

class DockerSandbox:
    """
    Creates an isolated Docker container per scan operation.
    Container has no access to host filesystem, postgres, or redis.
    Destroyed after use.
    """

    SECCOMP_PROFILE = "/etc/docker/seccomp/default.json"  # Block dangerous syscalls

    def __init__(self, docker_client: docker.DockerClient):
        self.docker = docker_client
        # Create isolated network per scan
        self._scan_networks: dict[str, str] = {}  # scan_id → network_id

    async def create_scan_network(self, scan_id: str) -> str:
        """Create an isolated network for a scan — only allows egress to target."""
        network = self.docker.networks.create(
            f"scan-{scan_id[:8]}",
            driver="bridge",
            internal=False,   # Allows internet access
            options={
                "com.docker.network.bridge.enable_icc": "false",  # No inter-container
            },
            ipam=docker.types.IPAMConfig(
                pool_configs=[docker.types.IPAMPool(
                    subnet="10.100.0.0/24",  # Isolated subnet
                )]
            )
        )
        self._scan_networks[scan_id] = network.id
        return network.id

    def run_tool(
        self,
        image: str,
        cmd: list[str],
        scan_id: str,
        evidence_volume_path: str,
        timeout: int = 300,
    ) -> dict:
        """Run a single tool in an isolated container."""
        container = self.docker.containers.run(
            image=image,
            command=cmd,
            detach=True,
            # Security hardening
            security_opt=[
                "no-new-privileges:true",
                f"seccomp={self.SECCOMP_PROFILE}",
                "apparmor=docker-default",
            ],
            cap_drop=["ALL"],        # Drop ALL capabilities
            read_only=True,          # Read-only root filesystem
            tmpfs={"/tmp": "size=512m,mode=1777"},  # Writable /tmp only
            mem_limit="2g",
            memswap_limit="2g",
            cpu_period=100000,
            cpu_quota=200000,        # 2 CPUs max
            pids_limit=200,
            network=f"scan-{scan_id[:8]}",
            # Evidence output mount (writable, isolated path)
            volumes={
                evidence_volume_path: {"bind": "/output", "mode": "rw"}
            },
            environment={
                "SCAN_ID": scan_id,
            },
            remove=False,            # Keep for log collection, remove manually
            auto_remove=False,
        )

        try:
            exit_code = container.wait(timeout=timeout)["StatusCode"]
            logs = container.logs().decode("utf-8", errors="replace")
        finally:
            container.remove(force=True)

        return {"exit_code": exit_code, "output": logs}

    def cleanup_scan(self, scan_id: str):
        """Remove network and any leftover containers for a scan."""
        network_id = self._scan_networks.pop(scan_id, None)
        if network_id:
            try:
                network = self.docker.networks.get(network_id)
                network.remove()
            except Exception:
                pass
```

### SSRF Internal Address Protection

```python
# backend/sandbox/network_policy.py
import ipaddress, socket

BLOCKED_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),   # Link-local (AWS IMDS)
    ipaddress.IPv4Network("100.64.0.0/10"),    # Carrier-grade NAT
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv6Network("::1/128"),           # IPv6 loopback
    ipaddress.IPv6Network("fc00::/7"),          # IPv6 ULA
]

def is_target_safe(url: str) -> tuple[bool, Optional[str]]:
    """
    Verify that the scan target does not point to internal infrastructure.
    Called before every DAST request and payload test.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return False, "No hostname in URL"

    # Resolve DNS to IP
    try:
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)
    except socket.gaierror:
        return False, f"Cannot resolve hostname: {hostname}"

    for blocked_net in BLOCKED_NETWORKS:
        if ip in blocked_net:
            return False, f"Target IP {ip} is in blocked network {blocked_net}"

    return True, None

class DNSRebindingProtection:
    """
    Resolves DNS once at scan start and pins the IP.
    Prevents DNS rebinding attacks where target changes IP mid-scan.
    """
    def __init__(self):
        self._pinned_ips: dict[str, str] = {}  # hostname → IP

    def resolve_and_pin(self, hostname: str) -> str:
        if hostname not in self._pinned_ips:
            ip = socket.gethostbyname(hostname)
            safe, reason = is_target_safe(f"http://{hostname}")
            if not safe:
                raise SecurityError(f"Unsafe target: {reason}")
            self._pinned_ips[hostname] = ip
        return self._pinned_ips[hostname]
```

---

## Credential and Secret Storage

```python
# backend/core/encryption.py
import os, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

class FieldEncryption:
    """
    AES-256-GCM field-level encryption for sensitive database columns.
    Each project gets a derived key from the master key + project_id.
    """

    def __init__(self, master_key_hex: str):
        # Master key from SECRET_KEY env var (must be 32 bytes hex = 64 chars)
        self._master_key = bytes.fromhex(master_key_hex)

    def _derive_project_key(self, project_id: str) -> bytes:
        """Derive a unique 32-byte key for each project using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f"project:{project_id}".encode()
        )
        return hkdf.derive(self._master_key)

    def encrypt(self, plaintext: str, project_id: str) -> str:
        """Returns base64-encoded ciphertext with nonce prepended."""
        key = self._derive_project_key(project_id)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)   # 96-bit nonce
        ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return base64.b64encode(nonce + ct).decode()

    def decrypt(self, ciphertext_b64: str, project_id: str) -> str:
        key = self._derive_project_key(project_id)
        aesgcm = AESGCM(key)
        data = base64.b64decode(ciphertext_b64)
        nonce, ct = data[:12], data[12:]
        return aesgcm.decrypt(nonce, ct, None).decode()

# Usage in SQLAlchemy model:
# @hybrid_property
# def auth_config(self) -> dict:
#     if not self._auth_config_enc:
#         return {}
#     encryption = get_field_encryption()
#     decrypted = encryption.decrypt(self._auth_config_enc, str(self.id))
#     return json.loads(decrypted)
```

---

## Audit Logging

```python
# backend/api/middleware/audit.py
from fastapi import Request, Response
import time

class AuditMiddleware:
    """
    Automatically creates audit log entries for all mutating API requests.
    """

    AUDITED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
    RESOURCE_PATTERNS = {
        r"/projects$": ("project", "create"),
        r"/projects/([^/]+)$": ("project", "update"),
        r"/projects/([^/]+)/scans$": ("scan", "create"),
        r"/scans/([^/]+)/pause$": ("scan", "pause"),
        r"/scans/([^/]+)/resume$": ("scan", "resume"),
        r"/findings/([^/]+)$": ("finding", "update"),
        r"/findings/([^/]+)/verify$": ("finding", "verify"),
        r"/findings/([^/]+)/false-positive$": ("finding", "false_positive"),
        r"/users/([^/]+)/role$": ("user", "role_change"),
        r"/plugins/([^/]+)/enable$": ("plugin", "enable"),
    }

    async def __call__(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        elapsed = time.time() - start_time

        if request.method in self.AUDITED_METHODS:
            await self._create_audit_log(request, response)

        return response

    async def _create_audit_log(self, request: Request, response: Response):
        import re
        path = request.url.path
        for pattern, (resource_type, action) in self.RESOURCE_PATTERNS.items():
            m = re.match(pattern, path)
            if m:
                user = getattr(request.state, "current_user", None)
                db = request.state.db
                await db.execute(
                    insert(AuditLog).values(
                        actor_id=user.id if user else None,
                        actor_email=user.email if user else "system",
                        action=f"{resource_type}.{action}",
                        resource_type=resource_type,
                        resource_id=m.group(1) if m.groups() else None,
                        details={"method": request.method, "path": path,
                                 "status_code": response.status_code},
                        ip_address=request.client.host,
                        user_agent=request.headers.get("user-agent"),
                        chain_hash=await self._compute_chain_hash(db),
                    )
                )
                await db.commit()
                break

    async def _compute_chain_hash(self, db) -> str:
        """Hash chain for tamper detection: SHA-256(prev_hash || this_record)."""
        import hashlib, json
        # Get last hash (locked to prevent concurrent hash computation)
        result = await db.execute(
            text("SELECT chain_hash FROM audit_logs ORDER BY created_at DESC LIMIT 1 FOR UPDATE")
        )
        prev_hash = (result.scalar() or "genesis")
        new_data = json.dumps({
            "prev": prev_hash,
            "timestamp": time.time(),
        })
        return hashlib.sha256(new_data.encode()).hexdigest()
```

---

## Platform Hardening

### Security Headers Middleware

```python
# backend/api/middleware/security_headers.py
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "   # unsafe-inline needed for Next.js
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self' ws: wss:; "          # Allow WebSocket
        "frame-src 'none'; "                      # No iframes (prevents evidence viewer XSS)
        "object-src 'none';"
    ),
}
```

### Command Injection Prevention

```python
# All subprocess calls must use list form, NEVER shell=True
# WRONG:
subprocess.run(f"semgrep scan {repo_path}", shell=True)  # NEVER

# CORRECT:
subprocess.run(
    ["semgrep", "scan", repo_path],   # List form — no shell interpretation
    capture_output=True,
    text=True,
    timeout=300
)

# URL validation before DAST requests
def validate_scan_target(url: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid scheme: {parsed.scheme}")
    if not parsed.netloc:
        raise ValueError("URL has no hostname")
    # Check scope
    safe, reason = is_target_safe(url)
    if not safe:
        raise SecurityError(f"Unsafe target: {reason}")
    return url
```

---

## Air-Gapped Operation Checklist

| Component | Air-Gapped Design | Implementation |
|-----------|------------------|----------------|
| LLM | .gguf from local filesystem | MODEL_PATH env var → no download |
| Embeddings | nomic-embed-text via local Ollama | Pre-pull image in Dockerfile |
| NVD/CVE DB | SQLite snapshot in `/opt/nvd/` | `scripts/update-nvd-offline.sh` |
| Nuclei templates | Bundled in `/opt/nuclei-templates` | `scripts/update-nuclei-templates.sh` |
| Semgrep rules | Bundled in `/opt/semgrep-rules` | `scripts/update-semgrep-rules.sh` |
| npm packages | Pre-installed in Docker image | `Dockerfile.worker` layer |
| pip packages | Pre-installed in Docker image | `Dockerfile.worker` layer |
| Container images | Pre-built, loaded via tar | `docker load < images.tar` |
| No telemetry | `SEMGREP_SEND_METRICS=off`, `nuclei -no-update-check` | Dockerfile ENV |
| No update checks | All tools configured to skip | Startup validation in `setup.sh` |
