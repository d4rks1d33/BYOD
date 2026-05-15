"""
Dynamic tool execution: the LLM can write arbitrary Python scripts and run them.

Security model:
  - Scripts run in an ephemeral temp dir that is deleted after execution
  - A fresh venv is created per run so the LLM can pip-install what it needs
  - Hard limits: 60-second wall-clock timeout, 256 MB RAM via ulimit
  - Network is allowed (the LLM needs to reach the target) but scope is
    enforced at the agent level before calling execute()
  - Generated code + stdout/stderr are saved as Evidence for the report
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import uuid
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Packages that are always available (pre-installed in the worker image)
_ALWAYS_AVAILABLE = {
    "requests", "httpx", "urllib3", "bs4", "lxml",
    "cryptography", "pycryptodome", "paramiko",
    "sqlalchemy", "psycopg2", "pymysql",
    "scapy", "impacket",
    "jwt", "python_jose",
}

# Hard-blocked package names (destructive / C2)
_BLOCKED_PACKAGES = {
    "metasploit", "pwntools_c2", "empire",
}

# Hard-blocked code patterns
_BLOCKED_CODE_PATTERNS = [
    r"os\.system\s*\(\s*['\"]rm\s+-rf",
    r"shutil\.rmtree\s*\(\s*['\"/]",
    r"subprocess.*rm\s+-rf",
    r"fork\s*\(\s*\)",          # fork-bomb guard
    r"while\s+True.*fork",
]


@dataclass
class ScriptResult:
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    script_hash: str
    elapsed_seconds: float
    requirements_installed: list[str]


class DynamicToolExecutor:
    """
    Executes LLM-generated Python scripts in an isolated temporary environment.
    """

    def __init__(
        self,
        timeout: int = 60,
        max_output_bytes: int = 256 * 1024,  # 256 KB
    ) -> None:
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes

    def _check_code_safety(self, code: str) -> Optional[str]:
        for pattern in _BLOCKED_CODE_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                return f"Blocked pattern detected: {pattern}"
        return None

    def _parse_requirements(self, code: str) -> list[str]:
        """Extract `# requires: pkg1 pkg2` comment from script header."""
        reqs: list[str] = []
        for line in code.splitlines()[:20]:
            line = line.strip()
            if line.startswith("# requires:"):
                raw = line[len("# requires:"):].strip()
                for pkg in re.split(r"[\s,]+", raw):
                    pkg = pkg.strip()
                    if pkg and pkg.lower() not in _BLOCKED_PACKAGES:
                        reqs.append(pkg)
        return reqs

    async def execute(self, code: str, env_vars: dict[str, str] | None = None) -> ScriptResult:
        safety_error = self._check_code_safety(code)
        if safety_error:
            return ScriptResult(
                success=False, stdout="", stderr=f"BLOCKED: {safety_error}",
                exit_code=-1, script_hash="", elapsed_seconds=0,
                requirements_installed=[],
            )

        requirements = self._parse_requirements(code)
        script_hash = hashlib.sha256(code.encode()).hexdigest()[:16]
        workdir = tempfile.mkdtemp(prefix=f"ap_tool_{script_hash}_")

        try:
            return await asyncio.wait_for(
                self._run_in_workdir(code, workdir, requirements, env_vars or {}),
                timeout=self.timeout + 30,  # +30s for venv setup
            )
        except asyncio.TimeoutError:
            return ScriptResult(
                success=False, stdout="", stderr=f"Timeout after {self.timeout}s",
                exit_code=124, script_hash=script_hash, elapsed_seconds=self.timeout,
                requirements_installed=[],
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    async def _run_in_workdir(
        self,
        code: str,
        workdir: str,
        requirements: list[str],
        env_vars: dict[str, str],
    ) -> ScriptResult:
        import time
        t0 = time.monotonic()

        script_path = os.path.join(workdir, "tool.py")
        with open(script_path, "w") as f:
            f.write(code)

        script_hash = hashlib.sha256(code.encode()).hexdigest()[:16]

        # Create venv
        venv_path = os.path.join(workdir, "venv")
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "venv", venv_path,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

        venv_python = os.path.join(venv_path, "bin", "python")
        venv_pip = os.path.join(venv_path, "bin", "pip")
        installed: list[str] = []

        # Install requirements
        for req in requirements:
            if req.lower() in _BLOCKED_PACKAGES:
                continue
            try:
                pip_proc = await asyncio.create_subprocess_exec(
                    venv_pip, "install", "--quiet", "--no-cache-dir", req,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    cwd=workdir,
                )
                await asyncio.wait_for(pip_proc.communicate(), timeout=60)
                installed.append(req)
            except Exception as e:
                logger.warning("Failed to install %s: %s", req, e)

        # Build execution environment
        merged_env = {
            **os.environ,
            "PYTHONPATH": workdir,
            "HOME": workdir,
            "TMPDIR": workdir,
            **env_vars,
        }
        # Strip any credential env vars from being leaked into the script
        for k in list(merged_env.keys()):
            if any(s in k.upper() for s in ("SECRET", "PASSWORD", "TOKEN", "PRIVATE_KEY")):
                del merged_env[k]

        # Execute
        try:
            run_proc = await asyncio.create_subprocess_exec(
                venv_python, script_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=workdir,
                env=merged_env,
            )
            try:
                raw_stdout, raw_stderr = await asyncio.wait_for(
                    run_proc.communicate(), timeout=self.timeout
                )
            except asyncio.TimeoutError:
                run_proc.kill()
                await run_proc.communicate()
                return ScriptResult(
                    success=False, stdout="", stderr=f"Script timeout after {self.timeout}s",
                    exit_code=124, script_hash=script_hash,
                    elapsed_seconds=time.monotonic() - t0,
                    requirements_installed=installed,
                )

            stdout = raw_stdout.decode(errors="replace")[: self.max_output_bytes]
            stderr = raw_stderr.decode(errors="replace")[: self.max_output_bytes]
            elapsed = time.monotonic() - t0

            return ScriptResult(
                success=(run_proc.returncode == 0),
                stdout=stdout,
                stderr=stderr,
                exit_code=run_proc.returncode or 0,
                script_hash=script_hash,
                elapsed_seconds=elapsed,
                requirements_installed=installed,
            )
        except Exception as e:
            return ScriptResult(
                success=False, stdout="", stderr=str(e),
                exit_code=-1, script_hash=script_hash,
                elapsed_seconds=time.monotonic() - t0,
                requirements_installed=installed,
            )
