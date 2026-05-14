from __future__ import annotations
import asyncio
import logging
import os
import tempfile
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    success: bool


class DockerSandbox:
    """Runs security tool commands inside an isolated Docker container."""

    DEFAULT_IMAGE = "autopentest-tools:latest"
    DEFAULT_TIMEOUT = 300

    def __init__(
        self,
        image: str = DEFAULT_IMAGE,
        timeout: int = DEFAULT_TIMEOUT,
        network: str = "autopentest_scan_net",
    ):
        self.image = image
        self.timeout = timeout
        self.network = network

    async def run(
        self,
        command: list[str],
        env: dict[str, str] | None = None,
        output_dir: str | None = None,
    ) -> SandboxResult:
        """Execute command in Docker sandbox with security hardening."""
        try:
            import docker
            client = docker.from_env()
        except Exception as e:
            logger.error("Docker unavailable, falling back to direct exec: %s", e)
            return await self._fallback_run(command, env)

        volumes = {}
        if output_dir:
            volumes[output_dir] = {"bind": "/output", "mode": "rw"}

        env_dict = env or {}

        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: client.containers.run(
                    self.image,
                    command=command,
                    environment=env_dict,
                    volumes=volumes,
                    network=self.network,
                    detach=False,
                    remove=True,
                    read_only=True,
                    tmpfs={"/tmp": "size=100m,noexec"},
                    security_opt=["no-new-privileges"],
                    cap_drop=["ALL"],
                    timeout=self.timeout,
                    mem_limit="512m",
                    cpu_period=100000,
                    cpu_quota=50000,  # 0.5 CPU
                ),
            )
            stdout = result.decode() if isinstance(result, bytes) else str(result)
            return SandboxResult(exit_code=0, stdout=stdout, stderr="", success=True)
        except Exception as e:
            logger.error("Docker sandbox error: %s", e)
            return SandboxResult(exit_code=1, stdout="", stderr=str(e), success=False)

    async def _fallback_run(self, command: list[str], env: dict | None) -> SandboxResult:
        """Direct subprocess fallback when Docker is unavailable (dev mode)."""
        merged_env = {**os.environ, **(env or {})}
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=merged_env,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )
            return SandboxResult(
                exit_code=proc.returncode or 0,
                stdout=stdout.decode(errors="replace"),
                stderr=stderr.decode(errors="replace"),
                success=(proc.returncode == 0),
            )
        except asyncio.TimeoutError:
            return SandboxResult(exit_code=124, stdout="", stderr="Timeout", success=False)
        except Exception as e:
            return SandboxResult(exit_code=1, stdout="", stderr=str(e), success=False)
