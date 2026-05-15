#!/usr/bin/env python3
"""Verify all required security tools are installed and accessible."""
from __future__ import annotations
import subprocess
import sys

TOOLS = [
    ("nuclei", ["nuclei", "-version"]),
    ("ffuf", ["ffuf", "-V"]),
    ("katana", ["katana", "-version"]),
    ("trufflehog", ["trufflehog", "--version"]),
    ("semgrep", ["semgrep", "--version"]),
    ("pip-audit", ["pip-audit", "--version"]),
    ("git", ["git", "--version"]),
]

PYTHON_PACKAGES = [
    "httpx",
    "sqlalchemy",
    "fastapi",
    "celery",
    "redis",
    "llama_cpp",
    "ollama",
    "pgvector",
    "playwright",
    "weasyprint",
]


def check_tool(name: str, cmd: list[str]) -> bool:
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        ok = result.returncode == 0
        version_line = (result.stdout or result.stderr).decode(errors="replace").splitlines()
        version = version_line[0] if version_line else ""
        status = "✅" if ok else "❌"
        print(f"  {status} {name:<15} {version[:60]}")
        return ok
    except FileNotFoundError:
        print(f"  ❌ {name:<15} NOT FOUND")
        return False
    except Exception as e:
        print(f"  ❌ {name:<15} ERROR: {e}")
        return False


def check_python_package(pkg: str) -> bool:
    try:
        __import__(pkg.replace("-", "_"))
        print(f"  ✅ {pkg}")
        return True
    except ImportError:
        print(f"  ❌ {pkg} — not installed")
        return False


def main() -> None:
    print("\n=== AutoPentest Tool Check ===\n")

    print("Security tools:")
    tool_results = [check_tool(name, cmd) for name, cmd in TOOLS]

    print("\nPython packages:")
    pkg_results = [check_python_package(pkg) for pkg in PYTHON_PACKAGES]

    failed_tools = sum(1 for r in tool_results if not r)
    failed_pkgs = sum(1 for r in pkg_results if not r)

    print(f"\nSummary: {len(TOOLS) - failed_tools}/{len(TOOLS)} tools OK, "
          f"{len(PYTHON_PACKAGES) - failed_pkgs}/{len(PYTHON_PACKAGES)} packages OK")

    if failed_tools > 0:
        print("\nRun scripts/setup.sh to install missing tools.")
    if failed_pkgs > 0:
        print("Run pip install -r requirements.txt to install missing packages.")

    if failed_tools > 0 or failed_pkgs > 0:
        sys.exit(1)
    else:
        print("\n✅ All tools ready. AutoPentest is good to go!")


if __name__ == "__main__":
    main()
