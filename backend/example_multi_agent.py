#!/usr/bin/env python3
"""
Example: Multi-Agent Pentest with Multi-LLM Fallback

Demonstrates:
- 4 specialized agents (Recon, Exploit, Analysis, Report)
- Multiple LLMs working together with automatic fallback
- 22+ pentesting tools available to the AI
"""
import os
import sys
import logging
import json
from services.llm_orchestrator import build_orchestrator_from_env, LLMConfig, LLMRole, LLMTier, LLMOrchestrator
from services.multi_agent_system import MultiAgentOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def main():
    TARGET_URL = "http://testaspnet.vulnweb.com"

    print("=" * 70)
    print(" MULTI-AGENT AI-NATIVE PENTEST DEMO")
    print("=" * 70)
    print(f"\nTarget: {TARGET_URL}")

    # Check available API keys
    available = []
    if os.getenv("GEMINI_API_KEY"):
        available.append("Gemini")
    if os.getenv("OPENAI_API_KEY"):
        available.append("OpenAI")
    if os.getenv("ANTHROPIC_API_KEY"):
        available.append("Anthropic")

    # Check Ollama
    try:
        import requests
        resp = requests.get("http://localhost:11434/api/tags", timeout=2)
        if resp.status_code == 200:
            available.append("Ollama (local)")
    except:
        pass

    print(f"Available LLMs: {', '.join(available) if available else 'NONE'}")

    if not available:
        print("\n❌ No LLMs configured!")
        print("\nConfigure at least one:")
        print("  export GEMINI_API_KEY='...'")
        print("  export OPENAI_API_KEY='...'")
        print("  export ANTHROPIC_API_KEY='...'")
        print("  # Or run: ollama serve")
        sys.exit(1)

    print("\n" + "=" * 70)
    print(" BUILDING LLM ORCHESTRATOR")
    print("=" * 70)

    # Build orchestrator with all available LLMs
    orchestrator = build_orchestrator_from_env()
    status = orchestrator.get_status()

    print(f"\n✅ Total LLMs configured: {status['total_configured']}")
    print(f"✅ Active LLMs: {status['active']}")
    print(f"   Available by role:")
    for role, count in status['available_by_role'].items():
        print(f"     - {role}: {count}")

    if status['active'] == 0:
        print("\n❌ No active LLMs after initialization")
        sys.exit(1)

    print("\n" + "=" * 70)
    print(" STARTING MULTI-AGENT PENTEST")
    print("=" * 70)
    print("""
The system will deploy 4 specialized agents:

  🔍 ReconAgent      - Maps attack surface
  💥 ExploitAgent    - Finds & exploits vulnerabilities
  🧐 AnalysisAgent   - Validates and prioritizes findings
  📄 ReportAgent     - Generates final report

Each agent can use different LLMs (best for each task).
Automatic fallback if any LLM fails.
22+ pentesting tools available.
""")

    # Create multi-agent system
    multi_agent = MultiAgentOrchestrator(
        target_url=TARGET_URL,
        llm_orchestrator=orchestrator,
        log_callback=lambda level, msg: print(f"  [{level}] {msg}")
    )

    # Run full audit
    try:
        result = multi_agent.run_full_audit()

        # Results
        print("\n" + "=" * 70)
        print(" AUDIT COMPLETED")
        print("=" * 70)

        print(f"\nStatus: {result['status']}")
        print(f"Validated Findings: {len(result['findings'])}")
        print(f"Raw Findings: {len(result['raw_findings'])}")

        # Statistics
        stats = result['statistics']
        print(f"\nStatistics:")
        print(f"  Total Time: {stats.get('total_time_seconds', 'N/A')}s")
        if 'recon' in stats:
            print(f"  Recon: {stats['recon']['iterations']} iterations, "
                  f"tools used: {sum(stats['recon']['tools_used'].values())}")
        if 'exploit' in stats:
            print(f"  Exploit: {stats['exploit']['iterations']} iterations, "
                  f"raw findings: {stats['exploit']['raw_findings']}")
        if 'analysis' in stats:
            print(f"  Analysis: {stats['analysis']['validated_count']} validated")

        # Show findings by severity
        if result['findings']:
            by_severity = {}
            for f in result['findings']:
                sev = f.get('severity', 'unknown').upper()
                by_severity.setdefault(sev, []).append(f)

            print(f"\n{'=' * 70}")
            print(" FINDINGS BY SEVERITY")
            print('=' * 70)

            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if severity in by_severity:
                    items = by_severity[severity]
                    print(f"\n[{severity}] - {len(items)} finding(s)")
                    print("-" * 50)
                    for f in items:
                        print(f"  • {f.get('title', 'Unknown')}")
                        desc = f.get('description', '')[:120]
                        if desc:
                            print(f"    {desc}...")
                        if f.get('cvss_score'):
                            print(f"    CVSS: {f['cvss_score']}")

        # Save full results
        output_file = "multi_agent_result.json"
        with open(output_file, "w") as f:
            json.dump({
                "status": result["status"],
                "findings": result["findings"],
                "raw_findings": result["raw_findings"],
                "recon_results": result["recon_results"],
                "statistics": result["statistics"],
                "llm_status": result.get("llm_status", {}),
            }, f, indent=2, default=str)
        print(f"\n📝 Full results: {output_file}")

        # Save report
        if result.get("report"):
            report_file = "pentest_report.md"
            with open(report_file, "w") as f:
                f.write(result["report"])
            print(f"📄 Report: {report_file}")

        # Final LLM status
        print(f"\n{'=' * 70}")
        print(" LLM USAGE")
        print('=' * 70)
        final_status = result.get("llm_status", {})
        print(f"Active LLMs: {final_status.get('active', 'N/A')}")
        if final_status.get('disabled'):
            print(f"Failed during audit: {final_status['disabled']}")

    except KeyboardInterrupt:
        print("\n\n⚠️  Audit interrupted")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
