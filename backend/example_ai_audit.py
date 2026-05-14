#!/usr/bin/env python3
"""
Example: Run AI-driven security audit directly from Python

This demonstrates how to use the AI Auditor without the full AutoPentest stack.
"""
import os
import sys
import logging
from services.llm_provider import get_llm_provider
from services.ai_auditor import AIAuditor

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def main():
    # Configuration
    TARGET_URL = "http://testaspnet.vulnweb.com"  # Vulnerable test site
    MAX_ITERATIONS = 30

    print("=" * 60)
    print("AI-NATIVE PENETRATION TESTING DEMO")
    print("=" * 60)
    print(f"\nTarget: {TARGET_URL}")
    print("Provider: Gemini 2.0 Flash")
    print(f"Max Iterations: {MAX_ITERATIONS}\n")

    # Check for API key
    if not os.getenv("GEMINI_API_KEY"):
        print("❌ Error: GEMINI_API_KEY not set")
        print("\nSet it with:")
        print("  export GEMINI_API_KEY='your-key-here'")
        print("\nOr use another provider:")
        print("  export OPENAI_API_KEY='your-key'")
        print("  export ANTHROPIC_API_KEY='your-key'")
        sys.exit(1)

    # Initialize LLM provider
    print("🧠 Initializing LLM provider...")
    try:
        llm = get_llm_provider("gemini", "gemini-2.0-flash-exp")
        print("✅ LLM initialized: Gemini 2.0 Flash\n")
    except Exception as e:
        print(f"❌ Failed to initialize LLM: {e}")
        sys.exit(1)

    # Create AI Auditor
    print("🤖 Creating AI Auditor...")
    auditor = AIAuditor(
        llm_provider=llm,
        target_url=TARGET_URL,
        max_iterations=MAX_ITERATIONS,
        log_callback=lambda level, msg: print(f"[{level}] {msg}")
    )
    print("✅ AI Auditor ready\n")

    # Run the audit
    print("=" * 60)
    print("STARTING AUTONOMOUS SECURITY AUDIT")
    print("=" * 60)
    print("\nThe AI will now autonomously:")
    print("  1. Understand the application")
    print("  2. Identify attack surfaces")
    print("  3. Test for vulnerabilities")
    print("  4. Create PoC exploits")
    print("  5. Report findings")
    print("\nThis may take several minutes...\n")

    try:
        result = auditor.run_audit()

        # Print results
        print("\n" + "=" * 60)
        print("AUDIT COMPLETED")
        print("=" * 60)

        print(f"\nStatus: {result['status']}")
        print(f"Iterations: {result['statistics']['iterations']}")
        print(f"Time: {result['statistics']['time_elapsed_seconds']}s")
        print(f"Tools Used: {result['statistics']['tools_used']}")

        # Print findings
        findings = result['findings']
        print(f"\n{'=' * 60}")
        print(f"FINDINGS: {len(findings)} total")
        print('=' * 60)

        if findings:
            # Group by severity
            by_severity = {}
            for finding in findings:
                sev = finding['severity'].upper()
                by_severity.setdefault(sev, []).append(finding)

            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if severity in by_severity:
                    print(f"\n{severity} ({len(by_severity[severity])})")
                    print("-" * 40)
                    for f in by_severity[severity]:
                        print(f"  • {f['title']}")
                        print(f"    {f['description'][:100]}...")
                        if f.get('cvss_score'):
                            print(f"    CVSS: {f['cvss_score']}")
                        print()
        else:
            print("\n✅ No vulnerabilities found!")

        print("=" * 60)

        # Save results to file
        import json
        output_file = "ai_audit_result.json"
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\n📝 Full results saved to: {output_file}")

    except KeyboardInterrupt:
        print("\n\n⚠️  Audit interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Audit failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
