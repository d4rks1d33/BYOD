import re

content = """
Notes
**FINDING: [CRITICAL] IDOR – Arbitrary Forum View**  
- **Endpoint:** `http://testasp.vulnweb.com/showforum.asp?id=`  
- **Parameter:** `id`  
- **Payload:** `id=0` → `id=1`  
- **Evidence:** Returned forum pages for multiple IDs (0, 1, 2) without authentication, confirming that any forum can be viewed by guessing an ID.  
- **Impact:** An attacker can enumerate all forum topics, read private discussion, and use this as a foothold for further attacks.  
- **CVSS:** 9.8 (High Impact, High Exploit critical

SQL Injection – Data Extraction**
No endpoint

Description
**Endpoint:** `http://testasp.vulnweb.com/showforum.asp?id=`

CWE
N/A

Status
new

Detected At
May 14, 10:40 PM

Notes
**FINDING: [CRITICAL] SQL Injection – Data Extraction**  
- **Endpoint:** `http://testasp.vulnweb.com/showforum.asp?id=`  
- **Parameter:** `id`  
- **Payload:** `id=0` → `id=1`  
- **Evidence:** Returned forum pages for multiple IDs (0, 1, 2) without authentication, confirming that any forum can be viewed by guessing an ID.  
- **Impact:** An attacker can enumerate all forum topics, read private discussion, and use this as a foothold for further attacks.  
- **CVSS:** 9.8 (High Impact, High Exploit ademas de que no veo la PoC lista para probar y validar
"""

# The user's log shows that the second finding is even more broken.
# It doesn't have the FINDING: [SEVERITY] format!
# It just says:
# SQL Injection – Data Extraction**
# No endpoint
# ...
# **FINDING: [CRITICAL] SQL Injection – Data Extraction**

# Wait, looking at the log again:
# [22:23:38] [ERROR] [orchestrator] Multi-agent audit failed: unexpected indent (multi_agent_system.py, line 455)
# This error happened during the scan.

# If the LLM produces:
# **FINDING: [CRITICAL] IDOR – Arbitrary Forum View**  
# - **Endpoint:** `...`
# This is what I'm targeting.

# Let's use a more robust splitter.
# We split by any line that looks like a finding header.
blocks = re.split(r'(?=\*?\*?FINDING:)', content)

print(f"Total blocks found: {len(blocks)}")

for i, block in enumerate(blocks):
    block = block.strip()
    if not block or not block.startswith("FINDING:"):
        continue
    
    print(f"--- Block {i} ---")
    print(f"Block content: {repr(block)}")
    
    # Parse header: FINDING: [SEVERITY] TITLE - DESCRIPTION
    # We allow optional ** around FINDING
    header_match = re.search(r'\*?\*?FINDING:\s*\[(?P<severity>CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(?P<title>.+?)\s*-\s*(?P<description>.+)', block)
    if not header_match:
        print("  FAILED to match header")
        continue
        
    severity = header_match.group("severity").strip().upper()
    title = header_match.group("title").strip().replace("**", "").strip()
    description = header_match.group("description").strip().replace("**", "").strip()
    
    print(f"  Header: {severity}, {title}, {description}")

    # Parse details
    details = {}
    lines = block.split('\n')
    for line in lines[1:]:
        line = line.strip()
        if not line or line.lower().startswith("details:"):
            continue
        
        if line.startswith("-"):
            line = line[1:].strip()
            if ":" in line:
                key_part, value_part = line.split(":", 1)
                key = key_part.replace("*", "").strip().lower().replace(" ", "_")
                value = value_part.strip()
                
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
    
    print(f"  Details: {details}")
