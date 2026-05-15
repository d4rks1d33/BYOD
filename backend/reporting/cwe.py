from __future__ import annotations
from typing import Optional
from dataclasses import dataclass


@dataclass
class CWEEntry:
    id: str
    name: str
    description: str
    url: str


_CWE_DB: dict[str, CWEEntry] = {
    "CWE-89": CWEEntry("CWE-89", "SQL Injection", "Improper neutralization of special elements used in an SQL command.", "https://cwe.mitre.org/data/definitions/89.html"),
    "CWE-79": CWEEntry("CWE-79", "Cross-site Scripting", "Improper neutralization of input during web page generation.", "https://cwe.mitre.org/data/definitions/79.html"),
    "CWE-22": CWEEntry("CWE-22", "Path Traversal", "Improper limitation of a pathname to a restricted directory.", "https://cwe.mitre.org/data/definitions/22.html"),
    "CWE-78": CWEEntry("CWE-78", "OS Command Injection", "Improper neutralization of special elements used in an OS command.", "https://cwe.mitre.org/data/definitions/78.html"),
    "CWE-94": CWEEntry("CWE-94", "Code Injection", "Improper control of generation of code.", "https://cwe.mitre.org/data/definitions/94.html"),
    "CWE-287": CWEEntry("CWE-287", "Improper Authentication", "When an actor claims to have a given identity, the software does not prove that the claim is correct.", "https://cwe.mitre.org/data/definitions/287.html"),
    "CWE-918": CWEEntry("CWE-918", "Server-Side Request Forgery", "The server fetches a URL from a user-controlled source.", "https://cwe.mitre.org/data/definitions/918.html"),
    "CWE-200": CWEEntry("CWE-200", "Exposure of Sensitive Information", "The product exposes sensitive information to an actor not explicitly authorized.", "https://cwe.mitre.org/data/definitions/200.html"),
    "CWE-798": CWEEntry("CWE-798", "Hard-coded Credentials", "The software contains hard-coded credentials.", "https://cwe.mitre.org/data/definitions/798.html"),
    "CWE-327": CWEEntry("CWE-327", "Broken Cryptographic Algorithm", "Use of a broken or risky cryptographic algorithm.", "https://cwe.mitre.org/data/definitions/327.html"),
    "CWE-306": CWEEntry("CWE-306", "Missing Authentication", "The software does not perform authentication for functionality that requires a provable user identity.", "https://cwe.mitre.org/data/definitions/306.html"),
    "CWE-384": CWEEntry("CWE-384", "Session Fixation", "Authenticating a user, or otherwise establishing a new user session, without invalidating any existing session identifier.", "https://cwe.mitre.org/data/definitions/384.html"),
    "CWE-502": CWEEntry("CWE-502", "Deserialization of Untrusted Data", "Deserialization of untrusted data.", "https://cwe.mitre.org/data/definitions/502.html"),
    "CWE-611": CWEEntry("CWE-611", "Improper Restriction of XML External Entity Reference", "XXE vulnerability.", "https://cwe.mitre.org/data/definitions/611.html"),
    "CWE-1021": CWEEntry("CWE-1021", "Improper Restriction of Rendered UI Layers", "Clickjacking.", "https://cwe.mitre.org/data/definitions/1021.html"),
}


class CWELookup:
    @staticmethod
    def get(cwe_id: str) -> Optional[CWEEntry]:
        normalized = cwe_id.upper().strip()
        if not normalized.startswith("CWE-"):
            normalized = f"CWE-{normalized}"
        return _CWE_DB.get(normalized)

    @staticmethod
    def description(cwe_id: str) -> str:
        entry = CWELookup.get(cwe_id)
        return entry.description if entry else f"See {cwe_id} at https://cwe.mitre.org"

    @staticmethod
    def name(cwe_id: str) -> str:
        entry = CWELookup.get(cwe_id)
        return entry.name if entry else cwe_id
