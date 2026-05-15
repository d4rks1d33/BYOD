from __future__ import annotations
import math
from dataclasses import dataclass
from typing import Optional


_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_NONE = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_C = {"N": 0.0, "L": 0.22, "H": 0.56}
_I = {"N": 0.0, "L": 0.22, "H": 0.56}
_A = {"N": 0.0, "L": 0.22, "H": 0.56}


@dataclass
class CVSSv3Score:
    base_score: float
    severity: str
    vector_string: str


def calculate_cvss_v3(vector: str) -> Optional[CVSSv3Score]:
    """Parse a CVSSv3.1 vector string and return base score."""
    try:
        parts = dict(p.split(":") for p in vector.split("/") if ":" in p)

        av = _AV.get(parts.get("AV", ""), 0.85)
        ac = _AC.get(parts.get("AC", ""), 0.77)
        scope_changed = parts.get("S", "U") == "C"
        pr = (_PR_CHANGED if scope_changed else _PR_NONE).get(parts.get("PR", ""), 0.62)
        ui = _UI.get(parts.get("UI", ""), 0.85)
        c = _C.get(parts.get("C", ""), 0.0)
        i = _I.get(parts.get("I", ""), 0.0)
        a = _A.get(parts.get("A", ""), 0.0)

        iss = 1 - (1 - c) * (1 - i) * (1 - a)

        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            base = 0.0
        elif scope_changed:
            base = min(1.08 * (impact + exploitability), 10)
        else:
            base = min(impact + exploitability, 10)

        base = math.ceil(base * 10) / 10

        if base == 0:
            severity = "none"
        elif base < 4.0:
            severity = "low"
        elif base < 7.0:
            severity = "medium"
        elif base < 9.0:
            severity = "high"
        else:
            severity = "critical"

        return CVSSv3Score(base_score=base, severity=severity, vector_string=vector)
    except Exception:
        return None


class CVSSCalculator:
    @staticmethod
    def from_vector(vector: str) -> Optional[CVSSv3Score]:
        return calculate_cvss_v3(vector)

    @staticmethod
    def severity_from_score(score: float) -> str:
        if score == 0:
            return "none"
        if score < 4.0:
            return "low"
        if score < 7.0:
            return "medium"
        if score < 9.0:
            return "high"
        return "critical"
