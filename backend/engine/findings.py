"""
WireCub finding model.

A finding is one thing worth an analyst's attention. Every finding carries
its own explanation, so the report stands on its own without the analyst
having to look up what a detection means.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}


@dataclass(slots=True)
class Finding:
    """One detection result."""

    id: str                       # stable rule id, e.g. "c2.beacon"
    title: str                    # short headline
    severity: str                 # critical | high | medium | low | info
    category: str                 # grouping for the UI
    description: str              # what was observed
    why: str                      # why this matters
    recommendation: str           # what the analyst should do next
    confidence: str = "medium"    # high | medium | low
    mitre: list[str] = field(default_factory=list)      # technique ids
    mitre_names: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)  # packets, hosts, values
    hosts: list[str] = field(default_factory=list)      # involved IPs
    count: int = 1                # how many times observed
    first_seen: float | None = None
    last_seen: float | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity_rank"] = SEVERITY_ORDER.get(self.severity, 0)
        return data


MITRE_NAMES = {
    "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols",
    "T1071.004": "DNS",
    "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1048.003": "Exfiltration Over Unencrypted Protocol",
    "T1046": "Network Service Discovery",
    "T1018": "Remote System Discovery",
    "T1021": "Remote Services",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.001": "Remote Desktop Protocol",
    "T1110": "Brute Force",
    "T1110.003": "Password Spraying",
    "T1557": "Adversary-in-the-Middle",
    "T1557.002": "ARP Cache Poisoning",
    "T1572": "Protocol Tunneling",
    "T1573": "Encrypted Channel",
    "T1568": "Dynamic Resolution",
    "T1568.002": "Domain Generation Algorithms",
    "T1090": "Proxy",
    "T1090.003": "Multi-hop Proxy",
    "T1105": "Ingress Tool Transfer",
    "T1190": "Exploit Public-Facing Application",
    "T1059": "Command and Scripting Interpreter",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Credentials In Files",
    "T1040": "Network Sniffing",
    "T1095": "Non-Application Layer Protocol",
    "T1571": "Non-Standard Port",
    "T1496": "Resource Hijacking",
    "T1550": "Use Alternate Authentication Material",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1558.003": "Kerberoasting",
    "T1187": "Forced Authentication",
    "T1499": "Endpoint Denial of Service",
    "T1595": "Active Scanning",
    "T1583": "Acquire Infrastructure",
    "T1102": "Web Service",
    "T1036": "Masquerading",
    "T1055": "Process Injection",
    "T1110.002": "Password Cracking",
    "T1210": "Exploitation of Remote Services",
    "T1486": "Data Encrypted for Impact",
    "T1505": "Server Software Component",
    "T1550.001": "Application Access Token",
    "T1566.002": "Spearphishing Link",
    "T1583.001": "Domains",
}


def make_finding(
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    why: str,
    recommendation: str,
    *,
    confidence: str = "medium",
    mitre: list[str] | None = None,
    evidence: list[dict] | None = None,
    hosts: list[str] | None = None,
    count: int = 1,
    first_seen: float | None = None,
    last_seen: float | None = None,
) -> Finding:
    mitre = mitre or []
    return Finding(
        id=rule_id,
        title=title,
        severity=severity,
        category=category,
        description=description,
        why=why,
        recommendation=recommendation,
        confidence=confidence,
        mitre=mitre,
        mitre_names=[MITRE_NAMES.get(m, m) for m in mitre],
        evidence=evidence or [],
        hosts=hosts or [],
        count=count,
        first_seen=first_seen,
        last_seen=last_seen,
    )


def risk_score(findings: list[Finding]) -> int:
    """
    Roll findings up into a single 0-100 capture risk score.

    Straight addition saturates almost immediately: any capture with a few
    serious findings lands on 100 and stops being comparable to anything
    else. Instead each finding is treated as an independent contribution
    and combined the way independent probabilities are, so the score
    approaches 100 without ever quite reaching it and keeps resolving
    differences between bad captures and much worse ones.

    Two adjustments stop one rule dominating. Repeats of the same rule
    decay, because ten instances of one detection is one problem seen ten
    times rather than ten problems. Confidence scales the contribution, so
    a low-confidence heuristic cannot push a capture into the red on its
    own.
    """
    # Contribution of a single high-confidence finding at each severity.
    weights = {
        "critical": 0.42,
        "high": 0.24,
        "medium": 0.10,
        "low": 0.035,
        "info": 0.0,
    }
    confidence_factor = {"high": 1.0, "medium": 0.75, "low": 0.5}

    seen: dict[str, int] = {}
    remaining = 1.0

    # Highest severity first, so the decay applies to the weaker repeats
    # rather than to the finding that matters most.
    ordered = sorted(
        findings,
        key=lambda f: -(SEVERITY_WEIGHT.get(f.severity, 0)),
    )

    for finding in ordered:
        base = weights.get(finding.severity, 0.0)
        if not base:
            continue
        base *= confidence_factor.get(finding.confidence, 0.75)

        # Each further finding from the same rule family contributes half
        # of the one before it.
        family = finding.id.split(".")[0]
        occurrence = seen.get(family, 0)
        seen[family] = occurrence + 1
        base *= 0.5 ** occurrence

        remaining *= (1.0 - base)

    return max(0, min(100, round((1.0 - remaining) * 100)))


def risk_band(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "elevated"
    if score >= 10:
        return "low"
    return "clean"


def risk_verdict(score: int, findings: list[Finding]) -> str:
    """One sentence an analyst can paste into a ticket."""
    band = risk_band(score)
    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")

    if band == "clean":
        return "No malicious activity detected. Traffic looks routine."
    if band == "low":
        return (
            "Mostly routine traffic with minor hygiene issues. "
            "No evidence of compromise."
        )
    if band == "elevated":
        return (
            "Suspicious activity present. Worth an analyst's review, "
            "but no single conclusive indicator of compromise."
        )
    if band == "high":
        return (
            f"Strong indicators of malicious activity ({crit} critical, "
            f"{high} high). Investigate the involved hosts."
        )
    return (
        f"Capture shows likely compromise ({crit} critical, {high} high). "
        "Treat involved hosts as suspect and begin incident response."
    )
