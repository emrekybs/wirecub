"""
WireCub detection modules.

Each module reads the tables the analyzer built and appends Findings.
Modules never touch the capture file, so adding one costs no parse time.

Detections are behavioural rather than signature-based: they look for the
shape of malicious activity (regular callbacks, encoded DNS labels, fan-out
scanning) instead of matching known-bad strings. That catches tooling that
has never been seen before, at the cost of needing scoring and thresholds
to keep false positives down.
"""

from __future__ import annotations

import ipaddress
import re
import statistics
import urllib.parse
from collections import Counter, defaultdict
from typing import Callable

from .findings import make_finding
from .protocols import byte_entropy, shannon_entropy
from .services import MINING_PORTS, is_cleartext, is_lateral

MAX_EVIDENCE = 12


def run_all(result, deep: bool = False, progress: Callable | None = None):
    """Run every module, tolerating failure in any one of them."""
    from . import detections_ext as ext

    modules = [
        ("Scanning and reconnaissance", detect_scanning),
        ("Command and control", detect_beaconing),
        ("DNS abuse", detect_dns_abuse),
        ("Web attacks", detect_web_attacks),
        ("Cleartext credentials", detect_cleartext),
        ("Data exfiltration", detect_exfiltration),
        ("Lateral movement", detect_lateral_movement),
        ("Protocol tunneling", detect_tunneling),
        ("TLS anomalies", detect_tls_anomalies),
        ("Spoofing", detect_spoofing),
        ("IPv6 abuse", detect_ipv6_abuse),
        ("Suspicious infrastructure", detect_suspicious_infra),
        ("Malware delivery", detect_malware_delivery),
        ("Anonymity networks", ext.detect_anonymity_networks),
        ("Windows authentication", ext.detect_ntlm_attacks),
        ("Kerberos attacks", ext.detect_kerberos_attacks),
        ("SMB posture", ext.detect_smb_issues),
        ("Ransomware", ext.detect_ransomware),
        ("Industrial control", ext.detect_ics_activity),
        ("IoT exposure", ext.detect_iot_issues),
        ("Wireless attacks", ext.detect_wifi_attacks),
        ("QUIC", ext.detect_quic_usage),
        ("Transferred files", ext.detect_malicious_files),
        ("VoIP telephony", ext.detect_voip),
        ("Analysis environment", ext.detect_simulated_environment),
        ("Lookalike domains", ext.detect_lookalike_domains),
        ("Captured credentials", ext.detect_captured_credentials),
        ("Capture hygiene", detect_capture_issues),
    ]

    step = 16.0 / len(modules)
    for index, (name, func) in enumerate(modules):
        if progress:
            progress("detecting", 78.0 + index * step, f"Checking: {name}")
        try:
            func(result, deep)
        except Exception as exc:  # a broken rule must not kill the run
            result.errors[f"Detection module '{name}' failed: {exc}"] += 1


def _ev(rows: list[dict]) -> list[dict]:
    return rows[:MAX_EVIDENCE]


def _is_broadcast_or_multicast(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_multicast or str(addr).endswith(".255")
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Scanning and reconnaissance
# ---------------------------------------------------------------------------

def detect_scanning(r, deep: bool):
    # --- vertical scan: one source hitting many ports on one target ---
    port_fanout: dict[tuple, set[int]] = defaultdict(set)
    host_fanout: dict[tuple, set[str]] = defaultdict(set)
    syn_only: dict[str, int] = Counter()
    syn_answered: dict[str, int] = Counter()

    for flow in r.flows.values():
        if flow.proto not in ("TCP", "UDP"):
            continue
        # Direction is what makes a scan a scan, so use the recorded
        # initiator rather than the order-independent flow key.
        src = flow.initiator or flow.src
        dst = flow.responder or flow.dst
        port = flow.responder_port or flow.dport
        port_fanout[(src, dst)].add(port)
        host_fanout[(src, port)].add(dst)

        if flow.syn_count and not flow.synack_count:
            syn_only[src] += 1
        elif flow.synack_count:
            syn_answered[src] += 1

    vertical = [
        (pair, ports) for pair, ports in port_fanout.items() if len(ports) >= 25
    ]
    if vertical:
        vertical.sort(key=lambda kv: len(kv[1]), reverse=True)
        top = vertical[0]
        hosts = sorted({pair[0] for pair, _ in vertical})
        r.findings.append(
            make_finding(
                "recon.port_scan",
                "Port scan against one or more hosts",
                "high" if len(top[1]) >= 100 else "medium",
                "Reconnaissance",
                f"{len(vertical)} source/target pairs show a single host probing "
                f"many ports. The heaviest is {top[0][0]} contacting "
                f"{len(top[1])} distinct ports on {top[0][1]}.",
                "Port scanning is how an attacker maps what a target is running "
                "before choosing an exploit. On an internal network it usually "
                "means a host is already compromised and is looking for its next "
                "step.",
                "Confirm whether the source is an authorised vulnerability "
                "scanner. If it is not, isolate it and review what it connected "
                "to after the scan finished.",
                confidence="high" if len(top[1]) >= 100 else "medium",
                mitre=["T1046", "T1595"],
                hosts=hosts[:20],
                count=len(vertical),
                evidence=_ev(
                    [
                        {
                            "source": pair[0],
                            "target": pair[1],
                            "ports_probed": len(ports),
                            "sample_ports": sorted(ports)[:15],
                        }
                        for pair, ports in vertical[:MAX_EVIDENCE]
                    ]
                ),
            )
        )

    # --- horizontal sweep: one source hitting one port across many hosts ---
    horizontal = [
        (pair, targets) for pair, targets in host_fanout.items() if len(targets) >= 20
    ]
    if horizontal:
        horizontal.sort(key=lambda kv: len(kv[1]), reverse=True)
        top = horizontal[0]
        r.findings.append(
            make_finding(
                "recon.network_sweep",
                "Network sweep across many hosts",
                "high",
                "Reconnaissance",
                f"{top[0][0]} contacted port {top[0][1]} on {len(top[1])} "
                f"different hosts. {len(horizontal)} such sweeps were seen.",
                "Sweeping one port across a subnet is how an attacker finds every "
                "machine running a particular service, such as SMB or RDP, to "
                "target them all at once.",
                "Identify the sweeping host and the service it was looking for. "
                "If the port is SMB or RDP, treat this as probable lateral "
                "movement preparation and check those targets for follow-on "
                "authentication attempts.",
                confidence="high",
                mitre=["T1046", "T1018"],
                hosts=sorted({pair[0] for pair, _ in horizontal})[:20],
                count=len(horizontal),
                evidence=_ev(
                    [
                        {
                            "source": pair[0],
                            "port": pair[1],
                            "hosts_contacted": len(targets),
                            "sample_targets": sorted(targets)[:10],
                        }
                        for pair, targets in horizontal[:MAX_EVIDENCE]
                    ]
                ),
            )
        )

    # --- unanswered SYN ratio: stealth scanning or dead infrastructure ---
    for src, unanswered in syn_only.items():
        answered = syn_answered.get(src, 0)
        total = unanswered + answered
        if total >= 40 and unanswered / total > 0.85:
            r.findings.append(
                make_finding(
                    "recon.syn_unanswered",
                    "High proportion of unanswered connection attempts",
                    "medium",
                    "Reconnaissance",
                    f"{src} opened {total} TCP connections and {unanswered} "
                    f"({unanswered / total:.0%}) received no reply.",
                    "Connection attempts that go unanswered usually mean the "
                    "target ports are closed or filtered, which is the normal "
                    "outcome of a scan. It can also indicate malware retrying a "
                    "dead command and control server.",
                    "Check whether the destinations are legitimate services that "
                    "have gone offline. If the destinations are external and "
                    "unfamiliar, treat the source as possibly infected.",
                    confidence="medium",
                    mitre=["T1046"],
                    hosts=[src],
                    count=unanswered,
                    evidence=[
                        {
                            "source": src,
                            "unanswered": unanswered,
                            "answered": answered,
                        }
                    ],
                )
            )

    r.scan_stats = {
        "vertical_scans": len(vertical),
        "horizontal_sweeps": len(horizontal),
    }


# ---------------------------------------------------------------------------
# Beaconing and command and control
# ---------------------------------------------------------------------------

def detect_beaconing(r, deep: bool):
    """
    Score every flow for regularity.

    Automated callbacks produce evenly spaced connections. Human-driven
    traffic does not. The coefficient of variation of the intervals
    separates the two, and the median absolute deviation confirms it
    without being skewed by a single long gap.
    """
    from .analyzer import summarise_intervals

    candidates = []

    # Group by (source, destination, port): a beacon may reconnect each time,
    # producing many short flows rather than one long one.
    grouped: dict[tuple, list[float]] = defaultdict(list)
    grouped_bytes: dict[tuple, int] = Counter()
    grouped_service: dict[tuple, str] = {}

    for flow in r.flows.values():
        if flow.proto not in ("TCP", "UDP"):
            continue
        dst = flow.responder or flow.dst
        if _is_broadcast_or_multicast(dst):
            continue
        key = (flow.initiator or flow.src, dst, flow.responder_port or flow.dport)
        # Use connection events, not raw packet times: a callback that sends
        # three packets per check-in must count as one event, not three.
        grouped[key].extend(flow.connection_events)
        grouped_bytes[key] += flow.total_bytes
        grouped_service[key] = flow.service

    for key, times in grouped.items():
        if len(times) < 8:
            continue
        stats = summarise_intervals(times)
        if not stats or stats["count"] < 7:
            continue

        # Ignore sub-second chatter: that is a session, not a beacon.
        if stats["median"] < 0.9:
            continue
        # Ignore intervals so long the sample cannot support a conclusion.
        if stats["median"] > 86400:
            continue

        cv = stats["cv"]
        mad_ratio = stats["mad_ratio"]

        # Two independent regularity measures must agree.
        if cv > 0.55 or mad_ratio > 0.45:
            continue

        src, dst, dport = key
        total_bytes = grouped_bytes[key]
        avg_bytes = total_bytes / max(1, len(times))

        score = 0
        if cv < 0.15:
            score += 40
        elif cv < 0.3:
            score += 28
        else:
            score += 15

        if mad_ratio < 0.1:
            score += 25
        elif mad_ratio < 0.25:
            score += 15

        if stats["count"] >= 40:
            score += 20
        elif stats["count"] >= 20:
            score += 12
        elif stats["count"] >= 12:
            score += 6

        # Small, uniform payloads are typical of check-in traffic.
        if avg_bytes < 2000:
            score += 10

        dst_host = r.hosts.get(dst)
        external = dst_host is not None and not dst_host.is_private
        if external:
            score += 10

        if score < 55:
            continue

        candidates.append(
            {
                "source": src,
                "destination": dst,
                "port": dport,
                "service": grouped_service.get(key, ""),
                "connections": len(times),
                "interval_seconds": round(stats["median"], 2),
                "jitter_cv": round(cv, 3),
                "mad_ratio": round(mad_ratio, 3),
                "total_bytes": total_bytes,
                "avg_bytes_per_connection": round(avg_bytes),
                "external": external,
                "score": score,
                "first_seen": min(times),
                "last_seen": max(times),
            }
        )

    if not candidates:
        return

    candidates.sort(key=lambda c: -c["score"])
    strong = [c for c in candidates if c["score"] >= 75 and c["external"]]
    weak = [c for c in candidates if c not in strong]

    if strong:
        top = strong[0]
        r.findings.append(
            make_finding(
                "c2.beacon",
                "Regular automated callbacks to an external host",
                "critical",
                "Command and control",
                f"{len(strong)} host pairs connect on a fixed schedule. The "
                f"clearest is {top['source']} reaching {top['destination']} "
                f"on port {top['port']} every {top['interval_seconds']}s across "
                f"{top['connections']} connections, with only "
                f"{top['jitter_cv']:.1%} timing variation.",
                "Traffic this regular is generated by software on a timer, not "
                "by a person. Malware checks in with its operator on a fixed "
                "interval to receive commands, and that heartbeat is what this "
                "pattern looks like. Legitimate software also polls, so the "
                "destination is what decides the verdict.",
                "Look up the destination address and check whether it belongs to "
                "a service the source host is expected to use. If it does not, "
                "treat the source as compromised: capture volatile memory, "
                "identify the process holding the connection, and block the "
                "destination at the perimeter.",
                confidence="high",
                mitre=["T1071", "T1573", "T1102"],
                hosts=sorted({c["source"] for c in strong} | {c["destination"] for c in strong})[:20],
                count=len(strong),
                first_seen=min(c["first_seen"] for c in strong),
                last_seen=max(c["last_seen"] for c in strong),
                evidence=_ev(strong),
            )
        )

    if weak:
        r.findings.append(
            make_finding(
                "c2.periodic_traffic",
                "Periodic connections worth reviewing",
                "medium" if any(c["external"] for c in weak) else "low",
                "Command and control",
                f"{len(weak)} host pairs show repeating connection intervals "
                "that are regular but less precise than a typical beacon.",
                "Software updaters, monitoring agents and mail clients all poll "
                "on a schedule, so this pattern alone is not malicious. It is "
                "listed so you can confirm each destination is expected rather "
                "than assume it.",
                "Scan the destinations for anything unfamiliar. Known update and "
                "telemetry endpoints can be dismissed; unrecognised external "
                "addresses deserve the same treatment as a confirmed beacon.",
                confidence="low",
                mitre=["T1071"],
                hosts=sorted({c["source"] for c in weak})[:20],
                count=len(weak),
                evidence=_ev(weak),
            )
        )


# ---------------------------------------------------------------------------
# DNS abuse: tunneling, DGA, exfiltration
# ---------------------------------------------------------------------------

def _registered_domain(name: str) -> str:
    parts = name.rstrip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    # Handle common two-part suffixes without a public suffix list.
    two_part = {"co.uk", "com.tr", "co.jp", "com.au", "com.br", "co.in",
                "org.uk", "net.tr", "gov.uk", "ac.uk", "com.cn", "edu.tr"}
    if ".".join(parts[-2:]) in two_part and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def detect_dns_abuse(r, deep: bool):
    if not r.dns_records:
        return

    by_domain: dict[str, set[str]] = defaultdict(set)
    by_domain_client: dict[str, set[str]] = defaultdict(set)
    domain_types: dict[str, Counter] = defaultdict(Counter)
    domain_lengths: dict[str, list[int]] = defaultdict(list)
    domain_entropy: dict[str, list[float]] = defaultdict(list)
    nxdomain_by_client: Counter = Counter()
    queries_by_client: Counter = Counter()
    first_seen: dict[str, float] = {}

    for rec in r.dns_records:
        client = rec["src"] if not rec["is_response"] else rec["dst"]
        for q in rec["queries"]:
            name = q["name"].lower().rstrip(".")
            if not name or "." not in name:
                continue
            domain = _registered_domain(name)
            subdomain = name[: -len(domain)].rstrip(".")

            if not rec["is_response"]:
                queries_by_client[client] += 1
                by_domain[domain].add(subdomain)
                by_domain_client[domain].add(client)
                domain_types[domain][q["type"]] += 1
                if subdomain:
                    domain_lengths[domain].append(len(subdomain))
                    longest_label = max(
                        (len(p) for p in subdomain.split(".")), default=0
                    )
                    if longest_label >= 12:
                        domain_entropy[domain].append(shannon_entropy(subdomain))
                first_seen.setdefault(domain, rec["ts"])

        if rec["is_response"] and rec["rcode"] == "NXDOMAIN":
            nxdomain_by_client[rec["dst"]] += 1

    # --- DNS tunneling ---
    tunnels = []
    for domain, subs in by_domain.items():
        if len(subs) < 25:
            continue
        lengths = domain_lengths.get(domain, [])
        if not lengths:
            continue
        avg_len = statistics.fmean(lengths)
        entropies = domain_entropy.get(domain, [])
        avg_entropy = statistics.fmean(entropies) if entropies else 0.0
        types = domain_types[domain]
        odd_type_share = (
            types.get("TXT", 0) + types.get("NULL", 0) + types.get("MX", 0)
        ) / max(1, sum(types.values()))

        score = 0
        if len(subs) >= 200:
            score += 35
        elif len(subs) >= 80:
            score += 25
        else:
            score += 12

        if avg_len >= 40:
            score += 30
        elif avg_len >= 25:
            score += 20
        elif avg_len >= 18:
            score += 10

        if avg_entropy >= 3.8:
            score += 25
        elif avg_entropy >= 3.2:
            score += 15

        if odd_type_share > 0.3:
            score += 20

        if score >= 55:
            tunnels.append(
                {
                    "domain": domain,
                    "unique_subdomains": len(subs),
                    "avg_subdomain_length": round(avg_len, 1),
                    "avg_entropy": round(avg_entropy, 2),
                    "record_types": dict(types.most_common(5)),
                    "clients": sorted(by_domain_client[domain])[:5],
                    "score": score,
                    "sample": sorted(subs, key=len, reverse=True)[:3],
                }
            )

    if tunnels:
        tunnels.sort(key=lambda t: -t["score"])
        top = tunnels[0]
        r.findings.append(
            make_finding(
                "dns.tunneling",
                "DNS tunneling",
                "critical" if top["score"] >= 80 else "high",
                "DNS abuse",
                f"{top['domain']} received queries for "
                f"{top['unique_subdomains']} distinct subdomains averaging "
                f"{top['avg_subdomain_length']} characters with "
                f"{top['avg_entropy']} bits of entropy per character.",
                "Long, high-entropy subdomains are how data is smuggled inside "
                "DNS queries. Because DNS is almost always allowed outbound, "
                "attackers use it as a covert channel for both command and "
                "control and data theft when other egress is blocked.",
                "Treat the querying hosts as compromised. Block the parent "
                "domain at the resolver, capture the full query log to estimate "
                "how much data left, and check whether the same domain appears "
                "in DNS logs from other hosts.",
                confidence="high",
                mitre=["T1071.004", "T1048", "T1572"],
                hosts=sorted({c for t in tunnels for c in t["clients"]})[:20],
                count=len(tunnels),
                evidence=_ev(tunnels),
            )
        )

    # --- DGA: many NXDOMAIN responses to one client ---
    for client, nx_count in nxdomain_by_client.items():
        total = queries_by_client.get(client, 0)
        if nx_count >= 40 and total and nx_count / total > 0.4:
            r.findings.append(
                make_finding(
                    "dns.dga",
                    "Repeated lookups for domains that do not exist",
                    "high",
                    "DNS abuse",
                    f"{client} received {nx_count} NXDOMAIN responses out of "
                    f"{total} queries ({nx_count / total:.0%}).",
                    "Malware that uses a domain generation algorithm computes "
                    "hundreds of candidate domain names and tries each until one "
                    "resolves. Most fail, producing exactly this burst of "
                    "NXDOMAIN responses. Misconfigured software can also cause "
                    "it, but rarely at this ratio.",
                    "Pull the failed domain names and check whether they look "
                    "algorithmically generated rather than mistyped. If they do, "
                    "the host is running malware that is trying to find its "
                    "controller, and any domain that did resolve is the live "
                    "command and control address.",
                    confidence="medium",
                    mitre=["T1568.002"],
                    hosts=[client],
                    count=nx_count,
                    evidence=[
                        {
                            "client": client,
                            "nxdomain_responses": nx_count,
                            "total_queries": total,
                            "failure_rate": f"{nx_count / total:.0%}",
                        }
                    ],
                )
            )

    # --- very high entropy single domains, a DGA signal without NXDOMAIN ---
    suspicious_names = []
    for domain in by_domain:
        label = domain.split(".")[0]
        if len(label) < 10:
            continue
        entropy = shannon_entropy(label)
        digits = sum(c.isdigit() for c in label) / len(label)
        vowels = sum(c in "aeiou" for c in label) / len(label)
        if entropy > 3.6 and vowels < 0.25:
            suspicious_names.append(
                {
                    "domain": domain,
                    "entropy": round(entropy, 2),
                    "vowel_ratio": round(vowels, 2),
                    "digit_ratio": round(digits, 2),
                    "clients": sorted(by_domain_client[domain])[:3],
                }
            )

    if len(suspicious_names) >= 3:
        r.findings.append(
            make_finding(
                "dns.random_domains",
                "Lookups for randomly structured domain names",
                "medium",
                "DNS abuse",
                f"{len(suspicious_names)} domains were queried whose names show "
                "the character distribution of machine-generated strings rather "
                "than words.",
                "Domains built by an algorithm have high character entropy and "
                "few vowels. Content delivery networks and tracking services "
                "also generate names this way, so this is a lead rather than a "
                "conclusion.",
                "Check whether the domains resolve to known infrastructure. "
                "Clusters registered recently and sharing an address range are "
                "far more suspicious than isolated results.",
                confidence="low",
                mitre=["T1568.002"],
                hosts=sorted({c for s in suspicious_names for c in s["clients"]})[:20],
                count=len(suspicious_names),
                evidence=_ev(suspicious_names),
            )
        )


# ---------------------------------------------------------------------------
# Web attacks
# ---------------------------------------------------------------------------

WEB_PATTERNS = [
    # (rule, category, weight, compiled regex)
    ("SQL injection: union select", "sqli", 40,
     re.compile(r"\bunion\b[\s/*]+\bselect\b", re.I)),
    ("SQL injection: tautology", "sqli", 35,
     re.compile(r"(\bor\b|\band\b)\s*['\"]?\s*\d+\s*=\s*\d+", re.I)),
    ("SQL injection: time based", "sqli", 45,
     re.compile(r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(", re.I)),
    ("SQL injection: metadata access", "sqli", 40,
     re.compile(r"information_schema|sysobjects|@@version|table_name", re.I)),
    ("SQL injection: stacked query", "sqli", 30,
     re.compile(r";\s*(drop|insert|update|delete)\s+", re.I)),
    ("Cross-site scripting: script tag", "xss", 35,
     re.compile(r"<\s*script[\s>]|<\s*/\s*script\s*>", re.I)),
    ("Cross-site scripting: event handler", "xss", 30,
     re.compile(r"\bon(error|load|mouseover|focus|click)\s*=", re.I)),
    ("Cross-site scripting: javascript scheme", "xss", 25,
     re.compile(r"javascript\s*:|data:text/html", re.I)),
    ("Path traversal", "lfi", 40,
     re.compile(r"(\.\./){2,}|(\.\.\\){2,}|%2e%2e[/%5c]", re.I)),
    ("Local file access", "lfi", 45,
     re.compile(r"/etc/(passwd|shadow|hosts)|boot\.ini|win\.ini", re.I)),
    ("PHP wrapper abuse", "lfi", 45,
     re.compile(r"php://(filter|input)|expect://|zip://", re.I)),
    ("Command injection", "cmdi", 45,
     re.compile(r"[;|`]\s*(cat|wget|curl|nc|bash|sh|powershell|whoami|id)\b", re.I)),
    ("Command injection: shell substitution", "cmdi", 40,
     re.compile(r"\$\(.*\)|`[^`]+`"),),
    ("Log4Shell / JNDI lookup", "rce", 60,
     re.compile(r"\$\{jndi:(ldap|rmi|dns|iiop)", re.I)),
    ("Server-side template injection", "rce", 40,
     re.compile(r"\{\{.*(config|self|__class__|globals).*\}\}", re.I)),
    ("Server-side request forgery", "ssrf", 30,
     re.compile(r"(url|redirect|next|dest|target)=(https?%3a|https?:)//"
                r"(127\.0\.0\.1|localhost|169\.254|\[::1\])", re.I)),
    ("Deserialization payload", "rce", 45,
     re.compile(r"rO0AB|aced0005|O:\d+:\"", re.I)),
    ("Web shell access", "webshell", 50,
     re.compile(r"(c99|r57|wso|b374k|shell|cmd)\.(php|asp|aspx|jsp)\b", re.I)),
    ("XML external entity", "xxe", 45,
     re.compile(r"<!ENTITY\s+\S+\s+SYSTEM", re.I)),
    ("NoSQL injection", "sqli", 35,
     re.compile(r"\$where|\$ne\s*:|\$regex\s*:", re.I)),
]

SCANNER_AGENTS = re.compile(
    r"sqlmap|nikto|nmap|acunetix|nessus|masscan|dirbuster|gobuster|wfuzz|"
    r"burp|zaproxy|havij|w3af|metasploit|hydra|feroxbuster|ffuf",
    re.I,
)


def _decode_layers(value: str, rounds: int = 3) -> str:
    """URL-decode repeatedly so encoded payloads are matched too."""
    current = value
    for _ in range(rounds):
        try:
            decoded = urllib.parse.unquote_plus(current)
        except Exception:
            break
        if decoded == current:
            break
        current = decoded
    return current


def detect_web_attacks(r, deep: bool):
    if not r.http_records:
        return

    hits: dict[str, list[dict]] = defaultdict(list)
    scanner_hits: list[dict] = []
    status_by_src: dict[str, Counter] = defaultdict(Counter)
    uris_by_src: dict[str, set[str]] = defaultdict(set)

    # Responses tell us whether an attack landed.
    response_status: dict[int, int] = {}
    for rec in r.http_records:
        if rec.get("kind") == "response":
            response_status[rec["packet"]] = rec["status"]
            status_by_src[rec["dst"]][rec["status"]] += 1

    for rec in r.http_records:
        if rec.get("kind") != "request":
            continue

        src = rec["src"]
        uri = rec.get("uri") or ""
        uris_by_src[src].add(uri.split("?")[0])

        agent = rec.get("user_agent") or ""
        if agent and SCANNER_AGENTS.search(agent):
            scanner_hits.append(
                {
                    "source": src,
                    "target": rec["dst"],
                    "user_agent": agent[:120],
                    "packet": rec["packet"],
                    "uri": uri[:120],
                }
            )

        body = rec.get("body_preview") or b""
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")

        # Payloads hide in headers as often as in the URI. Log4Shell in
        # particular is usually delivered through User-Agent or Referer.
        header_surface = " ".join(
            filter(
                None,
                [agent, rec.get("referer") or "", rec.get("cookie") or ""],
            )
        )
        haystack = " ".join(
            [
                _decode_layers(uri),
                _decode_layers(body),
                _decode_layers(header_surface),
            ]
        )

        for title, category, weight, pattern in WEB_PATTERNS:
            match = pattern.search(haystack)
            if not match:
                continue

            # Keep the text that actually matched, with a little either
            # side. Knowing a request "matched SQL injection" is far less
            # useful than seeing the payload and deciding for yourself.
            span_start = max(0, match.start() - 60)
            span_end = min(len(haystack), match.end() + 60)
            context = haystack[span_start:span_end]

            # Where the payload arrived matters: a body payload and a
            # User-Agent payload mean different things about the attacker.
            if match.group(0) in _decode_layers(uri):
                location = "URI"
            elif body and match.group(0) in _decode_layers(body):
                location = "request body"
            else:
                location = "header"

            hits[title].append(
                {
                    "source": src,
                    "target": rec["dst"],
                    "method": rec.get("method"),
                    "host": rec.get("host"),
                    "uri": uri[:200],
                    "packet": rec["packet"],
                    "category": category,
                    "weight": weight,
                    "ts": rec["ts"],
                    "matched": match.group(0)[:200],
                    "location": location,
                    "context": context,
                    "user_agent": agent[:160] or None,
                    "referer": (rec.get("referer") or "")[:160] or None,
                    "body_preview": body[:400] if body else None,
                    "status": response_status.get(rec["packet"] + 1),
                }
            )

    for title, rows in hits.items():
        weight = rows[0]["weight"]
        category = rows[0]["category"]
        severity = "critical" if weight >= 50 else "high" if weight >= 40 else "medium"

        sources = sorted({row["source"] for row in rows})
        targets = sorted({row["target"] for row in rows})

        r.findings.append(
            make_finding(
                f"web.{category}",
                title,
                severity,
                "Web attack",
                f"{len(rows)} HTTP requests carried this payload pattern, sent "
                f"from {len(sources)} source(s) to {len(targets)} target(s).",
                _web_why(category),
                _web_recommendation(category),
                confidence="high" if weight >= 45 else "medium",
                mitre=_web_mitre(category),
                hosts=(sources + targets)[:20],
                count=len(rows),
                first_seen=min(row["ts"] for row in rows),
                last_seen=max(row["ts"] for row in rows),
                evidence=_ev(rows),
            )
        )

    if scanner_hits:
        r.findings.append(
            make_finding(
                "web.scanner",
                "Web vulnerability scanner traffic",
                "high",
                "Web attack",
                f"{len(scanner_hits)} requests identified themselves as security "
                "scanning tools in the User-Agent header.",
                "These tools announce themselves by default, so seeing them means "
                "either an authorised assessment is running or an attacker has "
                "not bothered to hide. Either way the target was actively probed "
                "for vulnerabilities.",
                "Confirm against your change calendar whether a penetration test "
                "or scan was scheduled. If not, block the source and review the "
                "target's logs for any request that returned a successful status "
                "code.",
                confidence="high",
                mitre=["T1595", "T1190"],
                hosts=sorted({h["source"] for h in scanner_hits})[:20],
                count=len(scanner_hits),
                evidence=_ev(scanner_hits),
            )
        )

    # --- directory brute forcing ---
    for src, statuses in status_by_src.items():
        not_found = statuses.get(404, 0)
        total = sum(statuses.values())
        if not_found >= 50 and total and not_found / total > 0.6:
            r.findings.append(
                make_finding(
                    "web.dirbust",
                    "Directory brute forcing",
                    "medium",
                    "Web attack",
                    f"{src} received {not_found} 'not found' responses out of "
                    f"{total} requests, across {len(uris_by_src.get(src, []))} "
                    "distinct paths.",
                    "Guessing paths in bulk is how an attacker finds admin "
                    "panels, backups and forgotten files that are not linked "
                    "from anywhere on the site.",
                    "Review which requests did not return 404. Those paths exist "
                    "and are what the attacker found. Check whether any of them "
                    "expose configuration or backup files.",
                    confidence="medium",
                    mitre=["T1595"],
                    hosts=[src],
                    count=not_found,
                    evidence=[
                        {
                            "source": src,
                            "not_found": not_found,
                            "total_requests": total,
                            "distinct_paths": len(uris_by_src.get(src, [])),
                        }
                    ],
                )
            )


def _outcome_note(rows: list[dict]) -> str:
    """
    Say whether the server appeared to accept the request.

    A 200 to an injection attempt is a different conversation from a 403.
    This is a hint rather than proof: matching a response to its request
    by packet order is reliable in a clean capture and less so in a busy
    one.
    """
    statuses = [row.get("status") for row in rows if row.get("status")]
    if not statuses:
        return "No matching responses were seen, so it is not clear whether the target accepted them."

    succeeded = sum(1 for s in statuses if 200 <= s < 300)
    rejected = sum(1 for s in statuses if s in (401, 403, 406, 429))
    errors = sum(1 for s in statuses if s >= 500)

    parts = []
    if succeeded:
        parts.append(f"{succeeded} received a success response")
    if rejected:
        parts.append(f"{rejected} were rejected")
    if errors:
        parts.append(f"{errors} caused a server error, which often means the "
                     "payload reached the application")
    return "Of the responses seen, " + ", ".join(parts) + "." if parts else ""


def _web_why(category: str) -> str:
    return {
        "sqli": "SQL injection lets an attacker read or modify the database "
                "behind a web application, which usually means every account "
                "record and credential the application stores.",
        "xss": "Cross-site scripting runs attacker-supplied JavaScript in "
               "another user's browser, which is used to steal session cookies "
               "and take over accounts without needing the password.",
        "lfi": "Path traversal reaches files outside the web root. Attackers "
               "use it to read configuration files containing database "
               "credentials, or system files listing every account on the host.",
        "cmdi": "Command injection runs operating system commands on the web "
                "server. It is the fastest route from a web bug to full control "
                "of the machine.",
        "rce": "This payload targets remote code execution. If it succeeded, "
               "the attacker is running their own code on the server.",
        "ssrf": "Server-side request forgery makes the server issue requests on "
                "the attacker's behalf, which is used to reach internal services "
                "and cloud metadata endpoints that are otherwise unreachable.",
        "webshell": "A web shell is a script an attacker uploads to keep "
                    "command access to a server. Requests to one mean the "
                    "compromise already happened.",
        "xxe": "XML external entity attacks make the parser read local files or "
               "contact internal systems, leaking data the application should "
               "never expose.",
    }.get(category, "This request pattern is associated with attacks against "
                    "web applications.")


def _web_recommendation(category: str) -> str:
    return {
        "sqli": "Check the target's application logs for these requests and "
                "whether they returned data. Review the affected parameter for "
                "missing parameterised queries, and assume database contents "
                "were exposed if any request returned a 200 with unusual size.",
        "xss": "Identify whether the payload was stored or reflected. Stored "
               "payloads affect every visitor and need immediate removal from "
               "the database.",
        "lfi": "Check whether the response contained file contents. If it did, "
               "rotate every credential stored in the files that were read.",
        "cmdi": "Treat the web server as compromised until proven otherwise. "
                "Check for new processes, scheduled tasks and outbound "
                "connections started around the time of these requests.",
        "rce": "Isolate the server and begin incident response. Check for "
               "follow-on outbound connections, which would confirm the exploit "
               "succeeded and a payload was retrieved.",
        "ssrf": "Review what internal endpoints the server could reach. If a "
                "cloud metadata service was among them, rotate the instance "
                "credentials immediately.",
        "webshell": "Locate and remove the shell file, then determine how it "
                    "was uploaded. The upload path is the vulnerability that "
                    "still needs fixing.",
        "xxe": "Disable external entity resolution in the XML parser and check "
               "which files the responses returned.",
    }.get(category, "Review the target application logs for these requests and "
                    "confirm whether they succeeded.")


def _web_mitre(category: str) -> list[str]:
    return {
        "sqli": ["T1190"],
        "xss": ["T1190"],
        "lfi": ["T1190"],
        "cmdi": ["T1190", "T1059"],
        "rce": ["T1190", "T1059"],
        "ssrf": ["T1190"],
        "webshell": ["T1190", "T1505" ],
        "xxe": ["T1190"],
    }.get(category, ["T1190"])


# ---------------------------------------------------------------------------
# Cleartext credentials
# ---------------------------------------------------------------------------

CRED_PARAM = re.compile(
    r"(password|passwd|pwd|pass|secret|token|api[_-]?key|auth)"
    r"=([^&\s\"']{1,60})",
    re.I,
)


def detect_cleartext(r, deep: bool):
    findings_rows: list[dict] = []

    # HTTP Basic authentication carries base64 credentials in the header.
    for rec in r.http_records:
        if rec.get("kind") != "request":
            continue
        auth = rec.get("authorization")
        if auth and auth.lower().startswith("basic "):
            findings_rows.append(
                {
                    "protocol": "HTTP Basic",
                    "source": rec["src"],
                    "target": rec["dst"],
                    "packet": rec["packet"],
                    "detail": "Authorization header sends credentials "
                              "base64-encoded, which is not encryption.",
                    "host": rec.get("host"),
                }
            )

        body = rec.get("body_preview") or b""
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        target = (rec.get("uri") or "") + " " + body
        match = CRED_PARAM.search(target)
        if match and rec.get("dport") not in (443, 8443):
            findings_rows.append(
                {
                    "protocol": "HTTP form",
                    "source": rec["src"],
                    "target": rec["dst"],
                    "packet": rec["packet"],
                    "parameter": match.group(1),
                    "detail": "Credential parameter submitted over plain HTTP.",
                    "host": rec.get("host"),
                }
            )

    # Any use of a protocol that has no encryption at all.
    cleartext_flows: dict[str, list] = defaultdict(list)
    for flow in r.flows.values():
        name = is_cleartext(flow.responder_port or flow.dport)
        if name and flow.total_packets > 2:
            cleartext_flows[name].append(flow)

    for name, flows in cleartext_flows.items():
        if name == "HTTP":
            continue  # HTTP is reported through its own findings
        total_bytes = sum(f.total_bytes for f in flows)
        r.findings.append(
            make_finding(
                f"cleartext.{name.lower()}",
                f"{name} in use without encryption",
                "high" if name in ("Telnet", "FTP", "POP3", "IMAP") else "medium",
                "Credential exposure",
                f"{len(flows)} {name} sessions carried {total_bytes:,} bytes "
                "with no transport encryption.",
                f"{name} sends everything, including usernames and passwords, "
                "as readable text. Anyone positioned on the network path can "
                "capture those credentials exactly as this capture did.",
                f"Move these sessions to the encrypted equivalent and disable "
                f"{name} on the server. Treat any credential used over this "
                "protocol as exposed and rotate it.",
                confidence="high",
                mitre=["T1040", "T1552"],
                hosts=sorted({f.src for f in flows} | {f.dst for f in flows})[:20],
                count=len(flows),
                evidence=_ev(
                    [
                        {
                            "source": f.src,
                            "target": f.dst,
                            "port": f.dport,
                            "packets": f.total_packets,
                            "bytes": f.total_bytes,
                        }
                        for f in flows[:MAX_EVIDENCE]
                    ]
                ),
            )
        )

    if findings_rows:
        r.credential_hits = findings_rows
        r.findings.append(
            make_finding(
                "cleartext.http_credentials",
                "Credentials sent over plain HTTP",
                "critical",
                "Credential exposure",
                f"{len(findings_rows)} requests carried authentication data over "
                "unencrypted HTTP.",
                "Credentials sent this way are readable by anyone who can see "
                "the traffic: other devices on the same network, the wireless "
                "access point, and every network device along the path. These "
                "specific credentials should now be considered public.",
                "Rotate every credential involved. Move the application to HTTPS "
                "and set HSTS so browsers refuse to fall back to HTTP.",
                confidence="high",
                mitre=["T1040", "T1552"],
                hosts=sorted({row["source"] for row in findings_rows})[:20],
                count=len(findings_rows),
                evidence=_ev(findings_rows),
            )
        )


# ---------------------------------------------------------------------------
# Data exfiltration
# ---------------------------------------------------------------------------

def detect_exfiltration(r, deep: bool):
    outbound: list[dict] = []

    for flow in r.flows.values():
        source = flow.initiator or flow.src
        destination = flow.responder or flow.dst
        src_host = r.hosts.get(source)
        dst_host = r.hosts.get(destination)
        if not src_host or not dst_host:
            continue
        if not src_host.is_private or dst_host.is_private:
            continue

        sent = flow.bytes_out
        received = flow.bytes_in
        if sent < 5_000_000:
            continue

        ratio = sent / max(1, received)
        if ratio < 4:
            continue

        outbound.append(
            {
                "source": source,
                "destination": destination,
                "port": flow.responder_port or flow.dport,
                "service": flow.service,
                "bytes_sent": sent,
                "bytes_received": received,
                "upload_ratio": round(ratio, 1),
                "duration_seconds": round(flow.duration, 1),
                "sni": flow.sni,
            }
        )

    if outbound:
        outbound.sort(key=lambda o: -o["bytes_sent"])
        total = sum(o["bytes_sent"] for o in outbound)
        top = outbound[0]
        severity = "high" if total > 100_000_000 else "medium"
        r.findings.append(
            make_finding(
                "exfil.large_upload",
                "Large outbound transfer to an external host",
                severity,
                "Data exfiltration",
                f"{len(outbound)} flows sent far more data out than they "
                f"received, totalling {total / 1_048_576:.1f} MB. The largest "
                f"is {top['source']} sending "
                f"{top['bytes_sent'] / 1_048_576:.1f} MB to {top['destination']} "
                f"on port {top['port']}.",
                "Most client traffic downloads more than it uploads. A strongly "
                "reversed ratio means a host is pushing data out, which is what "
                "data theft looks like on the wire. Backups and cloud sync "
                "produce the same shape, so the destination decides the verdict.",
                "Identify what the destination is. If it is not an approved "
                "backup or sync service, determine what data the source host "
                "had access to and treat this as a potential breach requiring "
                "disclosure assessment.",
                confidence="medium",
                mitre=["T1041", "T1048"],
                hosts=sorted({o["source"] for o in outbound})[:20],
                count=len(outbound),
                evidence=_ev(outbound),
            )
        )


# ---------------------------------------------------------------------------
# Lateral movement
# ---------------------------------------------------------------------------

def detect_lateral_movement(r, deep: bool):
    admin_flows: dict[str, list] = defaultdict(list)

    for flow in r.flows.values():
        name = is_lateral(flow.responder_port or flow.dport)
        if not name:
            continue
        source = flow.initiator or flow.src
        destination = flow.responder or flow.dst
        src_host = r.hosts.get(source)
        dst_host = r.hosts.get(destination)
        if not (src_host and dst_host and src_host.is_private and dst_host.is_private):
            continue
        admin_flows[name].append((source, destination))

    # A workstation reaching many peers over an admin protocol is the signal.
    for name, flows in admin_flows.items():
        by_source: dict[str, set[str]] = defaultdict(set)
        for source, destination in flows:
            by_source[source].add(destination)

        spreaders = {src: peers for src, peers in by_source.items() if len(peers) >= 5}
        if not spreaders:
            continue

        top_src = max(spreaders, key=lambda s: len(spreaders[s]))
        r.findings.append(
            make_finding(
                f"lateral.{name.lower()}",
                f"{name} connections fanning out across internal hosts",
                "high" if len(spreaders[top_src]) >= 10 else "medium",
                "Lateral movement",
                f"{top_src} opened {name} connections to "
                f"{len(spreaders[top_src])} internal hosts. "
                f"{len(spreaders)} host(s) show this pattern.",
                f"{name} is how administrators manage machines remotely, and "
                "how attackers move between them once they have a working "
                "credential. A single workstation contacting many peers over an "
                "admin protocol is unusual unless it is a management server.",
                "Confirm whether the source is a designated administrative host. "
                "If it is an ordinary workstation, check which account "
                "authenticated and whether that account's credentials were "
                "recently exposed.",
                confidence="medium",
                mitre=["T1021", "T1021.002" if name == "SMB" else "T1021"],
                hosts=sorted(spreaders.keys())[:20],
                count=sum(len(p) for p in spreaders.values()),
                evidence=_ev(
                    [
                        {
                            "source": src,
                            "protocol": name,
                            "hosts_contacted": len(peers),
                            "sample_targets": sorted(peers)[:8],
                        }
                        for src, peers in spreaders.items()
                    ]
                ),
            )
        )


# ---------------------------------------------------------------------------
# Protocol tunneling
# ---------------------------------------------------------------------------

def detect_tunneling(r, deep: bool):
    # --- ICMP tunneling: large or high-entropy echo payloads ---
    if r.icmp_records:
        suspicious = [
            rec for rec in r.icmp_records
            if rec["type"] in (0, 8, 128, 129)
            and rec["payload_len"] > 100
            and rec["entropy"] > 5.5
        ]
        if len(suspicious) >= 10:
            pairs = Counter((s["src"], s["dst"]) for s in suspicious)
            total_bytes = sum(s["payload_len"] for s in suspicious)
            r.findings.append(
                make_finding(
                    "tunnel.icmp",
                    "Data carried inside ICMP echo packets",
                    "high",
                    "Protocol tunneling",
                    f"{len(suspicious)} ICMP echo packets carried payloads "
                    f"averaging {total_bytes // len(suspicious)} bytes with high "
                    "entropy, totalling "
                    f"{total_bytes / 1024:.1f} KB.",
                    "A normal ping carries a small, fixed, repeating payload. "
                    "Large high-entropy payloads mean something is using ICMP as "
                    "a transport, which is a well-established way to move data "
                    "past firewalls that permit ping but inspect nothing else.",
                    "Block or rate-limit outbound ICMP echo at the perimeter, "
                    "then investigate the sending host for the process "
                    "generating it.",
                    confidence="high",
                    mitre=["T1572", "T1095", "T1048"],
                    hosts=sorted({s["src"] for s in suspicious})[:20],
                    count=len(suspicious),
                    evidence=_ev(
                        [
                            {
                                "source": src,
                                "destination": dst,
                                "packets": count,
                            }
                            for (src, dst), count in pairs.most_common(MAX_EVIDENCE)
                        ]
                    ),
                )
            )

    # --- services running on non-standard ports ---
    odd = []
    for flow in r.flows.values():
        port = flow.responder_port or flow.dport
        if flow.sni and port not in (443, 8443, 993, 995, 465, 587, 636, 990):
            odd.append(
                {
                    "source": flow.initiator or flow.src,
                    "destination": flow.responder or flow.dst,
                    "port": port,
                    "sni": flow.sni,
                    "bytes": flow.total_bytes,
                }
            )
    if odd:
        r.findings.append(
            make_finding(
                "tunnel.tls_nonstandard_port",
                "Encrypted sessions on unexpected ports",
                "medium",
                "Protocol tunneling",
                f"{len(odd)} TLS sessions were negotiated on ports not normally "
                "used for encrypted traffic.",
                "Running TLS on an unusual port is a way to blend command and "
                "control traffic in with everything else, since inspection tools "
                "often only decrypt on well-known ports. Legitimate internal "
                "services also do this.",
                "Check whether each destination and port combination matches a "
                "known internal service. Unrecognised external endpoints on odd "
                "ports deserve investigation as covert channels.",
                confidence="low",
                mitre=["T1571", "T1573"],
                hosts=sorted({o["source"] for o in odd})[:20],
                count=len(odd),
                evidence=_ev(odd),
            )
        )

    # --- cryptocurrency mining ---
    mining = [
        flow for flow in r.flows.values()
        if (flow.responder_port or flow.dport) in MINING_PORTS
        and flow.total_packets > 20
    ]
    if mining:
        r.findings.append(
            make_finding(
                "abuse.mining",
                "Traffic consistent with cryptocurrency mining",
                "medium",
                "Resource abuse",
                f"{len(mining)} long-lived sessions ran on ports commonly used "
                "by mining pools.",
                "Mining software connects to a pool and holds the connection "
                "open, consuming processing capacity that was paid for by "
                "someone else. It often arrives as the payload of a separate "
                "compromise, so it can be the visible symptom of a deeper "
                "problem.",
                "Identify the process on the source host. Treat its presence as "
                "evidence of an earlier intrusion and look for how it was "
                "installed.",
                confidence="low",
                mitre=["T1496"],
                hosts=sorted({f.src for f in mining})[:20],
                count=len(mining),
                evidence=_ev(
                    [
                        {
                            "source": f.src,
                            "destination": f.dst,
                            "port": f.dport,
                            "packets": f.total_packets,
                            "duration_seconds": round(f.duration, 1),
                        }
                        for f in mining[:MAX_EVIDENCE]
                    ]
                ),
            )
        )


# ---------------------------------------------------------------------------
# TLS anomalies
# ---------------------------------------------------------------------------

def detect_tls_anomalies(r, deep: bool):
    if r.certificates:
        self_signed = [c for c in r.certificates if c.get("self_signed")]
        if self_signed:
            r.findings.append(
                make_finding(
                    "tls.self_signed",
                    "Self-signed certificates in use",
                    "medium",
                    "TLS anomaly",
                    f"{len(self_signed)} certificates had a subject matching "
                    "their own issuer.",
                    "A self-signed certificate has no third party vouching for "
                    "it, so a client cannot tell the real server from an "
                    "impostor. Internal tools often use them legitimately, but "
                    "so does attacker infrastructure, because it needs no "
                    "registration.",
                    "Confirm each certificate belongs to a known internal "
                    "service. Self-signed certificates on external destinations "
                    "are a strong signal of attacker-controlled infrastructure.",
                    confidence="medium",
                    mitre=["T1573"],
                    hosts=sorted({c.get("server", "") for c in self_signed})[:20],
                    count=len(self_signed),
                    evidence=_ev(
                        [
                            {
                                "server": c.get("server"),
                                "subject": c.get("subject_cn"),
                                "issuer": c.get("issuer_cn"),
                                "packet": c.get("packet"),
                            }
                            for c in self_signed[:MAX_EVIDENCE]
                        ]
                    ),
                )
            )

    # --- rare JA3 fingerprints ---
    if r.tls_records:
        ja3_counts = Counter(t["ja3"] for t in r.tls_records if t.get("ja3"))
        rare = [
            (fp, count) for fp, count in ja3_counts.items()
            if count <= 2 and len(ja3_counts) > 5
        ]
        if rare and len(rare) / max(1, len(ja3_counts)) < 0.5:
            rows = []
            for fp, count in rare[:MAX_EVIDENCE]:
                sample = next(t for t in r.tls_records if t.get("ja3") == fp)
                rows.append(
                    {
                        "ja3": fp,
                        "sessions": count,
                        "client": sample["src"],
                        "server": sample["dst"],
                        "sni": sample.get("sni"),
                        "tls_version": sample.get("version"),
                    }
                )
            r.findings.append(
                make_finding(
                    "tls.rare_fingerprint",
                    "Uncommon TLS client fingerprints",
                    "low",
                    "TLS anomaly",
                    f"{len(rare)} JA3 fingerprints appeared only once or twice, "
                    f"out of {len(ja3_counts)} distinct client fingerprints.",
                    "A JA3 fingerprint identifies the software making the "
                    "connection, not the user. Browsers and common libraries "
                    "produce fingerprints seen thousands of times. One that "
                    "appears once was made by something unusual on this network, "
                    "which is how custom malware stands out even when its "
                    "traffic is encrypted.",
                    "Compare these fingerprints against the software you expect "
                    "on the source host. An unrecognised fingerprint paired with "
                    "regular outbound connections is a strong compromise "
                    "indicator.",
                    confidence="low",
                    mitre=["T1573"],
                    hosts=sorted({row["client"] for row in rows})[:20],
                    count=len(rare),
                    evidence=rows,
                )
            )

    # --- obsolete TLS versions ---
    old = [
        t for t in r.tls_records
        if t.get("version") in ("SSL 3.0", "TLS 1.0", "TLS 1.1")
    ]
    if old:
        r.findings.append(
            make_finding(
                "tls.obsolete_version",
                "Obsolete TLS versions negotiated",
                "medium",
                "TLS anomaly",
                f"{len(old)} sessions used SSL 3.0, TLS 1.0 or TLS 1.1.",
                "These versions have known cryptographic weaknesses and were "
                "deprecated years ago. Traffic protected by them can be "
                "downgraded or decrypted by an attacker with network access.",
                "Identify the client and server software still negotiating "
                "these versions and update it. Disable versions below TLS 1.2 "
                "on the server side.",
                confidence="high",
                hosts=sorted({t["src"] for t in old})[:20],
                count=len(old),
                evidence=_ev(
                    [
                        {
                            "client": t["src"],
                            "server": t["dst"],
                            "version": t.get("version"),
                            "sni": t.get("sni"),
                        }
                        for t in old[:MAX_EVIDENCE]
                    ]
                ),
            )
        )


# ---------------------------------------------------------------------------
# Spoofing
# ---------------------------------------------------------------------------

def detect_spoofing(r, deep: bool):
    # One IP claimed by several MAC addresses is ARP poisoning's signature.
    conflicts = {
        ip: macs for ip, macs in r.arp_map.items()
        if len(macs) > 1 and not _is_broadcast_or_multicast(ip)
    }
    if conflicts:
        r.findings.append(
            make_finding(
                "spoof.arp",
                "One IP address claimed by multiple MAC addresses",
                "high",
                "Spoofing",
                f"{len(conflicts)} IP addresses were announced by more than one "
                "hardware address in ARP traffic.",
                "Each IP on a network should map to exactly one network card. "
                "Two cards claiming the same address means one of them is lying, "
                "which is how an attacker inserts themselves between two hosts "
                "to read and modify their traffic. Failover clusters and "
                "roaming devices produce the same conflict legitimately.",
                "Check whether the conflicting addresses belong to a known "
                "redundancy setup. If not, find the physical port behind the "
                "unexpected MAC address and disconnect it, then enable dynamic "
                "ARP inspection on the switch.",
                confidence="medium",
                mitre=["T1557.002", "T1557"],
                hosts=sorted(conflicts.keys())[:20],
                count=len(conflicts),
                evidence=_ev(
                    [
                        {"ip": ip, "mac_addresses": sorted(macs)}
                        for ip, macs in list(conflicts.items())[:MAX_EVIDENCE]
                    ]
                ),
            )
        )


# ---------------------------------------------------------------------------
# IPv6 abuse
# ---------------------------------------------------------------------------

def detect_ipv6_abuse(r, deep: bool):
    v6_icmp = [rec for rec in r.icmp_records if rec.get("is_v6")]
    if not v6_icmp:
        return

    # ICMPv6 type 134 is a Router Advertisement.
    routers = Counter(rec["src"] for rec in v6_icmp if rec["type"] == 134)
    if len(routers) > 1:
        r.findings.append(
            make_finding(
                "ipv6.rogue_ra",
                "Multiple sources advertising themselves as IPv6 routers",
                "high",
                "IPv6 abuse",
                f"{len(routers)} different addresses sent IPv6 Router "
                "Advertisements on this network.",
                "Hosts configure their IPv6 address and default gateway from "
                "whatever router advertises itself. An extra advertiser can "
                "become the default gateway for every IPv6-capable host and "
                "read all their traffic. This works even on networks that only "
                "intend to run IPv4, because most operating systems prefer IPv6 "
                "when it is available.",
                "Confirm which advertiser is your real router. Enable RA Guard "
                "on the switch so only authorised ports may send "
                "advertisements, and investigate the host behind any "
                "unauthorised source.",
                confidence="medium",
                mitre=["T1557"],
                hosts=list(routers.keys())[:20],
                count=sum(routers.values()),
                evidence=_ev(
                    [
                        {"advertising_address": src, "advertisements": count}
                        for src, count in routers.most_common(MAX_EVIDENCE)
                    ]
                ),
            )
        )

    # Tunnelled IPv6 inside IPv4 bypasses IPv4-only controls.
    tunnel_count = r.encapsulations.get("6in4", 0) + r.encapsulations.get("IP-in-IP", 0)
    if tunnel_count >= 20:
        r.findings.append(
            make_finding(
                "ipv6.tunnelled",
                "IPv6 traffic tunnelled inside IPv4",
                "medium",
                "IPv6 abuse",
                f"{tunnel_count} packets carried IPv6 inside an IPv4 tunnel.",
                "Firewalls and monitoring tools configured for IPv4 often do not "
                "inspect inside these tunnels, so traffic passes through "
                "unexamined. That makes tunnelling a standard technique for "
                "evading network controls.",
                "Confirm the tunnel is a sanctioned transition mechanism. If it "
                "is not, block protocol 41 at the perimeter and inspect what the "
                "tunnel carried.",
                confidence="medium",
                mitre=["T1572"],
                count=tunnel_count,
                evidence=[{"tunnelled_packets": tunnel_count}],
            )
        )


# ---------------------------------------------------------------------------
# Suspicious infrastructure
# ---------------------------------------------------------------------------

def detect_suspicious_infra(r, deep: bool):
    # HTTP requests addressed to a bare IP rather than a hostname.
    ip_literal = []
    for rec in r.http_records:
        if rec.get("kind") != "request":
            continue
        host_header = rec.get("host") or ""
        stripped = host_header.split(":")[0].strip("[]")
        try:
            ipaddress.ip_address(stripped)
        except ValueError:
            continue
        ip_literal.append(
            {
                "source": rec["src"],
                "destination": rec["dst"],
                "host_header": host_header,
                "uri": (rec.get("uri") or "")[:120],
                "user_agent": (rec.get("user_agent") or "")[:100],
                "packet": rec["packet"],
            }
        )

    if ip_literal:
        r.findings.append(
            make_finding(
                "infra.ip_literal_http",
                "HTTP requests to a raw IP address",
                "medium",
                "Suspicious infrastructure",
                f"{len(ip_literal)} HTTP requests used an IP address in the Host "
                "header instead of a domain name.",
                "Browsers reach websites by name. Requests addressed directly to "
                "an IP usually come from software rather than a person, and "
                "malware frequently hardcodes an address to avoid needing a "
                "domain that could be taken down.",
                "Check what process on the source host made these requests and "
                "what the destination returned. Requests to an IP that fetch an "
                "executable are a download of a second-stage payload.",
                confidence="medium",
                mitre=["T1071.001", "T1105"],
                hosts=sorted({row["source"] for row in ip_literal})[:20],
                count=len(ip_literal),
                evidence=_ev(ip_literal),
            )
        )

    # Rare user agents suggest tooling rather than browsers.
    agents = Counter()
    agent_hosts: dict[str, set[str]] = defaultdict(set)
    for rec in r.http_records:
        if rec.get("kind") == "request" and rec.get("user_agent"):
            agents[rec["user_agent"]] += 1
            agent_hosts[rec["user_agent"]].add(rec["src"])

    if len(agents) > 3:
        rare_agents = [
            (agent, count) for agent, count in agents.items()
            if count <= 3
            and not SCANNER_AGENTS.search(agent)
        ]
        if rare_agents:
            r.findings.append(
                make_finding(
                    "infra.rare_user_agent",
                    "Uncommon HTTP client identifiers",
                    "low",
                    "Suspicious infrastructure",
                    f"{len(rare_agents)} User-Agent strings appeared only a "
                    f"handful of times among {len(agents)} distinct values.",
                    "The User-Agent names the software making the request. "
                    "Browsers on a network produce a small set of repeated "
                    "values. A string seen once was sent by something unusual, "
                    "which is often a script or a piece of malware using a "
                    "default library identifier.",
                    "Review each rare identifier against the software you expect "
                    "on the source host. Generic library defaults such as "
                    "python-requests or curl on a user workstation are worth "
                    "explaining.",
                    confidence="low",
                    hosts=sorted({h for a, _ in rare_agents for h in agent_hosts[a]})[:20],
                    count=len(rare_agents),
                    evidence=_ev(
                        [
                            {
                                "user_agent": agent[:150],
                                "requests": count,
                                "sources": sorted(agent_hosts[agent])[:5],
                            }
                            for agent, count in rare_agents[:MAX_EVIDENCE]
                        ]
                    ),
                )
            )


# ---------------------------------------------------------------------------
# Malware delivery
# ---------------------------------------------------------------------------

EXECUTABLE_SIGNATURES = {
    b"MZ": "Windows executable",
    b"\x7fELF": "Linux executable",
    b"\xca\xfe\xba\xbe": "Java class or macOS binary",
    b"PK\x03\x04": "ZIP archive (may contain macros)",
    b"%PDF": "PDF document",
    b"\xd0\xcf\x11\xe0": "Legacy Office document",
}

EXECUTABLE_EXTENSIONS = re.compile(
    r"\.(exe|dll|scr|bat|cmd|ps1|vbs|jar|hta|msi|com|pif|apk|elf|bin)"
    r"(\?|$)",
    re.I,
)


def detect_malware_delivery(r, deep: bool):
    downloads = []
    for rec in r.http_records:
        if rec.get("kind") != "request":
            continue
        uri = rec.get("uri") or ""
        if EXECUTABLE_EXTENSIONS.search(uri):
            downloads.append(
                {
                    "source": rec["src"],
                    "server": rec["dst"],
                    "host": rec.get("host"),
                    "uri": uri[:160],
                    "user_agent": (rec.get("user_agent") or "")[:100],
                    "packet": rec["packet"],
                }
            )

    if downloads:
        r.findings.append(
            make_finding(
                "malware.executable_download",
                "Executable file requested over HTTP",
                "high",
                "Malware delivery",
                f"{len(downloads)} requests asked for files with executable or "
                "script extensions over unencrypted HTTP.",
                "Software delivered over plain HTTP can be modified in transit, "
                "and an executable arriving from an unexpected source is one of "
                "the most common ways a host becomes infected in the first "
                "place.",
                "Identify what was downloaded and whether it ran. Hash the file "
                "on the endpoint and check it against threat intelligence. If "
                "the source is unfamiliar, treat the host as compromised.",
                confidence="medium",
                mitre=["T1105"],
                hosts=sorted({d["source"] for d in downloads})[:20],
                count=len(downloads),
                evidence=_ev(downloads),
            )
        )

    # Content-Type that does not match the body's magic bytes.
    mismatches = []
    for rec in r.http_records:
        if rec.get("kind") != "response":
            continue
        body = rec.get("body_preview") or b""
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        if not body:
            continue
        declared = (rec.get("content_type") or "").lower()
        for magic, label in EXECUTABLE_SIGNATURES.items():
            if body.startswith(magic):
                if "executable" in label.lower() and declared and not any(
                    token in declared
                    for token in ("octet-stream", "executable", "download",
                                  "msdownload", "zip", "binary")
                ):
                    mismatches.append(
                        {
                            "server": rec["src"],
                            "client": rec["dst"],
                            "declared_type": declared or "(none)",
                            "actual_content": label,
                            "packet": rec["packet"],
                        }
                    )
                break

    if mismatches:
        r.findings.append(
            make_finding(
                "malware.content_type_mismatch",
                "Server declared a content type that does not match the file",
                "high",
                "Malware delivery",
                f"{len(mismatches)} responses claimed one content type while the "
                "file itself was an executable.",
                "Mislabelling an executable as text or an image is a deliberate "
                "evasion: it gets the file past filters that decide what to "
                "block based on the declared type rather than the contents.",
                "Retrieve and hash the delivered file. A server sending "
                "mislabelled executables is either compromised or attacker "
                "controlled, so block it and check every host that contacted it.",
                confidence="high",
                mitre=["T1105"],
                hosts=sorted({m["client"] for m in mismatches})[:20],
                count=len(mismatches),
                evidence=_ev(mismatches),
            )
        )


# ---------------------------------------------------------------------------
# Capture hygiene
# ---------------------------------------------------------------------------

def detect_capture_issues(r, deep: bool):
    info = r.capture

    if info.truncated_packets and info.packets:
        share = info.truncated_packets / info.packets
        if share > 0.02:
            r.findings.append(
                make_finding(
                    "capture.truncated",
                    "Packets were truncated during capture",
                    "info",
                    "Capture quality",
                    f"{info.truncated_packets:,} of {info.packets:,} packets "
                    f"({share:.0%}) were cut short by the capture snap length "
                    f"of {info.snaplen} bytes.",
                    "Truncated packets lose their payload, so anything that "
                    "depends on reading content, such as credential detection "
                    "or file extraction, will miss things that were actually "
                    "present.",
                    "Re-capture with a snap length of 0 or 65535 to store full "
                    "packets. Treat payload-based findings from this capture as "
                    "a floor rather than a complete picture.",
                    confidence="high",
                    count=info.truncated_packets,
                )
            )

    if info.drops_reported:
        r.findings.append(
            make_finding(
                "capture.drops",
                "The capture tool reported dropped packets",
                "info",
                "Capture quality",
                f"{info.drops_reported:,} packets were dropped before being "
                "written to the file.",
                "Dropped packets are gaps in the record. Any conclusion drawn "
                "from this capture describes only what was successfully stored.",
                "Capture on a less loaded host or write to faster storage. If "
                "you are investigating a specific incident, note the gap in your "
                "case record.",
                confidence="high",
                count=info.drops_reported,
            )
        )

    if r.dropped_flows or r.dropped_hosts:
        r.findings.append(
            make_finding(
                "capture.limits_reached",
                "Analysis limits reached on a very large capture",
                "info",
                "Capture quality",
                f"WireCub stopped adding new records after reaching its limits: "
                f"{r.dropped_flows:,} flows and {r.dropped_hosts:,} hosts were "
                "counted but not stored individually.",
                "Limits keep memory predictable on large captures. Totals stay "
                "accurate, but the host and flow tables show only what was "
                "stored, so the least active endpoints may be missing.",
                "Split the capture by time range and analyse each part "
                "separately for complete per-host detail.",
                confidence="high",
            )
        )
