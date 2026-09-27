"""
Extended detection modules.

These run alongside the core set and cover the environments and techniques
that need reassembled streams, carved files, Windows authentication, or
protocols outside the web and DNS core.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from . import enrich
from .findings import make_finding

MAX_EVIDENCE = 12


def _ev(rows: list[dict]) -> list[dict]:
    return rows[:MAX_EVIDENCE]


# ---------------------------------------------------------------------------
# Carved file findings
# ---------------------------------------------------------------------------

def detect_malicious_files(r, deep: bool):
    """Raise findings from what the signature engine found in carved files."""
    if not r.files:
        return

    by_signature: dict[str, list[dict]] = defaultdict(list)
    for record in r.files:
        for signature in record.get("signatures", []):
            by_signature[signature["name"]].append(
                {
                    "file": record.get("filename") or f"stream-{record['index']}",
                    "type": record["description"],
                    "size": record["size"],
                    "sha256": record["sha256"],
                    "source": record["source"],
                    "destination": record["destination"],
                    "url": record.get("url"),
                    "severity": signature["severity"],
                    "why": signature["description"],
                }
            )

    for name, rows in by_signature.items():
        severity = rows[0]["severity"]
        r.findings.append(
            make_finding(
                f"file.signature.{name.lower().replace(' ', '_')[:40]}",
                f"File transferred matching: {name}",
                severity,
                "Malicious file",
                f"{len(rows)} transferred file(s) matched this signature. "
                f"The first is a {rows[0]['type'].lower()} of "
                f"{rows[0]['size']:,} bytes sent from {rows[0]['source']}.",
                rows[0]["why"],
                "Take the SHA-256 to your endpoint tooling and confirm whether "
                "the file reached disk and executed. Block the serving address "
                "and check every other host that contacted it.",
                confidence="high",
                mitre=["T1105"],
                hosts=sorted({row["destination"] for row in rows})[:20],
                count=len(rows),
                evidence=_ev(rows),
            )
        )

    # Executables that arrived over an unencrypted channel.
    executables = [
        f for f in r.files
        if f["category"] == "executable" and f["protocol"] in ("HTTP", "FTP", "TFTP", "FTP-Data")
    ]
    if executables:
        r.findings.append(
            make_finding(
                "file.executable_transfer",
                "Executable files recovered from the capture",
                "high",
                "Malicious file",
                f"{len(executables)} executable file(s) were reconstructed from "
                "traffic, with hashes computed from the bytes that actually "
                "crossed the wire.",
                "An executable delivered over a channel with no integrity "
                "protection can be replaced in transit, and one arriving from "
                "an unexpected source is a common first stage of an intrusion. "
                "Because these were rebuilt from the packets themselves, the "
                "hashes describe exactly what the endpoint received.",
                "Look each hash up in your threat intelligence. Where a file is "
                "unknown, submit it for analysis and check whether the "
                "receiving host executed it.",
                confidence="high",
                mitre=["T1105"],
                hosts=sorted({f["destination"] for f in executables})[:20],
                count=len(executables),
                evidence=_ev(
                    [
                        {
                            "filename": f.get("filename") or "(unnamed)",
                            "type": f["description"],
                            "size": f["size"],
                            "sha256": f["sha256"],
                            "md5": f["md5"],
                            "imphash": (f.get("pe_info") or {}).get("imphash"),
                            "entropy": f["entropy"],
                            "url": f.get("url"),
                            "source": f["source"],
                            "notes": f.get("notes", []),
                        }
                        for f in executables[:MAX_EVIDENCE]
                    ]
                ),
            )
        )

    # Binaries whose imports cluster around injection and anti-analysis.
    suspicious_pe = [
        f for f in r.files
        if f.get("pe_info") and len(f["pe_info"].get("suspicious_imports", [])) >= 3
    ]
    if suspicious_pe:
        r.findings.append(
            make_finding(
                "file.suspicious_imports",
                "Executable importing process injection and anti-analysis APIs",
                "high",
                "Malicious file",
                f"{len(suspicious_pe)} recovered executable(s) import several "
                "functions associated with running code inside other processes "
                "and detecting analysis environments.",
                "Individually these functions are all legitimate. Appearing "
                "together in one binary is the import profile of injection "
                "tooling: allocate memory in another process, write to it, "
                "start a thread there, and check first whether a debugger is "
                "watching.",
                "Treat the binary as suspicious regardless of whether the hash "
                "is known. Detonate it in a sandbox and watch for child "
                "processes and outbound connections.",
                confidence="medium",
                mitre=["T1055"],
                hosts=sorted({f["destination"] for f in suspicious_pe})[:20],
                count=len(suspicious_pe),
                evidence=_ev(
                    [
                        {
                            "sha256": f["sha256"],
                            "imphash": f["pe_info"].get("imphash"),
                            "architecture": f["pe_info"].get("architecture"),
                            "apis": [
                                i["api"] for i in f["pe_info"]["suspicious_imports"]
                            ][:10],
                        }
                        for f in suspicious_pe[:MAX_EVIDENCE]
                    ]
                ),
            )
        )


# ---------------------------------------------------------------------------
# Ransomware
# ---------------------------------------------------------------------------

# Extensions appended by well-known ransomware families.
RANSOM_EXTENSIONS = {
    ".locked", ".encrypted", ".crypt", ".crypto", ".enc", ".locky",
    ".cerber", ".zepto", ".odin", ".wncry", ".wcry", ".ryk", ".ryuk",
    ".conti", ".lockbit", ".revil", ".sodinokibi", ".darkside", ".blackcat",
    ".hive", ".avos", ".basta", ".royal", ".akira", ".phobos", ".dharma",
    ".makop", ".mallox", ".stop", ".djvu",
}

RANSOM_NOTE_NAMES = {
    "readme.txt", "read_me.txt", "how_to_decrypt.txt", "decrypt_instructions",
    "restore_files", "recovery.txt", "how_to_back_files", "!!!readme!!!",
    "readme_for_decrypt", "your_files", "recover_files", "unlock_files",
}


def detect_ransomware(r, deep: bool):
    """
    Look for the network fingerprint of an encryption run.

    Ransomware over SMB produces a distinctive shape: one host renaming or
    writing to files across many shares in a short window, at a rate no
    person could produce.
    """
    if not r.smb_records:
        return

    writes_by_source: Counter = Counter()
    targets_by_source: dict[str, set[str]] = defaultdict(set)
    times_by_source: dict[str, list[float]] = defaultdict(list)

    for record in r.smb_records:
        if record.get("is_response"):
            continue
        command = record.get("command", "")
        if command in ("Write", "Create", "SetInfo"):
            source = record["src"]
            writes_by_source[source] += 1
            targets_by_source[source].add(record["dst"])
            times_by_source[source].append(record["ts"])

    for source, count in writes_by_source.items():
        targets = targets_by_source[source]
        times = sorted(times_by_source[source])
        if count < 200 or len(targets) < 2:
            continue

        span = max(1.0, times[-1] - times[0])
        rate = count / span
        if rate < 3:
            continue

        r.findings.append(
            make_finding(
                "ransomware.mass_file_operations",
                "High-rate file writes across multiple servers",
                "critical",
                "Ransomware",
                f"{source} issued {count:,} SMB write and create operations "
                f"against {len(targets)} servers in {span:.0f} seconds, "
                f"about {rate:.0f} operations per second.",
                "Encrypting a file share means reading every file and writing "
                "it back. That produces a sustained burst of write operations "
                "across many shares at machine speed. A person copying files "
                "does not generate this pattern, and neither does normal "
                "application use.",
                "Disconnect the source host from the network now rather than "
                "investigating first: every second it stays connected is more "
                "files encrypted. Then check whether the affected shares have "
                "restorable snapshots.",
                confidence="medium",
                mitre=["T1486", "T1021.002"],
                hosts=[source] + sorted(targets)[:10],
                count=count,
                first_seen=times[0],
                last_seen=times[-1],
                evidence=[
                    {
                        "source": source,
                        "operations": count,
                        "servers_touched": len(targets),
                        "duration_seconds": round(span, 1),
                        "operations_per_second": round(rate, 1),
                        "servers": sorted(targets)[:10],
                    }
                ],
            )
        )

    # Ransom notes and renamed files carried over the wire.
    note_hits = []
    for record in r.files:
        name = (record.get("filename") or "").lower()
        if any(marker in name for marker in RANSOM_NOTE_NAMES):
            note_hits.append(
                {
                    "filename": record.get("filename"),
                    "source": record["source"],
                    "destination": record["destination"],
                    "sha256": record["sha256"],
                }
            )
        if any(name.endswith(ext) for ext in RANSOM_EXTENSIONS):
            note_hits.append(
                {
                    "filename": record.get("filename"),
                    "note": "Filename carries a known ransomware extension",
                    "source": record["source"],
                    "destination": record["destination"],
                }
            )

    if note_hits:
        r.findings.append(
            make_finding(
                "ransomware.artefacts",
                "Ransomware artefacts seen in transferred files",
                "critical",
                "Ransomware",
                f"{len(note_hits)} transferred file(s) carried ransom note "
                "names or extensions used by known ransomware families.",
                "These filenames only appear after encryption has already "
                "run. Seeing them on the wire means the incident is under way "
                "rather than being prepared.",
                "Begin incident response immediately. Identify the earliest "
                "affected host and isolate the segment before checking scope.",
                confidence="high",
                mitre=["T1486"],
                hosts=sorted({h["destination"] for h in note_hits})[:20],
                count=len(note_hits),
                evidence=_ev(note_hits),
            )
        )


# ---------------------------------------------------------------------------
# Anonymity networks and VPN
# ---------------------------------------------------------------------------

def detect_anonymity_networks(r, deep: bool):
    """Spot Tor, VPN and proxy use leaving the network."""
    tor_hits = []
    vpn_hits = []

    for flow in r.flows.values():
        destination = flow.responder or flow.dst
        port = flow.responder_port or flow.dport
        host = r.hosts.get(destination)
        if not host or host.is_private:
            continue

        if destination in enrich.TOR_DIRECTORY_AUTHORITIES:
            tor_hits.append(
                {
                    "source": flow.initiator or flow.src,
                    "destination": destination,
                    "port": port,
                    "reason": "Tor directory authority",
                    "packets": flow.total_packets,
                }
            )
        elif enrich.is_anonymity_infrastructure(destination):
            tor_hits.append(
                {
                    "source": flow.initiator or flow.src,
                    "destination": destination,
                    "port": port,
                    "reason": enrich.enrich(destination).get("note", "Tor range"),
                    "packets": flow.total_packets,
                }
            )
        elif port in enrich.TOR_PORTS and flow.total_packets > 20:
            tor_hits.append(
                {
                    "source": flow.initiator or flow.src,
                    "destination": destination,
                    "port": port,
                    "reason": "Tor relay port",
                    "packets": flow.total_packets,
                }
            )

        protocol = enrich.VPN_PORTS.get(port)
        if protocol and flow.total_packets > 10:
            vpn_hits.append(
                {
                    "source": flow.initiator or flow.src,
                    "destination": destination,
                    "port": port,
                    "protocol": protocol,
                    "packets": flow.total_packets,
                    "bytes": flow.total_bytes,
                }
            )

    if tor_hits:
        r.findings.append(
            make_finding(
                "anonymity.tor",
                "Connections to Tor infrastructure",
                "high",
                "Anonymity network",
                f"{len(tor_hits)} connections reached addresses associated "
                "with the Tor network.",
                "Tor hides where traffic actually goes. On a corporate network "
                "that defeats every egress control at once, and it is used both "
                "by staff bypassing policy and by malware whose operators want "
                "their command and control unreachable by takedown.",
                "Identify the process making these connections on the source "
                "host. If Tor is not sanctioned, block the known relay ranges "
                "and treat the host as needing investigation rather than just "
                "a policy conversation.",
                confidence="medium",
                mitre=["T1090.003", "T1090"],
                hosts=sorted({h["source"] for h in tor_hits})[:20],
                count=len(tor_hits),
                evidence=_ev(tor_hits),
            )
        )

    if vpn_hits:
        protocols_seen = sorted({h["protocol"] for h in vpn_hits})
        r.findings.append(
            make_finding(
                "anonymity.vpn",
                "VPN tunnels leaving the network",
                "medium",
                "Anonymity network",
                f"{len(vpn_hits)} tunnels were established using "
                f"{', '.join(protocols_seen)}.",
                "A VPN moves traffic outside the reach of network monitoring. "
                "Corporate VPNs are expected; consumer VPNs on a workstation "
                "create a blind spot where anything can pass unobserved.",
                "Confirm each destination is a sanctioned VPN concentrator. "
                "Tunnels to consumer VPN providers should be blocked at the "
                "perimeter and raised with the user.",
                confidence="low",
                mitre=["T1572"],
                hosts=sorted({h["source"] for h in vpn_hits})[:20],
                count=len(vpn_hits),
                evidence=_ev(vpn_hits),
            )
        )

    # Behavioural signals from enrichment rather than named ranges.
    suspicious_hosting = []
    for finding in r.findings:
        if finding.severity not in ("critical", "high"):
            continue
        for ip in finding.hosts:
            host = r.hosts.get(ip)
            if host and not host.is_private and enrich.is_cheap_vps(ip):
                info = enrich.enrich(ip)
                suspicious_hosting.append(
                    {
                        "address": ip,
                        "operator": info.get("operator"),
                        "raised_by": finding.title,
                    }
                )

    if suspicious_hosting:
        seen = {row["address"]: row for row in suspicious_hosting}
        r.findings.append(
            make_finding(
                "infra.disposable_hosting",
                "Flagged addresses sit on low-cost hosting",
                "low",
                "Suspicious infrastructure",
                f"{len(seen)} of the addresses raised by other findings belong "
                "to providers where a server can be rented anonymously in "
                "minutes.",
                "This is context rather than a detection. These providers host "
                "an enormous amount of legitimate infrastructure, but they are "
                "also where disposable attacker infrastructure lives, because "
                "a burned address costs a few dollars to replace.",
                "Weigh this alongside the finding that flagged each address. "
                "A beaconing destination on a rented VPS is a stronger signal "
                "than the same behaviour toward a major cloud service.",
                confidence="low",
                hosts=sorted(seen.keys())[:20],
                count=len(seen),
                evidence=_ev(list(seen.values())),
            )
        )


# ---------------------------------------------------------------------------
# Windows authentication attacks
# ---------------------------------------------------------------------------

def detect_kerberos_attacks(r, deep: bool):
    """Kerberoasting, AS-REP roasting, and weak ticket encryption."""
    if not r.kerberos_records:
        return

    # Inventory first, so Kerberos activity is visible even when nothing
    # about it is an attack. Domain authentication traffic is the backbone
    # of a Windows timeline and belongs in the report regardless.
    message_types = Counter(
        record.get("message_type") for record in r.kerberos_records
    )
    realms = sorted({
        record.get("realm") for record in r.kerberos_records if record.get("realm")
    })
    principals = sorted({
        p for record in r.kerberos_records
        for p in (record.get("principals") or [])
    })[:20]
    offers_rc4 = [
        record for record in r.kerberos_records
        if 23 in (record.get("etypes") or [])
    ]

    r.findings.append(
        make_finding(
            "kerberos.activity",
            "Kerberos authentication traffic",
            "info",
            "Windows authentication",
            f"{len(r.kerberos_records)} Kerberos messages "
            f"({', '.join(f'{k} {v}' for k, v in message_types.most_common(4))})"
            + (f" in realm {', '.join(realms)}" if realms else "")
            + (f". Accounts and services seen: {', '.join(principals[:8])}"
               if principals else ""),
            "Kerberos exchanges name the accounts, the services they asked "
            "for, and the exact time each request was made. That makes them "
            "the most precise timeline available for what a user or machine "
            "did on a Windows domain.",
            "Use these as the anchor for a timeline. Check whether the "
            "accounts and the services they requested match what those users "
            "should be doing.",
            confidence="high",
            hosts=sorted({record["src"] for record in r.kerberos_records})[:20],
            count=len(r.kerberos_records),
            evidence=_ev(
                [
                    {
                        "message": record.get("message_type"),
                        "from": record["src"],
                        "to": record["dst"],
                        "realm": record.get("realm"),
                        "principals": record.get("principals"),
                        "encryption": ", ".join(record.get("etype_names", [])[:4]),
                    }
                    for record in r.kerberos_records[:MAX_EVIDENCE]
                ]
            ),
        )
    )

    if offers_rc4 and len(offers_rc4) == len(r.kerberos_records):
        r.findings.append(
            make_finding(
                "kerberos.rc4_offered",
                "Clients still advertise RC4 encryption",
                "low",
                "Windows authentication",
                f"All {len(offers_rc4)} Kerberos requests listed RC4 among "
                "the encryption types they accept.",
                "Offering RC4 is not an attack, but it is what makes "
                "Kerberoasting worth attempting: an attacker can ask for a "
                "service ticket in RC4 and crack it offline far faster than "
                "an AES one. Removing the option removes the technique.",
                "Set the domain to require AES and disable RC4 once you have "
                "confirmed no legacy service depends on it.",
                confidence="high",
                mitre=["T1558.003"],
                count=len(offers_rc4),
            )
        )

    rc4_requests = [
        record for record in r.kerberos_records
        if record.get("message_type") == "TGS-REQ" and 23 in record.get("etypes", [])
    ]

    if rc4_requests:
        by_source = Counter(record["src"] for record in rc4_requests)
        targeted = sorted({
            record["service"] for record in rc4_requests if record.get("service")
        })
        severity = "high" if len(rc4_requests) >= 5 else "medium"
        r.findings.append(
            make_finding(
                "kerberos.kerberoasting",
                "Service tickets requested with weak encryption",
                severity,
                "Credential attack",
                f"{len(rc4_requests)} ticket-granting service requests asked "
                f"for RC4 encryption, from {len(by_source)} source(s)."
                + (f" Service accounts targeted: {', '.join(targeted[:6])}."
                   if targeted else ""),
                "A service ticket is encrypted with the service account's "
                "password hash. Asking for RC4 specifically, when modern "
                "domains default to AES, means the requester wants a ticket "
                "they can crack offline at speed. That is Kerberoasting: "
                "harvest tickets, crack them elsewhere, come back with a valid "
                "service account password.",
                "Identify which service accounts were requested and rotate "
                "their passwords to long random values. Disable RC4 in the "
                "domain, and check the requesting host: a workstation asking "
                "for many service tickets is not doing normal work.",
                confidence="medium",
                mitre=["T1558.003", "T1558"],
                hosts=list(by_source.keys())[:20],
                count=len(rc4_requests),
                evidence=_ev(
                    [
                        {
                            "source": source,
                            "requests": count,
                            "encryption": "RC4-HMAC (crackable offline)",
                            "services": sorted({
                                r["service"] for r in rc4_requests
                                if r["src"] == source and r.get("service")
                            })[:6],
                        }
                        for source, count in by_source.most_common(MAX_EVIDENCE)
                    ]
                ),
            )
        )

    # AS-REP without preauthentication: tickets crackable without any
    # credential at all.
    asrep = [
        record for record in r.kerberos_records
        if record.get("message_type") == "AS-REP" and record.get("weak_etype")
    ]
    if len(asrep) >= 3:
        r.findings.append(
            make_finding(
                "kerberos.asrep_roasting",
                "Authentication responses using weak encryption",
                "medium",
                "Credential attack",
                f"{len(asrep)} authentication responses used a weak encryption "
                "type.",
                "Accounts configured without Kerberos pre-authentication hand "
                "out an encrypted blob to anyone who asks for it. With weak "
                "encryption that blob can be cracked offline, yielding the "
                "account password without ever attempting a login.",
                "Find domain accounts with pre-authentication disabled and "
                "re-enable it. Those accounts' passwords should be treated as "
                "exposed.",
                confidence="low",
                mitre=["T1558"],
                hosts=sorted({record["dst"] for record in asrep})[:20],
                count=len(asrep),
                evidence=_ev(
                    [
                        {
                            "server": record["src"],
                            "client": record["dst"],
                            "encryption": ", ".join(record.get("etype_names", [])),
                        }
                        for record in asrep[:MAX_EVIDENCE]
                    ]
                ),
            )
        )


def detect_ntlm_attacks(r, deep: bool):
    """NTLM relay exposure, NTLMv1 use, and authentication spraying."""
    if not r.ntlm_records:
        return

    auths = [record for record in r.ntlm_records if record.get("stage") == "authenticate"]
    if not auths:
        return

    ntlmv1 = [record for record in auths if record.get("ntlm_version") == "NTLMv1"]
    if ntlmv1:
        r.findings.append(
            make_finding(
                "ntlm.v1_in_use",
                "NTLMv1 authentication observed",
                "high",
                "Credential attack",
                f"{len(ntlmv1)} authentications used NTLMv1, from "
                f"{len({record['src'] for record in ntlmv1})} host(s).",
                "NTLMv1 responses can be converted to the account's password "
                "hash using precomputed tables, in hours rather than years. "
                "Anyone who captured this traffic, as this capture just did, "
                "holds material that yields working credentials.",
                "Disable NTLMv1 domain-wide through the LAN Manager "
                "authentication level policy. Treat every account that "
                "authenticated this way as compromised and rotate it.",
                confidence="high",
                mitre=["T1550", "T1040"],
                hosts=sorted({record["src"] for record in ntlmv1})[:20],
                count=len(ntlmv1),
                evidence=_ev(
                    [
                        {
                            "user": f"{record.get('domain')}\\{record.get('user')}",
                            "workstation": record.get("workstation"),
                            "source": record["src"],
                            "target": record["dst"],
                            "transport": record.get("transport"),
                        }
                        for record in ntlmv1[:MAX_EVIDENCE]
                    ]
                ),
            )
        )

    # One account authenticating to many hosts, or many accounts from one
    # host: the two shapes of credential abuse.
    by_user: dict[str, set[str]] = defaultdict(set)
    by_source: dict[str, set[str]] = defaultdict(set)
    for record in auths:
        user = f"{record.get('domain', '')}\\{record.get('user', '')}".strip("\\")
        if user:
            by_user[user].add(record["dst"])
            by_source[record["src"]].add(user)

    spreading = {user: targets for user, targets in by_user.items() if len(targets) >= 6}
    if spreading:
        top = max(spreading, key=lambda u: len(spreading[u]))
        r.findings.append(
            make_finding(
                "ntlm.credential_spread",
                "One account authenticating across many systems",
                "high",
                "Credential attack",
                f"{top} authenticated to {len(spreading[top])} different hosts. "
                f"{len(spreading)} account(s) show this pattern.",
                "An ordinary user account touches a handful of systems. One "
                "reaching many in a short window is either a service account "
                "in the wrong place or an attacker using a stolen credential "
                "to move through the network.",
                "Check whether the account is a designated service or admin "
                "account. If it belongs to a person, disable it and rotate the "
                "password: the pattern indicates the credential is being used "
                "by something other than that person.",
                confidence="medium",
                mitre=["T1550", "T1021"],
                hosts=sorted({h for targets in spreading.values() for h in targets})[:20],
                count=len(spreading),
                evidence=_ev(
                    [
                        {"account": user, "hosts_reached": len(targets),
                         "sample": sorted(targets)[:8]}
                        for user, targets in spreading.items()
                    ]
                ),
            )
        )

    spraying = {source: users for source, users in by_source.items() if len(users) >= 8}
    if spraying:
        top = max(spraying, key=lambda s: len(spraying[s]))
        r.findings.append(
            make_finding(
                "ntlm.password_spraying",
                "Many accounts authenticating from one host",
                "high",
                "Credential attack",
                f"{top} attempted authentication as {len(spraying[top])} "
                "different accounts.",
                "Password spraying tries one common password against every "
                "account rather than many passwords against one, which avoids "
                "the lockout thresholds that stop conventional brute force. "
                "One host cycling through many usernames is its signature.",
                "Review the authentication logs on the targeted servers for "
                "which attempts succeeded. Any account that authenticated from "
                "this host should be treated as compromised.",
                confidence="medium",
                mitre=["T1110.003", "T1110"],
                hosts=sorted(spraying.keys())[:20],
                count=sum(len(u) for u in spraying.values()),
                evidence=_ev(
                    [
                        {"source": source, "accounts_tried": len(users),
                         "sample": sorted(users)[:8]}
                        for source, users in spraying.items()
                    ]
                ),
            )
        )


def detect_smb_issues(r, deep: bool):
    """SMB1 use and unsigned sessions, both of which enable relay attacks."""
    if not r.smb_records:
        return

    smb1 = [record for record in r.smb_records if record.get("version") == "SMB1"]
    if smb1:
        r.findings.append(
            make_finding(
                "smb.v1_in_use",
                "SMB1 in use",
                "high",
                "Legacy protocol",
                f"{len(smb1)} SMB1 messages were exchanged between "
                f"{len({record['src'] for record in smb1})} host(s).",
                "SMB1 has no meaningful integrity protection and is the "
                "protocol EternalBlue and WannaCry spread through. Microsoft "
                "removed it from default installs years ago; where it survives "
                "it is usually attached to equipment nobody wants to touch.",
                "Identify what still needs SMB1, usually a printer, scanner or "
                "an old NAS, and isolate it on its own segment. Disable SMB1 "
                "everywhere else.",
                confidence="high",
                mitre=["T1210"],
                hosts=sorted({record["src"] for record in smb1})[:20],
                count=len(smb1),
                evidence=_ev(
                    [
                        {"source": record["src"], "target": record["dst"],
                         "command": record.get("command")}
                        for record in smb1[:MAX_EVIDENCE]
                    ]
                ),
            )
        )

    unsigned = [
        record for record in r.smb_records
        if record.get("version") == "SMB2/3"
        and record.get("command") == "SessionSetup"
        and not record.get("signed")
    ]
    if len(unsigned) >= 5:
        r.findings.append(
            make_finding(
                "smb.unsigned_sessions",
                "SMB sessions negotiated without signing",
                "medium",
                "Legacy protocol",
                f"{len(unsigned)} SMB session setups completed without message "
                "signing.",
                "Without signing, an attacker who can intercept traffic can "
                "relay an authentication attempt to a different server and act "
                "as that user. Signing is what makes the relay fail, which is "
                "why every NTLM relay tool checks for it first.",
                "Enable SMB signing through group policy, requiring it on "
                "servers and domain controllers.",
                confidence="medium",
                mitre=["T1557", "T1187"],
                hosts=sorted({record["src"] for record in unsigned})[:20],
                count=len(unsigned),
            )
        )


# ---------------------------------------------------------------------------
# Industrial control systems
# ---------------------------------------------------------------------------

def detect_ics_activity(r, deep: bool):
    """Control-system traffic, and the commands that change plant state."""
    if not r.ics_records:
        return

    by_protocol: dict[str, list[dict]] = defaultdict(list)
    for record in r.ics_records:
        by_protocol[record["protocol"]].append(record)

    protocols_seen = sorted(by_protocol.keys())
    all_hosts = sorted({record["src"] for record in r.ics_records}
                       | {record["dst"] for record in r.ics_records})

    r.findings.append(
        make_finding(
            "ics.traffic_present",
            f"Industrial control traffic present ({', '.join(protocols_seen)})",
            "info",
            "Industrial control",
            f"{len(r.ics_records):,} control-system messages were seen across "
            f"{len(protocols_seen)} protocol(s), involving {len(all_hosts)} "
            "hosts.",
            "These protocols were designed for isolated plant networks and "
            "have no authentication or encryption: any host that can reach a "
            "controller can command it. Their presence defines the blast "
            "radius of anything else found in this capture.",
            "Confirm this segment is separated from business networks and that "
            "only the engineering workstations can reach the controllers.",
            confidence="high",
            hosts=all_hosts[:20],
            count=len(r.ics_records),
            evidence=[
                {"protocol": protocol, "messages": len(records),
                 "endpoints": len({rec["dst"] for rec in records})}
                for protocol, records in by_protocol.items()
            ],
        )
    )

    # Commands that write to or halt a controller.
    dangerous = [
        record for record in r.ics_records
        if record.get("dangerous") or record.get("is_write")
    ]
    if dangerous:
        by_source = Counter(record["src"] for record in dangerous)
        r.findings.append(
            make_finding(
                "ics.control_commands",
                "Commands that change controller state",
                "high",
                "Industrial control",
                f"{len(dangerous)} messages issued write, stop or reprogram "
                f"commands, from {len(by_source)} source(s).",
                "Reading values from a controller is routine monitoring. "
                "Writing to one changes what the equipment physically does. "
                "On these protocols there is no authentication step between "
                "the two, so an attacker who reaches the network can command "
                "the plant directly.",
                "Confirm each source is an authorised engineering workstation "
                "or HMI. A write command from anything else, especially from "
                "the business network, is an incident rather than a "
                "configuration question.",
                confidence="medium",
                mitre=["T0855", "T0831"],
                hosts=list(by_source.keys())[:20],
                count=len(dangerous),
                evidence=_ev(
                    [
                        {
                            "protocol": record["protocol"],
                            "source": record["src"],
                            "controller": record["dst"],
                            "command": record.get("function_name"),
                            "packet": record["packet"],
                        }
                        for record in dangerous[:MAX_EVIDENCE]
                    ]
                ),
            )
        )

    # Anything reaching a controller from outside the plant network.
    external_reach = [
        record for record in r.ics_records
        if (r.hosts.get(record["src"]) and not r.hosts[record["src"]].is_private)
    ]
    if external_reach:
        r.findings.append(
            make_finding(
                "ics.external_access",
                "Control systems reached from outside the local network",
                "critical",
                "Industrial control",
                f"{len(external_reach)} control-system messages came from "
                "addresses outside the local network.",
                "Control protocols assume every participant is trusted, "
                "because they were designed for a network with a locked door "
                "around it. An external address speaking them means that "
                "assumption no longer holds and the equipment can be commanded "
                "by whoever is on the other end.",
                "Cut the external path immediately. Then determine how it was "
                "established: an exposed device, a misconfigured firewall rule, "
                "or a remote access tool installed for maintenance.",
                confidence="high",
                mitre=["T0886"],
                hosts=sorted({record["src"] for record in external_reach})[:20],
                count=len(external_reach),
                evidence=_ev(
                    [
                        {
                            "external_source": record["src"],
                            "controller": record["dst"],
                            "protocol": record["protocol"],
                            "command": record.get("function_name"),
                        }
                        for record in external_reach[:MAX_EVIDENCE]
                    ]
                ),
            )
        )


# ---------------------------------------------------------------------------
# IoT
# ---------------------------------------------------------------------------

def detect_iot_issues(r, deep: bool):
    """Unauthenticated MQTT, unencrypted brokers, and device exposure."""
    if not r.iot_records:
        return

    mqtt = [record for record in r.iot_records if record["protocol"] == "MQTT"]
    connects = [record for record in mqtt if record.get("type") == "CONNECT"]

    anonymous = [record for record in connects if record.get("anonymous")]
    if anonymous:
        r.findings.append(
            make_finding(
                "iot.mqtt_anonymous",
                "MQTT brokers accepting connections without credentials",
                "high",
                "IoT exposure",
                f"{len(anonymous)} MQTT clients connected with no username, "
                f"reaching {len({record['dst'] for record in anonymous})} broker(s).",
                "An MQTT broker that accepts anonymous clients lets anyone who "
                "can reach it read every topic and publish to any of them. "
                "Where those topics drive actuators, publishing to them "
                "controls physical devices.",
                "Enable authentication on the broker and give each device its "
                "own credential. Restrict topic access so a compromised sensor "
                "cannot publish to control topics.",
                confidence="high",
                hosts=sorted({record["dst"] for record in anonymous})[:20],
                count=len(anonymous),
                evidence=_ev(
                    [
                        {
                            "client_id": record.get("client_id"),
                            "client": record["src"],
                            "broker": record["dst"],
                            "encrypted": record.get("encrypted", False),
                        }
                        for record in anonymous[:MAX_EVIDENCE]
                    ]
                ),
            )
        )

    cleartext_credentials = [
        record for record in connects
        if record.get("has_password") and not record.get("encrypted")
    ]
    if cleartext_credentials:
        r.findings.append(
            make_finding(
                "iot.mqtt_cleartext_credentials",
                "MQTT credentials sent without encryption",
                "critical",
                "IoT exposure",
                f"{len(cleartext_credentials)} MQTT connections sent a "
                "username and password over an unencrypted channel.",
                "MQTT on port 1883 has no transport encryption. The "
                "credentials in these packets are readable by anyone on the "
                "path, and device credentials are rarely rotated once "
                "deployed.",
                "Move the broker to MQTT over TLS on port 8883 and rotate "
                "every device credential that was used in the clear.",
                confidence="high",
                mitre=["T1040"],
                hosts=sorted({record["src"] for record in cleartext_credentials})[:20],
                count=len(cleartext_credentials),
            )
        )

    ssdp = [record for record in r.iot_records if record["protocol"] == "SSDP"]
    if ssdp:
        devices = {}
        for record in ssdp:
            if record.get("server"):
                devices[record["src"]] = record["server"]
        if devices:
            r.findings.append(
                make_finding(
                    "iot.device_discovery",
                    "Devices announcing themselves over SSDP",
                    "low",
                    "IoT exposure",
                    f"{len(devices)} devices advertised their make and firmware "
                    "version on the local network.",
                    "SSDP announcements name the device and its firmware to "
                    "anyone listening. That is exactly the inventory an "
                    "attacker needs to look up which of them has an unpatched "
                    "vulnerability.",
                    "Disable UPnP on devices that do not need it, and block "
                    "SSDP at segment boundaries so announcements stay local.",
                    confidence="high",
                    hosts=sorted(devices.keys())[:20],
                    count=len(devices),
                    evidence=_ev(
                        [
                            {"device": ip, "announces": server}
                            for ip, server in list(devices.items())[:MAX_EVIDENCE]
                        ]
                    ),
                )
            )


# ---------------------------------------------------------------------------
# Wireless
# ---------------------------------------------------------------------------

def detect_wifi_attacks(r, deep: bool):
    """Deauthentication floods, evil twins, and handshake capture."""
    if not r.wifi_records:
        return

    deauths = [
        record for record in r.wifi_records
        if record.get("subtype") in ("Deauthentication", "Disassociation")
    ]

    if len(deauths) >= 20:
        by_source = Counter(record.get("source") for record in deauths)
        times = sorted(record["ts"] for record in deauths)
        span = max(1.0, times[-1] - times[0])
        rate = len(deauths) / span

        r.findings.append(
            make_finding(
                "wifi.deauth_flood",
                "Deauthentication flood",
                "high",
                "Wireless attack",
                f"{len(deauths)} deauthentication frames were sent in "
                f"{span:.0f} seconds ({rate:.1f} per second), from "
                f"{len(by_source)} source address(es).",
                "A deauthentication frame tells a client it has been "
                "disconnected. Unless the network enables management frame "
                "protection, these frames are unauthenticated, so anyone "
                "nearby can forge them. Attackers send them in bulk to knock "
                "clients off, either to deny service or to force a reconnection "
                "whose handshake they can capture and crack.",
                "Enable 802.11w management frame protection on the access "
                "points. Then check whether a WPA handshake was captured "
                "immediately after this burst, which would indicate the goal "
                "was credential capture rather than disruption.",
                confidence="high",
                mitre=["T1499"],
                count=len(deauths),
                first_seen=times[0],
                last_seen=times[-1],
                evidence=_ev(
                    [
                        {"source": source, "frames": count,
                         "note": "Source address in a forged frame is itself "
                                 "unverifiable"}
                        for source, count in by_source.most_common(MAX_EVIDENCE)
                    ]
                ),
            )
        )

    # One SSID served by several radios, or served with different security.
    evil_twins = []
    for ssid, entry in r.wifi_networks.items():
        if ssid == "<hidden>":
            continue
        if len(entry["bssids"]) > 1:
            evil_twins.append(
                {
                    "ssid": ssid,
                    "access_points": sorted(entry["bssids"])[:8],
                    "count": len(entry["bssids"]),
                    "security": sorted(entry["security"]),
                    "mixed_security": len(entry["security"]) > 1,
                }
            )

    if evil_twins:
        mixed = [entry for entry in evil_twins if entry["mixed_security"]]
        severity = "high" if mixed else "medium"
        r.findings.append(
            make_finding(
                "wifi.evil_twin",
                "One network name advertised by multiple access points",
                severity,
                "Wireless attack",
                f"{len(evil_twins)} network name(s) were advertised by more "
                "than one radio."
                + (
                    f" {len(mixed)} of them advertised different security "
                    "settings, which a legitimate deployment does not do."
                    if mixed else ""
                ),
                "Multiple access points sharing an SSID is normal in any "
                "building with roaming. It is also exactly what an evil twin "
                "looks like: a rogue radio broadcasting a familiar name so "
                "clients associate with it automatically. Differing security "
                "settings across the same name is the part that cannot be "
                "explained by roaming.",
                "Compare the hardware addresses against your access point "
                "inventory. Any radio not on the list is rogue and should be "
                "located physically.",
                confidence="medium" if mixed else "low",
                mitre=["T1557"],
                count=len(evil_twins),
                evidence=_ev(evil_twins),
            )
        )

    # A complete four-way handshake is offline-crackable material.
    handshakes = [
        record for record in r.wifi_records
        if record.get("subtype") == "EAPOL" and record.get("handshake_message")
    ]
    if handshakes:
        messages = {record["handshake_message"] for record in handshakes}
        if len(messages & {1, 2}) == 2:
            r.findings.append(
                make_finding(
                    "wifi.handshake_captured",
                    "WPA handshake present in the capture",
                    "high",
                    "Wireless attack",
                    f"{len(handshakes)} EAPOL key frames were captured, "
                    f"including handshake messages {sorted(messages)}.",
                    "The first two messages of the four-way handshake are "
                    "enough to attempt the wireless passphrase offline, at "
                    "whatever speed the attacker's hardware allows. No further "
                    "network access is needed once these frames are recorded.",
                    "Treat the wireless passphrase as exposed and change it. "
                    "For networks that matter, move to WPA3 or 802.1X, where "
                    "capturing the handshake does not yield the credential.",
                    confidence="high",
                    mitre=["T1040"],
                    count=len(handshakes),
                )
            )


# ---------------------------------------------------------------------------
# QUIC
# ---------------------------------------------------------------------------

def detect_quic_usage(r, deep: bool):
    """QUIC sessions, and the visibility gap they create."""
    if not r.quic_records:
        return

    initials = [record for record in r.quic_records if record.get("type") == "initial"]
    if not initials:
        return

    destinations = Counter(record["dst"] for record in initials)
    external = [
        record for record in initials
        if r.hosts.get(record["dst"]) and not r.hosts[record["dst"]].is_private
    ]
    unknown_versions = [
        record for record in initials if not record.get("is_known_version")
    ]

    r.findings.append(
        make_finding(
            "quic.in_use",
            "QUIC sessions established",
            "low",
            "Encrypted transport",
            f"{len(initials)} QUIC connections were opened to "
            f"{len(destinations)} destination(s), {len(external)} of them "
            "external.",
            "QUIC encrypts its handshake, so the server name that a TLS "
            "ClientHello would reveal is not visible here. Anything relying on "
            "reading the destination name, including most web filtering, sees "
            "nothing on these connections. Browsers use QUIC by default, so "
            "its presence is normal, but the blind spot is real.",
            "If you need name-level visibility, block UDP 443 at the perimeter "
            "so clients fall back to TCP where the server name is readable.",
            confidence="high",
            hosts=sorted({record["src"] for record in initials})[:20],
            count=len(initials),
            evidence=_ev(
                [
                    {"destination": destination, "connections": count,
                     "version": next(
                         (record["version_name"] for record in initials
                          if record["dst"] == destination), "unknown")}
                    for destination, count in destinations.most_common(MAX_EVIDENCE)
                ]
            ),
        )
    )

    if unknown_versions:
        r.findings.append(
            make_finding(
                "quic.unknown_version",
                "QUIC connections using an unrecognised version",
                "medium",
                "Encrypted transport",
                f"{len(unknown_versions)} QUIC packets advertised a version "
                "number outside the published set.",
                "Standard browsers negotiate published QUIC versions. A "
                "non-standard version number means a custom implementation, "
                "which is worth explaining: it is a way to build an encrypted "
                "channel that ordinary tooling cannot classify.",
                "Identify the process on the source host. If it is not a "
                "browser or a known application, treat the destination as a "
                "candidate command and control endpoint.",
                confidence="low",
                mitre=["T1573"],
                hosts=sorted({record["src"] for record in unknown_versions})[:20],
                count=len(unknown_versions),
                evidence=_ev(
                    [
                        {"source": record["src"], "destination": record["dst"],
                         "version": record["version_name"]}
                        for record in unknown_versions[:MAX_EVIDENCE]
                    ]
                ),
            )
        )


# ---------------------------------------------------------------------------
# Captured credentials
# ---------------------------------------------------------------------------

def detect_captured_credentials(r, deep: bool):
    """
    Raise findings for authentication material recovered from the capture.

    Plaintext passwords and challenge-response hashes are separated because
    the response differs. A plaintext password is compromised the moment
    the traffic is captured. A hash is compromised once it is cracked,
    which buys time proportional to the password's strength and nothing
    more.
    """
    creds = getattr(r, "credentials", [])
    if not creds:
        return

    plaintext = [c for c in creds if c.get("secret_kind") == "password"]
    crackable = [
        c for c in creds
        if c.get("secret_kind") in ("hash", "challenge-response")
        and c.get("crackable", True)
    ]
    tokens = [c for c in creds if c.get("secret_kind") == "token"]

    def rows(entries):
        return [
            {
                "protocol": c["protocol"],
                "method": c["method"],
                "username": c.get("username"),
                "secret": c.get("secret"),
                "client": c["client"],
                "server": f"{c['server']}:{c['server_port']}",
                "packet": c.get("packet"),
            }
            for c in entries[:MAX_EVIDENCE]
        ]

    if plaintext:
        by_protocol = Counter(c["protocol"] for c in plaintext)
        accounts = sorted({c["username"] for c in plaintext if c.get("username")})
        r.findings.append(
            make_finding(
                "credentials.cleartext",
                "Usernames and passwords recovered from the capture",
                "critical",
                "Credential exposure",
                f"{len(plaintext)} set(s) of credentials were sent in a form "
                f"readable directly from the traffic, across "
                f"{len(by_protocol)} protocol(s): "
                f"{', '.join(f'{p} ({n})' for p, n in by_protocol.most_common())}."
                + (f" Accounts: {', '.join(accounts[:8])}." if accounts else ""),
                "These passwords were not protected in transit. Anyone who "
                "captured this traffic — as this capture just did — holds "
                "them in full. There is no cracking step and no delay: they "
                "are usable now. Base64 encoding, where it was used, is a "
                "transport convenience and not a protection. Password reuse "
                "means each one may open more than the service it was sent to.",
                "Treat every account listed here as compromised and reset it. "
                "Move the affected services onto their encrypted equivalents: "
                "FTPS or SFTP for FTP, IMAPS and POP3S for mail retrieval, "
                "SMTP over TLS for submission, SSH in place of Telnet. Then "
                "look for where these passwords were reused.",
                confidence="high",
                mitre=["T1040", "T1552.001"],
                hosts=sorted({c["client"] for c in plaintext})[:20],
                count=len(plaintext),
                evidence=rows(plaintext),
            )
        )

    if crackable:
        by_protocol = Counter(c["protocol"] for c in crackable)
        ntlmv1 = [c for c in crackable if "NTLMv1" in c.get("method", "")]
        r.findings.append(
            make_finding(
                "credentials.crackable_hashes",
                "Authentication hashes recovered from the capture",
                "high",
                "Credential exposure",
                f"{len(crackable)} challenge-response authentication(s) were "
                f"captured across "
                f"{', '.join(f'{p} ({n})' for p, n in by_protocol.most_common())}."
                + (f" {len(ntlmv1)} of them used NTLMv1." if ntlmv1 else ""),
                "These schemes never send the password itself, so they are "
                "better than plaintext. What they do send is a value computed "
                "from the password and a server challenge, and that can be "
                "attacked offline at whatever speed the attacker's hardware "
                "allows, with no failed logins and no lockouts to alert "
                "anyone. A weak password falls in minutes."
                + (" NTLMv1 is worse still: its responses can be reversed to "
                   "the password hash using precomputed tables rather than "
                   "guessed." if ntlmv1 else ""),
                "Reset the affected accounts, prioritising any that are "
                "privileged. Move these services to TLS so the exchange is "
                "not observable, and disable the weaker mechanisms: NTLMv1, "
                "and MD5-based digest authentication.",
                confidence="high",
                mitre=["T1040", "T1110.002"],
                hosts=sorted({c["client"] for c in crackable})[:20],
                count=len(crackable),
                evidence=rows(crackable),
            )
        )

    if tokens:
        r.findings.append(
            make_finding(
                "credentials.tokens",
                "Authentication tokens observed in traffic",
                "medium",
                "Credential exposure",
                f"{len(tokens)} authentication token(s) were sent over an "
                "unencrypted channel.",
                "A bearer token is a credential in its own right: whoever "
                "holds it is authenticated, without needing the password. "
                "Sent in the clear, it is usable by anyone on the path until "
                "it expires.",
                "Revoke the tokens and move the service to TLS. Where the "
                "mechanism supports it, shorten token lifetimes so an "
                "intercepted token has a narrow window.",
                confidence="medium",
                mitre=["T1040", "T1550.001"],
                hosts=sorted({c["client"] for c in tokens})[:20],
                count=len(tokens),
                evidence=rows(tokens),
            )
        )


# ---------------------------------------------------------------------------
# VoIP
# ---------------------------------------------------------------------------

def detect_voip(r, deep: bool):
    """
    Findings from SIP signalling and RTP media.

    Telephony is worth its own attention because the failure modes cost
    money directly. A cracked SIP password is used for toll fraud within
    hours, and unencrypted RTP means every call in the capture can be
    replayed as audio by anyone who has the file.
    """
    calls = getattr(r, "calls", {})
    streams = getattr(r, "rtp_streams", {})
    messages = getattr(r, "sip_messages", [])
    if not calls and not streams and not messages:
        return

    call_list = [c.to_dict() for c in calls.values()]
    answered = [c for c in call_list if c["answered"]]

    # --- inventory ---
    r.findings.append(
        make_finding(
            "voip.activity",
            "VoIP telephony present",
            "info",
            "Telephony",
            f"{len(call_list)} SIP dialogue(s) and {len(streams)} media "
            f"stream(s), {len(answered)} of the calls answered.",
            "Telephony traffic identifies who spoke to whom and when, which "
            "is often the fastest way to establish a timeline. It also "
            "defines what an attacker on this network could reach: SIP "
            "credentials are directly monetisable through toll fraud.",
            "Confirm the SIP registrar and media gateways are the ones you "
            "expect, and that call signalling does not cross network "
            "boundaries in the clear.",
            confidence="high",
            count=len(call_list),
            evidence=_ev(
                [
                    {
                        "from": c["caller"],
                        "to": c["callee"],
                        "answered": c["answered"],
                        "duration_seconds": c["duration"],
                        "status": c["final_status"],
                        "software": ", ".join(c["user_agents"][:2]),
                    }
                    for c in call_list[:MAX_EVIDENCE]
                ]
            ),
        )
    )

    # --- unencrypted media ---
    plaintext_media = [
        s for s in streams.values() if s["packets"] > 20
    ]
    unencrypted_calls = [c for c in call_list if not c["media_encrypted"]]

    if plaintext_media:
        total_seconds = sum(s.get("duration", 0) for s in plaintext_media)
        r.findings.append(
            make_finding(
                "voip.unencrypted_media",
                "Call audio carried without encryption",
                "high",
                "Telephony",
                f"{len(plaintext_media)} RTP streams totalling roughly "
                f"{total_seconds:.0f} seconds of media used plain RTP rather "
                "than SRTP.",
                "Plain RTP is the audio itself, in a standard codec, with no "
                "protection. Anyone holding this capture can reassemble the "
                "streams and listen to the conversations — there is no key "
                "to recover and no cracking step. Whatever was discussed on "
                "these calls should be treated as disclosed.",
                "Enable SRTP on the phones and gateway, and SIP over TLS for "
                "the signalling that negotiates the keys. Until then, treat "
                "any network segment carrying voice as carrying the content "
                "of every call on it.",
                confidence="high",
                mitre=["T1040"],
                hosts=sorted({s["src"] for s in plaintext_media})[:20],
                count=len(plaintext_media),
                evidence=_ev(
                    [
                        {
                            "from": f"{s['src']}:{s['src_port']}",
                            "to": f"{s['dst']}:{s['dst_port']}",
                            "codec": s["codec"],
                            "seconds": s.get("duration"),
                            "packets": s["packets"],
                        }
                        for s in sorted(
                            plaintext_media, key=lambda x: -x["packets"]
                        )[:MAX_EVIDENCE]
                    ]
                ),
            )
        )

    # --- registration hammering, the shape of a SIP password attack ---
    register_attempts: dict[tuple, list] = defaultdict(list)
    for call in call_list:
        for attempt in call["auth_attempts"]:
            if attempt.get("direction") != "response":
                continue
            key = (attempt.get("src"), attempt.get("username"))
            register_attempts[key].append(attempt)

    hammering = {
        key: attempts for key, attempts in register_attempts.items()
        if len(attempts) >= 5
    }
    if hammering:
        worst = max(hammering.values(), key=len)
        r.findings.append(
            make_finding(
                "voip.registration_attack",
                "Repeated SIP authentication attempts",
                "high",
                "Telephony",
                f"{sum(len(v) for v in hammering.values())} digest responses "
                f"were sent across {len(hammering)} account(s), the most "
                f"active making {len(worst)} attempts.",
                "A phone registers, gets challenged, answers once and stays "
                "registered. Repeated authentication for the same account is "
                "either a misconfigured device retrying, or someone working "
                "through passwords. The second case ends in toll fraud: a "
                "working SIP credential is used to place premium-rate calls, "
                "usually overnight and usually at scale.",
                "Check whether the source is a known handset. If it is not, "
                "block it at the SBC and rotate the account password. Rate "
                "limit registration attempts and alert on failures per "
                "account.",
                confidence="medium",
                mitre=["T1110"],
                hosts=sorted({k[0] for k in hammering if k[0]})[:20],
                count=len(hammering),
                evidence=_ev(
                    [
                        {
                            "source": key[0],
                            "account": key[1],
                            "attempts": len(attempts),
                            "realm": attempts[0].get("realm"),
                        }
                        for key, attempts in hammering.items()
                    ]
                ),
            )
        )

    # --- scanning and spoofed INVITEs ---
    sip_scanners = Counter()
    for message in messages:
        agent = (message.get("user_agent") or "").lower()
        if any(
            marker in agent
            for marker in ("sipvicious", "friendly-scanner", "sundayddr",
                           "sipcli", "sip-scan", "vaxsipuseragent", "metasploit")
        ):
            sip_scanners[message["src"]] += 1

    if sip_scanners:
        r.findings.append(
            make_finding(
                "voip.scanner",
                "SIP scanning tool identified",
                "high",
                "Telephony",
                f"{sum(sip_scanners.values())} messages came from software "
                "that identifies itself as a SIP scanning or attack tool, "
                f"from {len(sip_scanners)} source(s).",
                "These tools enumerate extensions and guess passwords. They "
                "announce themselves in the User-Agent header, which means "
                "either an unsophisticated attacker or an authorised test. "
                "Either way the traffic is not a phone.",
                "Confirm whether a penetration test was scheduled. If not, "
                "block the source and review whether any extension "
                "registered successfully afterwards.",
                confidence="high",
                mitre=["T1595"],
                hosts=list(sip_scanners.keys())[:20],
                count=sum(sip_scanners.values()),
                evidence=_ev(
                    [
                        {"source": source, "messages": count}
                        for source, count in sip_scanners.most_common(MAX_EVIDENCE)
                    ]
                ),
            )
        )

    # --- forged routing headers ---
    spoofed = []
    for message in messages:
        if not message.get("is_request") or message.get("method") != "INVITE":
            continue
        source = message.get("src")
        vias = message.get("via_hosts") or []
        contact = message.get("contact") or ""

        # Via names the host a reply should go back to. When it does not
        # match where the packet actually came from, the sender is either
        # behind a NAT it has not accounted for, or is deliberately
        # directing responses somewhere else.
        via_mismatch = bool(vias) and not any(
            source == via.split(":")[0] for via in vias
        )
        loopback_contact = "127.0.0.1" in contact or "localhost" in contact

        if via_mismatch or loopback_contact:
            reasons = []
            if via_mismatch:
                reasons.append(
                    f"Via claims {vias[0]} but the packet came from {source}"
                )
            if loopback_contact:
                reasons.append("Contact points at the loopback address")
            spoofed.append(
                {
                    "source": source,
                    "target": message.get("dst"),
                    "from": message.get("from"),
                    "to": message.get("to"),
                    "via": vias[0] if vias else None,
                    "contact": contact or None,
                    "packet": message.get("packet"),
                    "why": "; ".join(reasons),
                }
            )

    if spoofed:
        r.findings.append(
            make_finding(
                "voip.spoofed_invite",
                "Call setup with forged routing headers",
                "high",
                "Telephony",
                f"{len(spoofed)} INVITE(s) carried routing headers that do "
                "not match where the packet came from.",
                "SIP takes the Via and Contact headers at their word when "
                "deciding where to send replies and media. A mismatch means "
                "responses are being aimed somewhere other than the sender: "
                "that is used to make a target call an arbitrary third party, "
                "to amplify traffic at a victim, or simply to obscure who "
                "placed the call. A Contact on the loopback address cannot "
                "be a real endpoint at all.",
                "Configure the SBC or PBX to reject INVITEs whose Via does "
                "not match the source address, and to ignore Contact headers "
                "pointing at loopback or private ranges from outside. Check "
                "whether any of these attempts were answered.",
                confidence="medium",
                mitre=["T1036"],
                hosts=sorted({row["source"] for row in spoofed if row["source"]})[:20],
                count=len(spoofed),
                evidence=_ev(spoofed),
            )
        )

    # --- calls that never connected, in bulk ---
    failed = [
        c for c in call_list
        if c["final_status"] and c["final_status"] >= 400
    ]
    if len(failed) >= 10 and len(failed) > len(answered):
        statuses = Counter(c["final_status"] for c in failed)
        r.findings.append(
            make_finding(
                "voip.enumeration",
                "Many call attempts rejected",
                "medium",
                "Telephony",
                f"{len(failed)} dialogues ended in an error response against "
                f"{len(answered)} answered, most commonly "
                f"{statuses.most_common(1)[0][0]}.",
                "A high proportion of rejected calls with few successes is "
                "the pattern of extension enumeration: the attacker dials "
                "through a range and reads the difference between 'does not "
                "exist' and 'exists but requires authentication' from the "
                "response code.",
                "Configure the PBX to return the same response for unknown "
                "and unauthorised extensions, so enumeration yields nothing.",
                confidence="low",
                mitre=["T1595"],
                count=len(failed),
                evidence=_ev(
                    [
                        {"status": status, "count": count}
                        for status, count in statuses.most_common(MAX_EVIDENCE)
                    ]
                ),
            )
        )

    # --- media quality, which matters for the "was this call usable" question
    degraded = [
        s for s in streams.values()
        if s.get("loss_percent", 0) > 5 and s["packets"] > 50
    ]
    if degraded:
        r.findings.append(
            make_finding(
                "voip.media_loss",
                "Packet loss on call audio",
                "low",
                "Telephony",
                f"{len(degraded)} media stream(s) lost more than 5% of their "
                "packets.",
                "Loss above a few percent is audible as dropouts. This is "
                "usually a network problem rather than a security one, but "
                "it belongs in the record: it explains complaints, and "
                "sudden loss across many streams can also indicate "
                "congestion caused by something else in this capture.",
                "Check the path between the affected endpoints for "
                "congestion or a duplex mismatch. If the loss coincides with "
                "other findings here, treat it as a symptom rather than the "
                "cause.",
                confidence="medium",
                count=len(degraded),
                evidence=_ev(
                    [
                        {
                            "from": f"{s['src']}:{s['src_port']}",
                            "to": f"{s['dst']}:{s['dst_port']}",
                            "loss_percent": s["loss_percent"],
                            "packets": s["packets"],
                            "codec": s["codec"],
                        }
                        for s in sorted(
                            degraded, key=lambda x: -x["loss_percent"]
                        )[:MAX_EVIDENCE]
                    ]
                ),
            )
        )


# ---------------------------------------------------------------------------
# Analysis environment
# ---------------------------------------------------------------------------

# Fingerprints left by network simulators used in malware sandboxes. When
# these are present, nothing about the "external" side of the capture is
# real, which changes how every other finding should be read.
SIMULATOR_MARKERS = [
    (b"INetSim", "INetSim",
     "INetSim answers every protocol with a canned response so malware "
     "believes it has internet access."),
    (b"FakeNet", "FakeNet-NG",
     "FakeNet-NG intercepts all traffic and replies locally."),
    (b"This is the default HTML page for INetSim", "INetSim",
     "The INetSim default web page was served."),
]


def detect_simulated_environment(r, deep: bool):
    """
    Notice when the capture came from a sandbox rather than a real network.

    This matters more than it first appears. In a simulated environment
    every external address resolves, every connection succeeds, and every
    download returns content — none of which happened on a real network.
    An analyst reading "the host contacted 40 external servers" without
    knowing this will draw the wrong conclusion.
    """
    evidence = []
    tools = set()

    for record in r.http_records:
        surface = " ".join(
            str(record.get(field) or "")
            for field in ("server", "body_preview", "host", "uri")
        ).encode("utf-8", "replace")
        for marker, tool, explanation in SIMULATOR_MARKERS:
            if marker.lower() in surface.lower():
                tools.add(tool)
                if len(evidence) < MAX_EVIDENCE:
                    evidence.append(
                        {
                            "source": record.get("src"),
                            "server": record.get("dst"),
                            "detail": explanation,
                            "packet": record.get("packet"),
                        }
                    )

    for record in r.files:
        for marker, tool, explanation in SIMULATOR_MARKERS:
            if marker.decode() in (record.get("filename") or ""):
                tools.add(tool)

    # Identical responses to every request is the other tell: a real web
    # server does not return byte-for-byte the same page for every host.
    if r.files:
        hashes = Counter(f["sha256"] for f in r.files)
        top_hash, repeats = hashes.most_common(1)[0]
        distinct_sources = len({
            f["source"] for f in r.files if f["sha256"] == top_hash
        })
        if repeats >= 4 and distinct_sources >= 3:
            tools.add("uniform responder")
            evidence.append(
                {
                    "detail": f"The same {repeats} responses came from "
                              f"{distinct_sources} different servers, "
                              "byte for byte identical.",
                    "sha256": top_hash,
                }
            )

    if not tools:
        return

    r.findings.append(
        make_finding(
            "environment.simulated",
            "Capture taken in a simulated network environment",
            "info",
            "Analysis context",
            f"Signs of {', '.join(sorted(tools))} were found: the external "
            "side of this capture was answered by a simulator rather than by "
            "real servers.",
            "This changes how everything else here should be read. In a "
            "sandbox every domain resolves, every connection is accepted and "
            "every download returns content, so 'the host reached this "
            "server' does not mean the server exists or that it would have "
            "responded. What remains reliable is what the sample tried to "
            "do: the domains it wanted, the requests it made, the order it "
            "made them in.",
            "Read the outbound requests as intent rather than as achieved "
            "contact. The addresses in this capture belong to the sandbox, "
            "so do not add them to a blocklist; the domain names and URLs "
            "requested are the indicators worth keeping.",
            confidence="high",
            count=len(evidence),
            evidence=_ev(evidence),
        )
    )


# ---------------------------------------------------------------------------
# Lookalike domains
# ---------------------------------------------------------------------------

# Brands whose names are worth impersonating. Kept short deliberately:
# a long list produces more false matches than useful ones.
IMPERSONATION_TARGETS = [
    "google.com", "gmail.com", "youtube.com", "facebook.com", "instagram.com",
    "microsoft.com", "outlook.com", "office.com", "live.com", "windows.com",
    "apple.com", "icloud.com", "amazon.com", "netflix.com", "paypal.com",
    "yahoo.com", "twitter.com", "linkedin.com", "dropbox.com", "adobe.com",
    "whatsapp.com", "telegram.org", "steamcommunity.com", "github.com",
    "wetransfer.com", "docusign.com", "chase.com", "wellsfargo.com",
    "bankofamerica.com", "hsbc.com", "santander.com", "binance.com",
]


def _edit_distance(a: str, b: str, ceiling: int = 3) -> int:
    """Levenshtein distance, abandoned once it passes the ceiling."""
    if abs(len(a) - len(b)) > ceiling:
        return ceiling + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (ca != cb),
                )
            )
        if min(current) > ceiling:
            return ceiling + 1
        previous = current
    return previous[-1]


def detect_lookalike_domains(r, deep: bool):
    """
    Find domains that imitate a well-known one.

    Typosquats are registered to catch mistyped addresses and to make a
    phishing link survive a glance. A name one character away from a brand
    the organisation uses is worth a look, even though some will be
    legitimate.
    """
    queried: set[str] = set()
    for record in r.dns_records:
        for query in record.get("queries", []):
            name = (query.get("name") or "").lower().strip(".")
            if name:
                queried.add(name)
    for record in r.http_records:
        host = (record.get("host") or "").lower()
        if host and not host.replace(".", "").isdigit():
            queried.add(host)
    for record in r.tls_records:
        sni = (record.get("sni") or "").lower()
        if sni:
            queried.add(sni)

    hits = []
    for name in queried:
        labels = name.split(".")
        if len(labels) < 2:
            continue
        registrable = ".".join(labels[-2:])

        for target in IMPERSONATION_TARGETS:
            if registrable == target:
                break  # the real thing
            distance = _edit_distance(registrable, target)
            if 0 < distance <= 2 and abs(len(registrable) - len(target)) <= 2:
                hits.append(
                    {
                        "domain": name,
                        "resembles": target,
                        "edit_distance": distance,
                        "why": _lookalike_reason(registrable, target),
                    }
                )
                break

    if not hits:
        return

    r.findings.append(
        make_finding(
            "phishing.lookalike_domain",
            "Domains resembling well-known brands",
            "high",
            "Suspicious infrastructure",
            f"{len(hits)} domain(s) queried in this capture are within a "
            "character or two of a widely recognised name: "
            + ", ".join(f"{h['domain']} (like {h['resembles']})" for h in hits[:4])
            + ".",
            "Names this close to a brand are registered for a reason. They "
            "catch typing mistakes, and they survive the quick glance a user "
            "gives a link before clicking. A host resolving one has usually "
            "either followed a link from a message or been redirected there.",
            "Check what the user did next on that host: whether credentials "
            "were submitted, and whether anything was downloaded. Block the "
            "domain and look for the message that delivered the link.",
            confidence="medium",
            mitre=["T1566.002", "T1583.001"],
            count=len(hits),
            evidence=_ev(hits),
        )
    )


def _lookalike_reason(candidate: str, target: str) -> str:
    """Say what was changed, which makes the match self-evident."""
    if len(candidate) == len(target) + 1:
        return f"a character inserted into {target}"
    if len(candidate) == len(target) - 1:
        return f"a character removed from {target}"
    differences = [
        (a, b) for a, b in zip(candidate, target) if a != b
    ]
    if len(differences) == 1:
        return f"'{differences[0][1]}' replaced with '{differences[0][0]}'"
    return f"two characters differ from {target}"
