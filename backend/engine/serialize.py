"""
Turn an AnalysisResult into the JSON the interface consumes.

Includes graph construction: nodes are hosts grouped by subnet, edges are
conversations weighted by volume. The graph is trimmed before it leaves
the server so the browser never has to lay out more elements than a
person can read.
"""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict

from .oui import lookup_vendor
from .reader import LINKTYPE_NAMES
from .services import TCP_SERVICES, UDP_SERVICES, service_name


def _served_label(port: int) -> str:
    """Name a served port without assuming TCP: 53, 123 and 5060 are UDP."""
    return (TCP_SERVICES.get(port) or UDP_SERVICES.get(port)
            or ("Ephemeral" if port >= 49152 else f"port {port}"))

MAX_GRAPH_NODES = 300
MAX_GRAPH_EDGES = 900
MAX_TABLE_ROWS = 500


def _subnet_of(ip: str) -> str:
    """Group label for a host: /24 for IPv4, /64 for IPv6."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.version == 4:
        parts = ip.split(".")
        return ".".join(parts[:3]) + ".0/24"
    exploded = addr.exploded.split(":")
    return ":".join(exploded[:4]) + "::/64"


def _host_role(host, flows_by_host) -> str:
    """Classify a host so the graph can shape it meaningfully."""
    if host.ports_served:
        well_known = [p for p in host.ports_served if p < 1024]
        if well_known:
            return "server"
    if not host.is_private:
        return "external"
    if len(host.peers) > 20:
        return "hub"
    return "client"


def build_graph(result) -> dict:
    """
    Build the node and edge lists for the network map.

    Nodes carry enough detail for the side panel, so clicking a host does
    not need another round trip.
    """
    hosts = result.hosts
    if not hosts:
        return {"nodes": [], "edges": [], "groups": [], "truncated": False}

    # Rank hosts by how much they matter: risk first, then volume.
    ranked = sorted(
        hosts.values(),
        key=lambda h: (h.risk, h.bytes_sent + h.bytes_recv),
        reverse=True,
    )
    kept = ranked[:MAX_GRAPH_NODES]
    kept_ips = {h.ip for h in kept}

    flows_by_host = defaultdict(list)
    for flow in result.flows.values():
        flows_by_host[flow.src].append(flow)
        flows_by_host[flow.dst].append(flow)

    max_bytes = max((h.bytes_sent + h.bytes_recv) for h in kept) or 1

    nodes = []
    groups: Counter = Counter()

    for host in kept:
        total_bytes = host.bytes_sent + host.bytes_recv
        subnet = _subnet_of(host.ip)
        groups[subnet] += 1
        vendor = None
        for mac in list(host.macs)[:1]:
            vendor = lookup_vendor(mac)

        nodes.append(
            {
                "id": host.ip,
                "label": (
                    sorted(host.hostnames)[0]
                    if host.hostnames
                    else host.ip
                ),
                "ip": host.ip,
                "ip_version": host.version,
                "subnet": subnet,
                "role": _host_role(host, flows_by_host),
                "internal": host.is_private,
                "risk": host.risk,
                "weight": round((total_bytes / max_bytes) ** 0.4, 4),
                "bytes_total": total_bytes,
                "bytes_sent": host.bytes_sent,
                "bytes_received": host.bytes_recv,
                "packets_sent": host.packets_sent,
                "packets_received": host.packets_recv,
                "peers": len(host.peers),
                "macs": sorted(host.macs)[:4],
                "vendor": vendor,
                "hostnames": sorted(host.hostnames)[:4],
                "ports_served": sorted(host.ports_served)[:20],
                "services": [
                    _served_label(p) for p in sorted(host.ports_served)[:8]
                ],
                "ports_contacted": len(host.ports_contacted),
                "top_protocols": host.protocols.most_common(4),
                "user_agents": sorted(host.user_agents)[:3],
                "ja3": sorted(host.ja3)[:3],
                "ttl_values": sorted(host.ttl_values)[:4],
                "tags": sorted(host.tags)[:6],
                "first_seen": host.first_seen,
                "last_seen": host.last_seen,
            }
        )

    # Collapse flows into one edge per host pair.
    edge_map: dict[tuple, dict] = {}
    for flow in result.flows.values():
        if flow.src not in kept_ips or flow.dst not in kept_ips:
            continue
        key = tuple(sorted((flow.src, flow.dst)))
        edge = edge_map.get(key)
        if edge is None:
            edge = {
                "source": key[0],
                "target": key[1],
                "bytes": 0,
                "packets": 0,
                "flows": 0,
                "services": Counter(),
                "ports": set(),
            }
            edge_map[key] = edge
        edge["bytes"] += flow.total_bytes
        edge["packets"] += flow.total_packets
        edge["flows"] += 1
        if flow.service:
            edge["services"][flow.service] += 1
        edge["ports"].add(flow.dport)

    edges_sorted = sorted(edge_map.values(), key=lambda e: -e["bytes"])
    truncated = len(edges_sorted) > MAX_GRAPH_EDGES
    edges_sorted = edges_sorted[:MAX_GRAPH_EDGES]

    max_edge_bytes = max((e["bytes"] for e in edges_sorted), default=1) or 1

    risky_hosts = {
        ip
        for finding in result.findings
        if finding.severity in ("critical", "high")
        for ip in finding.hosts
    }

    edges = []
    for index, edge in enumerate(edges_sorted):
        top_service = (
            edge["services"].most_common(1)[0][0] if edge["services"] else "—"
        )
        edges.append(
            {
                "id": f"e{index}",
                "source": edge["source"],
                "target": edge["target"],
                "bytes": edge["bytes"],
                "packets": edge["packets"],
                "flows": edge["flows"],
                "service": top_service,
                "services": [s for s, _ in edge["services"].most_common(4)],
                "ports": sorted(edge["ports"])[:8],
                "weight": round((edge["bytes"] / max_edge_bytes) ** 0.35, 4),
                "suspect": edge["source"] in risky_hosts
                and edge["target"] in risky_hosts,
            }
        )

    return {
        "nodes": nodes,
        "edges": edges,
        "groups": [
            {"id": subnet, "count": count}
            for subnet, count in groups.most_common()
        ],
        "truncated": truncated or len(ranked) > MAX_GRAPH_NODES,
        "total_hosts": len(hosts),
        "shown_hosts": len(nodes),
    }


def build_timeline(result, buckets: int = 180) -> list[dict]:
    """Downsample the per-second timeline into a fixed number of buckets."""
    if not result.timeline:
        return []

    times = sorted(result.timeline.keys())
    start, end = times[0], times[-1]
    span = max(1, end - start)
    width = max(1, span // buckets)

    grouped: dict[int, dict] = {}
    for second, entry in result.timeline.items():
        slot = (second - start) // width
        target = grouped.setdefault(
            slot, {"t": start + slot * width, "packets": 0, "bytes": 0}
        )
        target["packets"] += entry["packets"]
        target["bytes"] += entry["bytes"]

    return [grouped[k] for k in sorted(grouped)]


def build_report(result, meta: dict) -> dict:
    """Assemble the full report payload."""
    info = result.capture

    top_talkers = sorted(
        result.hosts.values(),
        key=lambda h: h.bytes_sent + h.bytes_recv,
        reverse=True,
    )[:25]

    top_conversations = [
        {
            "a": pair[0],
            "b": pair[1],
            "bytes": byte_count,
        }
        for pair, byte_count in result.conversation_bytes.most_common(25)
    ]

    dns_names: Counter = Counter()
    for record in result.dns_records:
        if record["is_response"]:
            continue
        for query in record["queries"]:
            if query["name"]:
                dns_names[query["name"].lower().rstrip(".")] += 1

    http_hosts: Counter = Counter()
    for record in result.http_records:
        if record.get("kind") == "request" and record.get("host"):
            http_hosts[record["host"]] += 1

    sni_names: Counter = Counter(
        record["sni"] for record in result.tls_records if record.get("sni")
    )

    return {
        "meta": meta,
        "capture": {
            "format": info.fmt,
            "compression": info.compression,
            "packets": info.packets,
            "bytes_on_wire": info.bytes_on_wire,
            "bytes_captured": info.bytes_captured,
            "duration_seconds": round(info.duration, 3),
            "first_packet": info.first_ts,
            "last_packet": info.last_ts,
            "snaplen": info.snaplen,
            "truncated_packets": info.truncated_packets,
            "drops_reported": info.drops_reported,
            "link_types": info.linktype_names,
            "interfaces": info.interfaces,
            "capture_tool": info.app_desc,
            "capture_os": info.os_desc,
            "byte_order": info.byte_order,
        },
        "stats": result.stats,
        "profile": result.profile,
        "findings": [f.to_dict() for f in result.findings],
        "graph": build_graph(result),
        "timeline": build_timeline(result),
        "protocols": [
            {"name": name, "packets": count}
            for name, count in result.protocol_counts.most_common(20)
        ],
        "encapsulation": [
            {"name": name, "packets": count}
            for name, count in result.encapsulations.most_common(10)
        ],
        "hosts": [
            {
                "ip": h.ip,
                "ip_version": h.version,
                "hostnames": sorted(h.hostnames)[:3],
                "macs": sorted(h.macs)[:3],
                "vendor": next(
                    (lookup_vendor(m) for m in sorted(h.macs)[:1]), None
                ),
                "internal": h.is_private,
                "risk": h.risk,
                "packets": h.packets_sent + h.packets_recv,
                "bytes": h.bytes_sent + h.bytes_recv,
                "bytes_sent": h.bytes_sent,
                "bytes_received": h.bytes_recv,
                "peers": len(h.peers),
                "ports_served": sorted(h.ports_served)[:12],
                "services": [
                    _served_label(p) for p in sorted(h.ports_served)[:6]
                ],
                "tags": sorted(h.tags)[:5],
                "first_seen": h.first_seen,
                "last_seen": h.last_seen,
            }
            for h in sorted(
                result.hosts.values(),
                key=lambda x: (x.risk, x.bytes_sent + x.bytes_recv),
                reverse=True,
            )[:MAX_TABLE_ROWS]
        ],
        "top_talkers": [
            {
                "ip": h.ip,
                "bytes": h.bytes_sent + h.bytes_recv,
                "packets": h.packets_sent + h.packets_recv,
                "internal": h.is_private,
            }
            for h in top_talkers
        ],
        "conversations": top_conversations,
        "flows": [
            {
                "source": f.src,
                "destination": f.dst,
                "source_port": f.sport,
                "destination_port": f.dport,
                "protocol": f.proto,
                "service": f.service,
                "packets": f.total_packets,
                "bytes": f.total_bytes,
                "bytes_sent": f.bytes_fwd,
                "bytes_received": f.bytes_rev,
                "duration": round(f.duration, 2),
                "sni": f.sni,
                "first_seen": f.first_seen,
            }
            for f in sorted(
                result.flows.values(), key=lambda x: -x.total_bytes
            )[:MAX_TABLE_ROWS]
        ],
        "dns": {
            "top_domains": [
                {"name": name, "queries": count}
                for name, count in dns_names.most_common(50)
            ],
            "total_queries": result.stats.get("dns_queries", 0),
            "unique_domains": result.stats.get("unique_domains", 0),
        },
        "http": {
            "top_hosts": [
                {"host": host, "requests": count}
                for host, count in http_hosts.most_common(50)
            ],
            "requests": [
                {
                    "ts": rec["ts"],
                    "packet": rec["packet"],
                    "source": rec["src"],
                    "destination": rec["dst"],
                    "method": rec.get("method"),
                    "host": rec.get("host"),
                    "uri": (rec.get("uri") or "")[:200],
                    "user_agent": (rec.get("user_agent") or "")[:120],
                }
                for rec in result.http_records
                if rec.get("kind") == "request"
            ][:MAX_TABLE_ROWS],
        },
        "tls": {
            "top_sni": [
                {"name": name, "sessions": count}
                for name, count in sni_names.most_common(50)
            ],
            "sessions": [
                {
                    "ts": rec["ts"],
                    "client": rec["src"],
                    "server": rec["dst"],
                    "sni": rec.get("sni"),
                    "version": rec.get("version"),
                    "ja3": rec.get("ja3"),
                    "ja4": rec.get("ja4"),
                    "alpn": rec.get("alpn"),
                }
                for rec in result.tls_records
            ][:MAX_TABLE_ROWS],
            "certificates": result.certificates[:100],
        },
        "events": build_event_timeline(result),
        "credentials": result.credentials,
        "voip": {
            "calls": [c.to_dict() for c in result.calls.values()][:MAX_TABLE_ROWS],
            "rtp_streams": [
                {k: v for k, v in stream.items()}
                for stream in sorted(
                    result.rtp_streams.values(),
                    key=lambda x: -x.get("packets", 0),
                )
            ][:MAX_TABLE_ROWS],
            "messages": result.sip_messages[:MAX_TABLE_ROWS],
        },
        "files": result.files,
        "streams": result.streams,
        "enrichment": result.enrichment,
        "windows": {
            "smb": _summarise_smb(result),
            "ntlm": [
                {
                    "ts": rec["ts"], "packet": rec["packet"],
                    "source": rec["src"], "target": rec["dst"],
                    "user": rec.get("user"), "domain": rec.get("domain"),
                    "workstation": rec.get("workstation"),
                    "version": rec.get("ntlm_version"),
                    "transport": rec.get("transport"),
                }
                for rec in result.ntlm_records
                if rec.get("stage") == "authenticate"
            ][:MAX_TABLE_ROWS],
            "kerberos": [
                {
                    "ts": rec["ts"], "source": rec["src"], "target": rec["dst"],
                    "message": rec.get("message_type"),
                    "encryption": ", ".join(rec.get("etype_names", [])),
                    "weak": rec.get("weak_etype", False),
                    "realm": rec.get("realm"),
                    "service": rec.get("service"),
                }
                for rec in result.kerberos_records
            ][:MAX_TABLE_ROWS],
        },
        "ics": [
            {
                "ts": rec["ts"], "packet": rec["packet"],
                "protocol": rec["protocol"], "source": rec["src"],
                "target": rec["dst"], "command": rec.get("function_name"),
                "dangerous": bool(rec.get("dangerous") or rec.get("is_write")),
            }
            for rec in result.ics_records
        ][:MAX_TABLE_ROWS],
        "iot": [
            {
                "ts": rec["ts"], "protocol": rec["protocol"],
                "source": rec["src"], "target": rec["dst"],
                "type": rec.get("type") or rec.get("method"),
                "detail": rec.get("topic") or rec.get("client_id")
                          or rec.get("search_target") or rec.get("code_name"),
                "encrypted": rec.get("encrypted"),
            }
            for rec in result.iot_records
        ][:MAX_TABLE_ROWS],
        "wireless": {
            "networks": [
                {
                    "ssid": entry["ssid"],
                    "access_points": sorted(entry["bssids"])[:10],
                    "ap_count": len(entry["bssids"]),
                    "security": sorted(entry["security"]),
                    "beacons": entry["beacons"],
                }
                for entry in result.wifi_networks.values()
            ][:200],
            "events": [
                {
                    "ts": rec["ts"], "type": rec.get("subtype"),
                    "source": rec.get("source"), "bssid": rec.get("bssid"),
                    "reason": rec.get("reason"), "ssid": rec.get("ssid"),
                }
                for rec in result.wifi_records
                if rec.get("subtype") in
                ("Deauthentication", "Disassociation", "EAPOL")
            ][:MAX_TABLE_ROWS],
        },
        "quic": [
            {
                "ts": rec["ts"], "source": rec["src"], "target": rec["dst"],
                "version": rec.get("version_name"), "type": rec.get("type"),
            }
            for rec in result.quic_records
        ][:MAX_TABLE_ROWS],
        "reassembly": result.reassembly_stats,
        "iocs": build_iocs(result),
        "errors": [
            {"message": message, "count": count}
            for message, count in result.errors.most_common(10)
        ],
    }


def build_event_timeline(result, limit: int = 400) -> list[dict]:
    """
    Merge everything that happened into one ordered list.

    Grouping by kind answers "what sort of thing was going on". An
    investigation usually needs the other question: what happened, in what
    order. A credential sent two seconds after a file arrived is a
    different story from the same two events an hour apart, and no
    per-category table can show that.
    """
    events: list[dict] = []

    for finding in result.findings:
        when = finding.first_seen
        if when is None:
            # Fall back to the earliest timestamp in the evidence, so a
            # finding without its own window still lands in the right place.
            stamps = [
                row.get("ts") for row in (finding.evidence or [])
                if isinstance(row, dict) and row.get("ts")
            ]
            when = min(stamps) if stamps else None
        if when is None:
            continue
        events.append(
            {
                "ts": when,
                "kind": "finding",
                "severity": finding.severity,
                "title": finding.title,
                "detail": finding.description[:200],
                "hosts": finding.hosts[:4],
            }
        )

    for credential in result.credentials:
        events.append(
            {
                "ts": credential.get("ts"),
                "kind": "credential",
                "severity": "critical" if credential.get("secret_kind") == "password" else "high",
                "title": f"{credential['protocol']} {credential['method']}",
                "detail": f"{credential.get('username') or 'unknown account'} "
                          f"on {credential.get('server')}",
                "hosts": [credential.get("client")],
            }
        )

    # The same file fetched fifty times is one event with a count, not
    # fifty. Left uncollapsed it buries everything else in the timeline.
    seen_files: dict[str, dict] = {}
    for record in result.files:
        signatures = [s["name"] for s in record.get("signatures", [])]
        key = record.get("sha256", "")
        if key and key in seen_files:
            entry = seen_files[key]
            entry["repeats"] = entry.get("repeats", 1) + 1
            continue
        event = {
                "ts": record.get("ts"),
                "kind": "file",
                "severity": "critical" if signatures else "info",
                "title": f"{record.get('filename') or 'Unnamed file'} "
                         f"({record.get('description')})",
                "detail": (", ".join(signatures) if signatures
                           else f"{(record.get('size') or 0):,} bytes")
                         + f" — {record.get('source')} to {record.get('destination')}",
                "hosts": [record.get("destination")],
            }
        events.append(event)
        if key:
            seen_files[key] = event

    for call in result.calls.values():
        entry = call.to_dict()
        events.append(
            {
                "ts": entry.get("started"),
                "kind": "call",
                "severity": "info",
                "title": f"Call {entry.get('caller') or '?'} to {entry.get('callee') or '?'}",
                "detail": ("Answered, "
                           f"{entry.get('duration') or 0:.0f}s"
                           if entry.get("answered") else
                           f"Not answered ({entry.get('final_status') or 'no response'})"),
                "hosts": [entry.get("caller_ip")],
            }
        )

    # The first time each external destination was contacted. Repeats add
    # nothing to a timeline; the first contact is the event.
    seen_external: set[str] = set()
    for flow in sorted(result.flows.values(), key=lambda f: f.first_seen or 0):
        destination = flow.responder or flow.dst
        host = result.hosts.get(destination)
        if not host or host.is_private or destination in seen_external:
            continue
        seen_external.add(destination)
        if len(seen_external) > 60:
            break
        events.append(
            {
                "ts": flow.first_seen,
                "kind": "contact",
                "severity": "info",
                "title": f"First contact with {destination}",
                "detail": f"{flow.service or 'TCP'} on port "
                          f"{flow.responder_port or flow.dport}",
                "hosts": [flow.initiator or flow.src],
            }
        )

    events = [e for e in events if e.get("ts")]
    events.sort(key=lambda e: e["ts"])

    # Keep both ends of a long capture rather than truncating the tail,
    # since the last events are often the outcome.
    if len(events) > limit:
        half = limit // 2
        events = events[:half] + events[-half:]

    return events


def _summarise_smb(result) -> dict:
    """Condense SMB traffic into shares, versions and operation counts."""
    if not result.smb_records:
        return {"messages": 0, "versions": [], "top_commands": [], "pairs": []}

    versions = Counter(rec.get("version") for rec in result.smb_records)
    commands = Counter(
        rec.get("command") for rec in result.smb_records
        if not rec.get("is_response")
    )
    pairs = Counter(
        (rec["src"], rec["dst"]) for rec in result.smb_records
    )

    return {
        "messages": len(result.smb_records),
        "versions": [{"version": v, "messages": c} for v, c in versions.most_common()],
        "top_commands": [
            {"command": cmd, "count": count} for cmd, count in commands.most_common(12)
        ],
        "pairs": [
            {"client": a, "server": b, "messages": c}
            for (a, b), c in pairs.most_common(50)
        ],
    }


def defang(value: str) -> str:
    """Render an indicator unclickable so it can be shared safely."""
    return (
        value.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
    )


def build_iocs(result) -> dict:
    """
    Collect indicators worth feeding to a blocklist or intel platform.

    Only indicators attached to a medium or higher finding are included,
    so the list stays actionable instead of listing every address seen.
    """
    flagged_hosts: set[str] = set()
    for finding in result.findings:
        if finding.severity in ("critical", "high", "medium"):
            flagged_hosts.update(finding.hosts)

    external = [
        ip
        for ip in flagged_hosts
        if ip in result.hosts and not result.hosts[ip].is_private
    ]

    domains: set[str] = set()
    extra_ips: set[str] = set()

    for finding in result.findings:
        if finding.severity not in ("critical", "high"):
            continue
        for row in finding.evidence:
            for key in ("domain", "host", "host_header", "sni", "destination"):
                value = row.get(key)
                if not value or not isinstance(value, str):
                    continue
                candidate = value.split(":")[0].strip("[]").lower()
                if not candidate:
                    continue
                # A Host header may hold a bare address. Route it to the IP
                # list rather than leaving it to look like a domain.
                try:
                    address = ipaddress.ip_address(candidate)
                except ValueError:
                    if "." in candidate:
                        domains.add(candidate)
                    continue
                if not (address.is_private or address.is_loopback):
                    extra_ips.add(str(address))

    external = sorted(set(external) | extra_ips)

    ja3_values: set[str] = set()
    for finding in result.findings:
        if finding.id == "tls.rare_fingerprint":
            for row in finding.evidence:
                if row.get("ja3"):
                    ja3_values.add(row["ja3"])

    # Files carry the strongest indicators available: a hash of exactly what
    # crossed the wire. Only files that a signature flagged are included, so
    # the list stays actionable rather than listing every image on a page.
    file_hashes: list[str] = []
    file_details: list[dict] = []
    for record in getattr(result, "files", []):
        flagged = bool(record.get("signatures")) or record.get("category") == "executable"
        if not flagged:
            continue
        file_hashes.append(record["sha256"])
        file_details.append(
            {
                "sha256": record["sha256"],
                "md5": record["md5"],
                "imphash": (record.get("pe_info") or {}).get("imphash"),
                "filename": record.get("filename"),
                "type": record.get("description"),
                "size": record.get("size"),
                "signatures": [s["name"] for s in record.get("signatures", [])],
            }
        )

    return {
        "ip_addresses": sorted(external),
        "ip_addresses_defanged": [defang(ip) for ip in sorted(external)],
        "domains": sorted(domains),
        "domains_defanged": [defang(d) for d in sorted(domains)],
        "file_hashes": sorted(set(file_hashes)),
        "file_details": file_details[:100],
        "ja3": sorted(ja3_values),
        "note": (
            "Indicators are drawn from medium severity findings and above. "
            "Verify each one before blocking: shared hosting and content "
            "delivery addresses can appear here alongside genuine "
            "attacker infrastructure."
        ),
    }
