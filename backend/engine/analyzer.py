"""
WireCub analysis engine.

One streaming pass over the capture builds every table the detection
modules need: hosts, flows, DNS, HTTP, TLS, services, and a protocol
profile. Detections then run against those tables, never against the
capture, so adding a module costs nothing at parse time.

Memory is bounded. Flows, hosts and per-protocol records all have caps;
once a cap is hit WireCub keeps counting in aggregate instead of storing
new rows, so a 10 GB capture stays within a predictable footprint.
"""

from __future__ import annotations

import ipaddress
import os
import statistics
from functools import lru_cache
from pathlib import Path
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable

from . import carve, credentials, enrich, layers, protocols, protocols_ext, voip
from .findings import Finding, risk_band, risk_score, risk_verdict
from .oui import lookup_vendor
from .reader import CaptureInfo, read_packets
from .reassembly import FragmentReassembler, Reassembler, split_http_messages
from .services import service_name

# Bounds that keep memory predictable on very large captures
MAX_FLOWS = 400_000
MAX_HOSTS = 60_000
MAX_DNS = 200_000
MAX_HTTP = 120_000
MAX_TLS = 120_000
MAX_TIMES_PER_FLOW = 400       # timing samples kept for beacon scoring
MAX_EVIDENCE = 12                # evidence rows attached to a finding


@dataclass(slots=True)
class Host:
    ip: str
    version: int
    macs: set[str] = field(default_factory=set)
    hostnames: set[str] = field(default_factory=set)
    packets_sent: int = 0
    packets_recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    ports_served: set[int] = field(default_factory=set)
    ports_contacted: set[int] = field(default_factory=set)
    peers: set[str] = field(default_factory=set)
    protocols: Counter = field(default_factory=Counter)
    first_seen: float = 0.0
    last_seen: float = 0.0
    ttl_values: set[int] = field(default_factory=set)
    user_agents: set[str] = field(default_factory=set)
    ja3: set[str] = field(default_factory=set)
    is_private: bool = False
    risk: int = 0
    tags: set[str] = field(default_factory=set)


@dataclass(slots=True)
class Flow:
    key: tuple
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    # The flow key is order-independent so both directions land in one row.
    # Direction still matters for detection, so the side that opened the
    # conversation is recorded separately and never derived from the key.
    initiator: str = ""
    responder: str = ""
    initiator_port: int = 0
    responder_port: int = 0
    starts: list[float] = field(default_factory=list)
    packets_fwd: int = 0
    packets_rev: int = 0
    bytes_fwd: int = 0
    bytes_rev: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    times: list[float] = field(default_factory=list)
    flags_seen: int = 0
    syn_count: int = 0
    synack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    service: str = ""
    sni: str | None = None
    ja3: str | None = None
    http_hosts: set[str] = field(default_factory=set)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def total_bytes(self) -> int:
        return self.bytes_fwd + self.bytes_rev

    @property
    def bytes_out(self) -> int:
        """Bytes sent by whoever opened the conversation."""
        return self.bytes_fwd if self.initiator == self.key[0] else self.bytes_rev

    @property
    def bytes_in(self) -> int:
        """Bytes sent back to whoever opened the conversation."""
        return self.bytes_rev if self.initiator == self.key[0] else self.bytes_fwd

    @property
    def connection_events(self) -> list[float]:
        """
        When this conversation was initiated, as distinct events.

        A beacon that reconnects each time gives one SYN per callback. A
        beacon that holds one socket open gives packet timings instead, so
        near-simultaneous packets are collapsed into single events to stop
        a burst of three packets reading as a 0.05 second interval.
        """
        if self.starts:
            return self.starts
        if not self.times:
            return []
        events = [self.times[0]]
        for t in self.times[1:]:
            if t - events[-1] > 2.0:
                events.append(t)
        return events

    @property
    def total_packets(self) -> int:
        return self.packets_fwd + self.packets_rev


class AnalysisResult:
    """Everything one analysis produced."""

    def __init__(self):
        self.capture = CaptureInfo()
        self.hosts: dict[str, Host] = {}
        self.flows: dict[tuple, Flow] = {}
        self.dns_records: list[dict] = []
        self.http_records: list[dict] = []
        self.tls_records: list[dict] = []
        self.certificates: list[dict] = []
        self.arp_map: dict[str, set[str]] = defaultdict(set)
        self.protocol_counts: Counter = Counter()
        self.linklayer_counts: Counter = Counter()
        self.ethertype_counts: Counter = Counter()
        self.encapsulations: Counter = Counter()
        self.conversation_bytes: Counter = Counter()
        self.timeline: dict[int, dict] = {}
        self.findings: list[Finding] = []
        self.errors: Counter = Counter()
        self.dropped_flows = 0
        self.dropped_hosts = 0
        self.credential_hits: list[dict] = []
        self.file_transfers: list[dict] = []
        self.icmp_records: list[dict] = []
        self.dhcp_records: list[dict] = []
        self.ipv6_events: list[dict] = []
        self.scan_stats: dict = {}
        self.stats: dict = {}
        # Deep-scan tables
        self.streams: list = []
        self.files: list = []
        self.smb_records: list[dict] = []
        self.ntlm_records: list[dict] = []
        self.kerberos_records: list[dict] = []
        self.quic_records: list[dict] = []
        self.ics_records: list[dict] = []
        self.iot_records: list[dict] = []
        self.wifi_records: list[dict] = []
        self.wifi_networks: dict = {}
        self.enrichment: dict[str, dict] = {}
        self.credentials: list[dict] = []
        self.sip_messages: list[dict] = []
        self.calls: dict = {}
        self.rtp_streams: dict = {}
        self.credentials: list[dict] = []
        self.sip_messages: list[dict] = []
        self.calls: dict = {}
        self.rtp_streams: dict = {}
        self.reassembly_stats: dict = {}
        self.duration_wall: float = 0.0
        self.profile: dict = {}


@lru_cache(maxsize=65536)
def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )
    except ValueError:
        return False


class Analyzer:
    """Runs one capture through the full pipeline."""

    def __init__(
        self,
        path: str,
        deep: bool = True,
        progress: Callable[[str, float, str], None] | None = None,
        artifact_dir: str | None = None,
    ):
        self.path = path
        self.deep = deep
        # Carved files are written here so an analyst can retrieve the
        # actual bytes, not just a hash of them.
        self.artifact_dir = artifact_dir
        self.progress = progress or (lambda phase, pct, msg: None)
        self.result = AnalysisResult()
        self._cancelled = False
        # Reassembly is deep-scan only: it is the most expensive stage and
        # a quick scan is meant to return an answer in seconds.
        self.reassembler = Reassembler()
        # Fragment reassembly runs in both modes: splitting a payload across
        # fragments is a way to hide it from inspection, so skipping it in a
        # quick scan would leave the cheapest evasion technique working.
        self.fragments = FragmentReassembler()
        # QUIC Initial decryption budget. Deep scan gets a larger one
        # because the server names it recovers are worth the seconds.
        self._quic_budget = 1500

    def cancel(self):
        self._cancelled = True

    # -- main entry ---------------------------------------------------------

    def run(self) -> AnalysisResult:
        started = time.time()
        r = self.result

        self.progress("reading", 0.0, "Opening capture")
        file_size = os.path.getsize(self.path) or 1

        self._extract(file_size)

        if self._cancelled:
            return r

        if self.reassembler is not None:
            self.progress("reassembling", 71.0, "Rebuilding TCP streams")
            self._reassemble()

        if self._cancelled:
            return r

        if not r.reassembly_stats:
            r.reassembly_stats = self.fragments.stats()

        self._finalise_voip()

        self.progress("profiling", 75.0, "Building traffic profile")
        self._enrich_hosts()
        self._build_profile()

        self.progress("detecting", 79.0, "Running detection modules")
        from . import detections

        detections.run_all(r, deep=self.deep, progress=self.progress)

        self.progress("scoring", 95.0, "Scoring findings")
        self._finalise()

        r.duration_wall = time.time() - started
        self.progress("done", 100.0, "Analysis complete")
        return r

    # -- pass 1: extraction -------------------------------------------------

    def _extract(self, file_size: int):
        r = self.result
        info = r.capture
        last_report = 0.0
        bytes_seen = 0

        for pkt in read_packets(self.path, info):
            if self._cancelled:
                return

            bytes_seen += pkt.caplen + 16
            if pkt.number % 4096 == 0:
                pct = min(70.0, (bytes_seen / file_size) * 70.0)
                now = time.time()
                if now - last_report > 0.25:
                    last_report = now
                    self.progress(
                        "reading",
                        pct,
                        f"Decoding packets — {pkt.number:,} read",
                    )

            d = layers.decode(pkt.data, pkt.linktype)

            r.linklayer_counts[pkt.linktype] += 1
            if d.error:
                r.errors[d.error] += 1
            for enc in d.encapsulation:
                r.encapsulations[enc.split()[0]] += 1

            # Wireless management frames carry no IP layer at all, so they
            # are handled before the IP checks discard them.
            if pkt.linktype in (105, 127) and "802.11" in " ".join(d.encapsulation):
                self._inspect_wifi(pkt, d)

            # ARP is link layer only: record it and move on.
            if d.arp_op is not None:
                if d.arp_sender_ip and d.arp_sender_mac:
                    r.arp_map[d.arp_sender_ip].add(d.arp_sender_mac)
                r.protocol_counts["ARP"] += 1
                self._bump_timeline(pkt.ts, pkt.wirelen, "ARP")
                continue

            if not d.src_ip or not d.dst_ip:
                r.protocol_counts["Non-IP"] += 1
                self._bump_timeline(pkt.ts, pkt.wirelen, "Non-IP")
                continue

            proto_name = d.transport
            r.protocol_counts[proto_name] += 1
            if d.ethertype:
                r.ethertype_counts[d.ethertype] += 1

            # A fragmented datagram has no usable transport header until it
            # is whole, so rebuild it before anything tries to read it.
            if d.frag_offset is not None:
                assembled = self.fragments.add(d, pkt.ts)
                if assembled is not None:
                    d = layers.rebuild_from_payload(d, assembled)
                    r.protocol_counts["Reassembled"] += 1

            self._update_hosts(d, pkt.ts, pkt.wirelen)
            flow = self._update_flow(d, pkt.ts, pkt.wirelen)
            self._inspect_payload(d, pkt, flow)
            self._inspect_extended(d, pkt)
            self._bump_timeline(pkt.ts, pkt.wirelen, proto_name)

            if self.reassembler is not None and d.protocol == 6:
                self.reassembler.add(
                    d, pkt.ts, pkt.number, flow.service if flow else ""
                )

        self.progress("reading", 70.0, f"Decoded {info.packets:,} packets")

    # -- host and flow tables ----------------------------------------------

    def _get_host(self, ip: str, version: int, ts: float) -> Host | None:
        r = self.result
        host = r.hosts.get(ip)
        if host is None:
            if len(r.hosts) >= MAX_HOSTS:
                r.dropped_hosts += 1
                return None
            host = Host(ip=ip, version=version, is_private=_is_private(ip))
            host.first_seen = ts
            r.hosts[ip] = host
        host.last_seen = ts
        return host

    def _update_hosts(self, d: layers.Decoded, ts: float, size: int):
        src = self._get_host(d.src_ip, d.ip_version or 4, ts)
        dst = self._get_host(d.dst_ip, d.ip_version or 4, ts)

        if src:
            src.packets_sent += 1
            src.bytes_sent += size
            src.protocols[d.transport] += 1
            if d.src_mac:
                src.macs.add(d.src_mac)
            if d.ttl is not None:
                if len(src.ttl_values) < 8:
                    src.ttl_values.add(d.ttl)
            if d.dst_ip and len(src.peers) < 5_000:
                src.peers.add(d.dst_ip)
            if d.dst_port and len(src.ports_contacted) < 5_000:
                src.ports_contacted.add(d.dst_port)

        if dst:
            dst.packets_recv += 1
            dst.bytes_recv += size
            if d.dst_mac:
                dst.macs.add(d.dst_mac)
            if d.src_ip and len(dst.peers) < 5_000:
                dst.peers.add(d.src_ip)
            # A SYN toward a port means that port is being offered there.
            if d.dst_port and d.tcp_flags is not None:
                if d.tcp_flags & layers.TH_SYN and not d.tcp_flags & layers.TH_ACK:
                    pass  # not yet proven open
            # A SYN-ACK from a port proves it is listening.
            if d.src_port and d.tcp_flags is not None:
                if (d.tcp_flags & layers.TH_SYN) and (d.tcp_flags & layers.TH_ACK):
                    src_host = self.result.hosts.get(d.src_ip)
                    if src_host:
                        src_host.ports_served.add(d.src_port)

        key = tuple(sorted([d.src_ip, d.dst_ip]))
        self.result.conversation_bytes[key] += size

    def _update_flow(self, d: layers.Decoded, ts: float, size: int) -> Flow | None:
        r = self.result
        if d.src_port is None or d.dst_port is None:
            # Non-port protocols still get a flow so ICMP tunnels show up.
            key = (d.src_ip, d.dst_ip, 0, 0, d.transport)
            forward = True
        else:
            a = (d.src_ip, d.src_port)
            b = (d.dst_ip, d.dst_port)
            forward = a <= b
            lo, hi = (a, b) if forward else (b, a)
            key = (lo[0], hi[0], lo[1], hi[1], d.transport)

        flow = r.flows.get(key)
        if flow is None:
            if len(r.flows) >= MAX_FLOWS:
                r.dropped_flows += 1
                return None
            flow = Flow(
                key=key,
                src=key[0],
                dst=key[1],
                sport=key[2],
                dport=key[3],
                proto=d.transport,
                first_seen=ts,
                # The first packet seen defines the direction. For TCP this
                # is refined below once a SYN confirms who really opened it.
                initiator=d.src_ip,
                responder=d.dst_ip,
                initiator_port=d.src_port or 0,
                responder_port=d.dst_port or 0,
            )
            # Name the service from whichever side looks like the server.
            server_port = d.dst_port if (d.dst_port or 0) < (d.src_port or 0) else d.src_port
            flow.service = service_name(server_port or 0, d.transport)
            r.flows[key] = flow

        flow.last_seen = ts
        if forward:
            flow.packets_fwd += 1
            flow.bytes_fwd += size
        else:
            flow.packets_rev += 1
            flow.bytes_rev += size

        if len(flow.times) < MAX_TIMES_PER_FLOW:
            flow.times.append(ts)

        if d.tcp_flags is not None:
            flow.flags_seen |= d.tcp_flags
            syn = bool(d.tcp_flags & layers.TH_SYN)
            ack = bool(d.tcp_flags & layers.TH_ACK)
            if syn and not ack:
                flow.syn_count += 1
                # A bare SYN is definitive proof of who opened the connection,
                # so it overrides the guess made from the first packet seen.
                flow.initiator = d.src_ip
                flow.responder = d.dst_ip
                flow.initiator_port = d.src_port or 0
                flow.responder_port = d.dst_port or 0
                if len(flow.starts) < MAX_TIMES_PER_FLOW:
                    flow.starts.append(ts)
            elif syn and ack:
                flow.synack_count += 1
            if d.tcp_flags & layers.TH_RST:
                flow.rst_count += 1
            if d.tcp_flags & layers.TH_FIN:
                flow.fin_count += 1

        return flow

    # -- payload inspection -------------------------------------------------

    def _inspect_payload(self, d: layers.Decoded, pkt, flow: Flow | None):
        payload = d.payload
        if not payload:
            return
        r = self.result

        sport, dport = d.src_port or 0, d.dst_port or 0

        # --- DNS / mDNS / LLMNR ---
        if 53 in (sport, dport) or 5353 in (sport, dport) or 5355 in (sport, dport):
            if len(r.dns_records) < MAX_DNS:
                dns = protocols.parse_dns(payload)
                if dns and (dns["queries"] or dns["answers"]):
                    rec = {
                        "ts": pkt.ts,
                        "packet": pkt.number,
                        "src": d.src_ip,
                        "dst": d.dst_ip,
                        "is_response": dns["is_response"],
                        "rcode": dns["rcode_name"],
                        "queries": dns["queries"],
                        "answers": dns["answers"],
                        "transport": d.transport,
                        "port": 53 if 53 in (sport, dport) else (5353 if 5353 in (sport, dport) else 5355),
                    }
                    r.dns_records.append(rec)
                    # mDNS and LLMNR responses name the host that sent them.
                    if dns["is_response"] and rec["port"] in (5353, 5355):
                        host = r.hosts.get(d.src_ip)
                        if host:
                            for ans in dns["answers"][:3]:
                                if ans["name"]:
                                    host.hostnames.add(ans["name"].rstrip("."))
            return

        # --- DHCP ---
        if 67 in (sport, dport) or 68 in (sport, dport):
            self._parse_dhcp(payload, d, pkt)
            return

        # --- NetBIOS name service ---
        if 137 in (sport, dport):
            r.protocol_counts["NBNS"] += 1
            return

        # --- TLS ---
        if protocols.is_tls_record(payload):
            if len(r.tls_records) < MAX_TLS:
                hello = protocols.parse_tls_client_hello(payload)
                if hello:
                    rec = {
                        "ts": pkt.ts,
                        "packet": pkt.number,
                        "src": d.src_ip,
                        "dst": d.dst_ip,
                        "dport": dport,
                        **hello,
                    }
                    r.tls_records.append(rec)
                    if flow:
                        flow.sni = hello["sni"]
                        flow.ja3 = hello["ja3"]
                    host = r.hosts.get(d.src_ip)
                    if host and hello["ja3"]:
                        host.ja3.add(hello["ja3"])
                else:
                    certs = protocols.extract_tls_certificates(payload)
                    for cert in certs:
                        if len(r.certificates) < 5000:
                            cert["ts"] = pkt.ts
                            cert["packet"] = pkt.number
                            cert["server"] = d.src_ip
                            r.certificates.append(cert)
            return

        # --- HTTP ---
        req = protocols.parse_http_request(payload)
        if req:
            if len(r.http_records) < MAX_HTTP:
                rec = {
                    "ts": pkt.ts,
                    "packet": pkt.number,
                    "src": d.src_ip,
                    "dst": d.dst_ip,
                    "dport": dport,
                    **{k: v for k, v in req.items() if k != "headers"},
                }
                rec["body_preview"] = req["body_preview"][:512]
                r.http_records.append(rec)
            host = r.hosts.get(d.src_ip)
            if host:
                if req["user_agent"] and len(host.user_agents) < 12:
                    host.user_agents.add(req["user_agent"])
            if flow and req["host"]:
                flow.http_hosts.add(req["host"])
            return

        resp = protocols.parse_http_response(payload)
        if resp:
            if len(r.http_records) < MAX_HTTP:
                r.http_records.append(
                    {
                        "ts": pkt.ts,
                        "packet": pkt.number,
                        "src": d.src_ip,
                        "dst": d.dst_ip,
                        "kind": "response",
                        "status": resp["status"],
                        "content_type": resp["content_type"],
                        "content_length": resp["content_length"],
                        "server": resp["server"],
                        "body_preview": resp["body_preview"][:512],
                    }
                )
            return

        # --- ICMP records feed tunnel detection ---
        if d.icmp_type is not None and len(r.icmp_records) < 50_000:
            r.icmp_records.append(
                {
                    "ts": pkt.ts,
                    "packet": pkt.number,
                    "src": d.src_ip,
                    "dst": d.dst_ip,
                    "type": d.icmp_type,
                    "code": d.icmp_code,
                    "payload_len": len(payload),
                    "entropy": protocols.byte_entropy(payload[:256]) if payload else 0.0,
                    "is_v6": d.is_ipv6,
                }
            )

    def _parse_dhcp(self, payload: bytes, d: layers.Decoded, pkt):
        """Pull hostname and fingerprint options out of a DHCP message."""
        if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
            return
        r = self.result
        pos = 240
        hostname = None
        vendor_class = None
        param_list = None
        msg_type = None

        while pos + 2 <= len(payload):
            opt = payload[pos]
            if opt == 255:
                break
            if opt == 0:
                pos += 1
                continue
            length = payload[pos + 1]
            value = payload[pos + 2:pos + 2 + length]
            pos += 2 + length

            if opt == 53 and value:
                msg_type = value[0]
            elif opt == 12:
                hostname = value.decode("utf-8", "replace")
            elif opt == 60:
                vendor_class = value.decode("utf-8", "replace")
            elif opt == 55:
                param_list = ",".join(str(b) for b in value)

        if hostname:
            host = r.hosts.get(d.src_ip)
            if host:
                host.hostnames.add(hostname)

        if len(r.dhcp_records) < 20_000 and (hostname or vendor_class):
            r.dhcp_records.append(
                {
                    "ts": pkt.ts,
                    "packet": pkt.number,
                    "src": d.src_ip,
                    "mac": d.src_mac,
                    "hostname": hostname,
                    "vendor_class": vendor_class,
                    "fingerprint": param_list,
                    "msg_type": msg_type,
                }
            )

    # -- extended protocols -------------------------------------------------

    def _inspect_extended(self, d: layers.Decoded, pkt):
        """
        Decode the protocols outside the core web and DNS set.

        Dispatch is by port because these protocols have no reliable
        content signature at the first byte, and scanning every payload
        against every parser would cost more than it returns.
        """
        payload = d.payload
        if not payload or len(payload) < 4:
            return
        r = self.result
        sport, dport = d.src_port or 0, d.dst_port or 0
        ports = (sport, dport)

        # --- SIP signalling ---
        if (sport in voip.SIP_PORTS or dport in voip.SIP_PORTS
                or voip.looks_like_sip(payload)):
            self._inspect_sip(payload, d, pkt)
            return

        # --- RTP media ---
        if d.protocol == 17 and voip.is_probable_rtp(payload, sport, dport):
            self._inspect_rtp(payload, d, pkt)
            return

        # --- QUIC / HTTP3 ---
        if d.protocol == 17 and (443 in ports or 80 in ports) and payload[0] & 0x80:
            # Decryption is pure Python AES and costs real time, so it runs
            # only on a bounded number of Initial packets. Everything past
            # that budget is still recorded, just without the server name.
            decrypt = self._quic_budget > 0
            quic = protocols_ext.parse_quic_initial(payload, decrypt=decrypt)
            if quic and quic.get("type") == "initial" and decrypt:
                self._quic_budget -= 1
            if quic and len(r.quic_records) < 40_000:
                r.quic_records.append(
                    {
                        "ts": pkt.ts, "packet": pkt.number,
                        "src": d.src_ip, "dst": d.dst_ip, "dport": dport,
                        **quic,
                    }
                )
            if quic and quic.get("sni"):
                host = r.hosts.get(d.src_ip)
                if host and quic.get("ja3"):
                    host.ja3.add(quic["ja3"])
            return

        # --- SMB, and the NTLM that rides inside it ---
        if 445 in ports or 139 in ports:
            smb = protocols_ext.parse_smb(payload)
            if smb and len(r.smb_records) < 60_000:
                r.smb_records.append(
                    {
                        "ts": pkt.ts, "packet": pkt.number,
                        "src": d.src_ip, "dst": d.dst_ip, **smb,
                    }
                )
            self._capture_ntlm(payload, d, pkt, "SMB")
            return

        # --- Kerberos ---
        if 88 in ports:
            kerb = protocols_ext.parse_kerberos(payload)
            if kerb and len(r.kerberos_records) < 40_000:
                r.kerberos_records.append(
                    {
                        "ts": pkt.ts, "packet": pkt.number,
                        "src": d.src_ip, "dst": d.dst_ip, **kerb,
                    }
                )
            return

        # NTLM also appears over HTTP, LDAP and RPC.
        if any(p in ports for p in (80, 8080, 389, 636, 135, 5985, 5986)):
            self._capture_ntlm(payload, d, pkt, "HTTP/LDAP/RPC")

        # --- industrial control ---
        if 502 in ports:
            self._record_ics(protocols_ext.parse_modbus(payload), "Modbus", d, pkt)
            return
        if 102 in ports:
            self._record_ics(protocols_ext.parse_s7comm(payload), "S7comm", d, pkt)
            return
        if 20000 in ports:
            self._record_ics(protocols_ext.parse_dnp3(payload), "DNP3", d, pkt)
            return
        if 47808 in ports:
            self._record_ics(protocols_ext.parse_bacnet(payload), "BACnet", d, pkt)
            return

        # --- IoT messaging ---
        if 1883 in ports or 8883 in ports:
            mqtt = protocols_ext.parse_mqtt(payload)
            if mqtt and len(r.iot_records) < 40_000:
                r.iot_records.append(
                    {
                        "ts": pkt.ts, "packet": pkt.number, "protocol": "MQTT",
                        "src": d.src_ip, "dst": d.dst_ip,
                        "encrypted": 8883 in ports, **mqtt,
                    }
                )
            return
        if 5683 in ports or 5684 in ports:
            coap = protocols_ext.parse_coap(payload)
            if coap and len(r.iot_records) < 40_000:
                r.iot_records.append(
                    {
                        "ts": pkt.ts, "packet": pkt.number, "protocol": "CoAP",
                        "src": d.src_ip, "dst": d.dst_ip,
                        "encrypted": 5684 in ports, **coap,
                    }
                )
            return
        if 1900 in ports:
            ssdp = protocols_ext.parse_ssdp(payload)
            if ssdp and len(r.iot_records) < 40_000:
                r.iot_records.append(
                    {
                        "ts": pkt.ts, "packet": pkt.number, "protocol": "SSDP",
                        "src": d.src_ip, "dst": d.dst_ip, **ssdp,
                    }
                )

    def _inspect_sip(self, payload: bytes, d: layers.Decoded, pkt):
        """Parse a SIP message and fold it into the call it belongs to."""
        message = voip.parse_sip(payload)
        if not message:
            return
        r = self.result

        if len(r.sip_messages) < 40_000:
            r.sip_messages.append(
                {
                    "ts": pkt.ts,
                    "packet": pkt.number,
                    "src": d.src_ip,
                    "dst": d.dst_ip,
                    "is_request": message.is_request,
                    "method": message.method,
                    "status": message.status,
                    "reason": message.reason,
                    "from": message.from_uri,
                    "to": message.to_uri,
                    "call_id": message.call_id,
                    "user_agent": message.user_agent,
                    "has_auth": message.auth is not None,
                    "via_hosts": message.via_hosts[:4],
                    "contact": message.contact,
                }
            )

        call_id = message.call_id
        if not call_id or len(r.calls) > 8_000:
            return

        call = r.calls.get(call_id)
        if call is None:
            call = voip.Call(call_id=call_id, started=pkt.ts)
            r.calls[call_id] = call

        call.packets += 1
        if message.user_agent:
            call.user_agents.add(message.user_agent[:80])

        if message.is_request:
            if message.method and message.method not in call.methods:
                call.methods.append(message.method)

            if message.method == "INVITE" and call.caller is None:
                call.caller = message.from_uri
                call.callee = message.to_uri
                call.caller_ip = d.src_ip
                call.callee_ip = d.dst_ip
            elif message.method in ("BYE", "CANCEL"):
                call.ended_at = pkt.ts

        else:
            status = message.status or 0
            if status == 180 or status == 183:
                call.ringing_at = pkt.ts
            elif 200 <= status < 300 and "INVITE" in call.methods:
                if call.answered_at is None:
                    call.answered_at = pkt.ts
            if status >= 200:
                call.final_status = status
                call.final_reason = message.reason

        # Authentication material, whichever direction it came from.
        if message.auth:
            entry = dict(message.auth)
            entry["ts"] = pkt.ts
            entry["packet"] = pkt.number
            entry["src"] = d.src_ip
            entry["method"] = message.method
            call.auth_attempts.append(entry)

            if entry["direction"] == "response" and entry.get("response"):
                if len(r.credentials) < 500:
                    r.credentials.append(
                        {
                            "protocol": "SIP",
                            "method": f"{entry['scheme']} digest"
                                      + (f" ({message.method})" if message.method else ""),
                            "username": entry.get("username"),
                            "secret": entry.get("response"),
                            "secret_kind": "challenge-response",
                            "client": d.src_ip,
                            "server": d.dst_ip,
                            "server_port": d.dst_port or d.src_port or 0,
                            "packet": pkt.number,
                            "ts": pkt.ts,
                            "realm": entry.get("realm"),
                            "crackable": True,
                            "note": "SIP digest response. The password is not "
                                    "sent, but this can be cracked offline "
                                    "against the nonce "
                                    f"{entry.get('nonce') or 'shown here'}, "
                                    "and a recovered SIP password is usable "
                                    "for toll fraud.",
                        }
                    )

        if message.sdp:
            if message.sdp.get("encrypted"):
                call.media_encrypted = True
            address = message.sdp.get("address")
            for media in message.sdp.get("media", []):
                if address and media.get("port"):
                    call.media_endpoints.add(f"{address}:{media['port']}")

    def _inspect_rtp(self, payload: bytes, d: layers.Decoded, pkt):
        """Track RTP streams by synchronisation source."""
        parsed = voip.parse_rtp(payload)
        if not parsed:
            return
        r = self.result

        key = (d.src_ip, d.src_port, d.dst_ip, d.dst_port, parsed["ssrc"])
        stream = r.rtp_streams.get(key)
        if stream is None:
            if len(r.rtp_streams) >= 4_000:
                return
            stream = {
                "src": d.src_ip, "src_port": d.src_port,
                "dst": d.dst_ip, "dst_port": d.dst_port,
                "ssrc": parsed["ssrc"],
                "codec": parsed["codec"],
                "payload_type": parsed["payload_type"],
                "packets": 0, "bytes": 0,
                "first_seen": pkt.ts, "last_seen": pkt.ts,
                "first_sequence": parsed["sequence"],
                "last_sequence": parsed["sequence"],
                "encrypted": False,
            }
            r.rtp_streams[key] = stream

        stream["packets"] += 1
        stream["bytes"] += parsed["payload_size"]
        stream["last_seen"] = pkt.ts
        stream["last_sequence"] = parsed["sequence"]

    def _capture_ntlm(self, payload: bytes, d: layers.Decoded, pkt, transport: str):
        if b"NTLMSSP" not in payload:
            return
        ntlm = protocols_ext.parse_ntlm(payload)
        if not ntlm or len(self.result.ntlm_records) >= 20_000:
            return
        self.result.ntlm_records.append(
            {
                "ts": pkt.ts, "packet": pkt.number, "transport": transport,
                "src": d.src_ip, "dst": d.dst_ip, **ntlm,
            }
        )

    def _record_ics(self, parsed, protocol: str, d: layers.Decoded, pkt):
        if not parsed or len(self.result.ics_records) >= 60_000:
            return
        self.result.ics_records.append(
            {
                "ts": pkt.ts, "packet": pkt.number, "protocol": protocol,
                "src": d.src_ip, "dst": d.dst_ip, **parsed,
            }
        )

    def _inspect_wifi(self, pkt, d: layers.Decoded):
        """Record 802.11 management frames and the networks they advertise."""
        r = self.result
        offset = 0
        if pkt.linktype == 127 and len(pkt.data) >= 4:
            import struct as _struct
            offset = _struct.unpack("<H", pkt.data[2:4])[0]

        frame = protocols_ext.parse_dot11_management(pkt.data, offset)
        if not frame:
            eapol = protocols_ext.is_eapol(d.payload) if d.payload else None
            if eapol and len(r.wifi_records) < 40_000:
                r.wifi_records.append(
                    {
                        "ts": pkt.ts, "packet": pkt.number,
                        "subtype": "EAPOL", "source": d.src_mac,
                        "destination": d.dst_mac, **eapol,
                    }
                )
            return

        if len(r.wifi_records) < 60_000:
            r.wifi_records.append({"ts": pkt.ts, "packet": pkt.number, **frame})

        # Track each advertised network so evil twins stand out as one SSID
        # served by more than one radio.
        if frame.get("ssid"):
            entry = r.wifi_networks.setdefault(
                frame["ssid"],
                {"ssid": frame["ssid"], "bssids": set(), "security": set(),
                 "beacons": 0},
            )
            entry["bssids"].add(frame["bssid"])
            if frame.get("security"):
                entry["security"].add(frame["security"])
            entry["beacons"] += 1

    # -- reassembly and carving ---------------------------------------------

    def _reassemble(self):
        """Rebuild streams, then carve transferred files out of them."""
        r = self.result
        streams = self.reassembler.finish()
        file_index = 0

        r.reassembly_stats = {
            **self.fragments.stats(),
            "streams_tracked": len(self.reassembler.streams),
            "streams_dropped": self.reassembler.dropped,
            "streams_with_data": len(streams),
        }

        for position, stream in enumerate(streams[:4000]):
            if self._cancelled:
                return
            if position % 200 == 0:
                self.progress(
                    "reassembling",
                    71.0 + min(3.5, position / max(1, len(streams)) * 3.5),
                    f"Rebuilding streams — {position:,} of {len(streams):,}",
                )

            to_server, server_missing = stream.to_server.assemble()
            to_client, client_missing = stream.to_client.assemble()

            if len(r.streams) < 600:
                r.streams.append(
                    {
                        "id": position,
                        "client": stream.client,
                        "server": stream.server,
                        "client_port": stream.client_port,
                        "server_port": stream.server_port,
                        "service": stream.service,
                        "bytes_to_server": len(to_server),
                        "bytes_to_client": len(to_client),
                        "missing_bytes": server_missing + client_missing,
                        "first_seen": stream.first_seen,
                        "last_seen": stream.last_seen,
                        "packet": stream.first_packet,
                        "reset": stream.reset,
                        "complete": stream.complete,
                        # A short preview makes the stream list usable
                        # without shipping megabytes to the browser.
                        "preview_to_server": _preview(to_server),
                        "preview_to_client": _preview(to_client),
                    }
                )

            # Any conversation on an authentication port may carry
            # credentials, whether or not it also carried a file.
            if stream.server_port in credentials.AUTH_PORTS and \
                    len(r.credentials) < credentials.MAX_CREDENTIALS:
                for cred in credentials.extract_from_stream(
                    stream, to_server, to_client
                ):
                    r.credentials.append(cred.to_dict())

            if file_index >= carve.MAX_FILES:
                continue

            file_index = self._carve_stream(
                stream, to_server, to_client, file_index
            )

        r.files.sort(
            key=lambda f: (
                -max(
                    [
                        {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
                            s["severity"], 0
                        )
                        for s in f["signatures"]
                    ]
                    or [0]
                ),
                -f["size"],
            )
        )

    def _carve_stream(self, stream, to_server: bytes, to_client: bytes, index: int) -> int:
        """Extract files from one reassembled conversation."""
        r = self.result

        # HTTP: responses carry the payload, requests carry the URL.
        if to_client[:5] == b"HTTP/" or to_server[:4] in (b"GET ", b"POST", b"HEAD"):
            requests = split_http_messages(to_server) if to_server else []
            responses = split_http_messages(to_client) if to_client else []

            urls: list[str | None] = []
            for message in requests:
                parsed = protocols.parse_http_request(message)
                urls.append(
                    f"{parsed['host']}{parsed['uri']}"
                    if parsed and parsed.get("host")
                    else (parsed["uri"] if parsed else None)
                )

            for position, message in enumerate(responses):
                parsed = protocols.parse_http_response(message)
                if not parsed:
                    continue
                body = message.partition(b"\r\n\r\n")[2]
                if len(body) < carve.MIN_FILE_BYTES:
                    continue

                url = urls[position] if position < len(urls) else None
                carved = carve.carve_file(
                    body,
                    index=index,
                    source=stream.server,
                    destination=stream.client,
                    protocol="HTTP",
                    url=url,
                    content_type=parsed.get("content_type"),
                    filename=carve.filename_from_url(url),
                    packet=stream.first_packet,
                    ts=stream.first_seen,
                    truncated=not stream.complete,
                )
                if carved:
                    self._store_artifact(carved, body)
                    r.files.append(carved.to_dict())
                    index += 1
                    if index >= carve.MAX_FILES:
                        return index

            return index

        # SMB carries files inside Read and Write commands rather than as a
        # raw byte stream, so it needs its own reconstruction.
        if stream.server_port in (445, 139):
            return self._carve_smb(stream, to_server, to_client, index)

        # FTP data, TFTP and anything else: carve on magic bytes alone.
        if stream.server_port in (20, 21, 69) or stream.service in (
            "FTP-Data", "TFTP"
        ):
            for direction, data in (("download", to_client), ("upload", to_server)):
                if len(data) < carve.MIN_FILE_BYTES:
                    continue
                extension, _desc, _cat = carve.identify(data)
                if extension in ("bin", "txt"):
                    continue
                carved = carve.carve_file(
                    data,
                    index=index,
                    source=stream.server if direction == "download" else stream.client,
                    destination=stream.client if direction == "download" else stream.server,
                    protocol=stream.service or "TCP",
                    packet=stream.first_packet,
                    ts=stream.first_seen,
                    truncated=not stream.complete,
                )
                if carved:
                    self._store_artifact(carved, data)
                    r.files.append(carved.to_dict())
                    index += 1
                    if index >= carve.MAX_FILES:
                        return index

        return index

    def _carve_smb(self, stream, to_server: bytes, to_client: bytes,
                   index: int) -> int:
        """
        Rebuild files transferred over SMB.

        Data arrives inside Read responses and Write requests, each carrying
        its own file offset, so the pieces are placed by offset rather than
        appended in arrival order.
        """
        r = self.result
        names: list[str] = []
        transfers: dict[str, dict[int, bytes]] = {
            "read": {}, "write": {},
        }
        read_cursor = 0

        for direction_data, is_client in ((to_server, True), (to_client, False)):
            if not direction_data:
                continue
            for message in protocols_ext.iter_smb2_messages(direction_data):
                name = protocols_ext.parse_smb2_create(message)
                if name and len(names) < 40:
                    names.append(name)
                    continue

                transfer = protocols_ext.parse_smb2_transfer(message)
                if not transfer:
                    continue

                if transfer["direction"] == "read":
                    # Read responses carry no offset field, so they are laid
                    # down in the order they arrived.
                    transfers["read"][read_cursor] = transfer["data"]
                    read_cursor += len(transfer["data"])
                else:
                    transfers["write"][transfer["offset"] or 0] = transfer["data"]

        for direction, chunks in transfers.items():
            if not chunks:
                continue
            total = sum(len(c) for c in chunks.values())
            if total < carve.MIN_FILE_BYTES or total > carve.MAX_FILE_BYTES:
                continue

            assembled = bytearray()
            for offset in sorted(chunks):
                # Write offsets come from the capture. Bound the rebuilt span,
                # not only the bytes carried, or a handful of tiny writes far
                # apart turns into a multi-gigabyte buffer.
                if offset + len(chunks[offset]) > carve.MAX_FILE_BYTES:
                    break
                if offset > len(assembled):
                    gap = offset - len(assembled)
                    if gap > 1024 * 1024:
                        break
                    assembled.extend(b"\x00" * gap)
                assembled[offset:offset + len(chunks[offset])] = chunks[offset]

            filename = None
            for candidate in names:
                leaf = candidate.replace("\\", "/").rsplit("/", 1)[-1]
                if "." in leaf:
                    filename = leaf
                    break

            carved = carve.carve_file(
                bytes(assembled),
                index=index,
                source=stream.server if direction == "read" else stream.client,
                destination=stream.client if direction == "read" else stream.server,
                protocol="SMB",
                filename=filename,
                packet=stream.first_packet,
                ts=stream.first_seen,
                truncated=not stream.complete,
            )
            if carved:
                carved.notes.append(
                    f"Reconstructed from {len(chunks)} SMB {direction} "
                    "operations."
                )
                self._store_artifact(carved, bytes(assembled))
                r.files.append(carved.to_dict())
                index += 1
                if index >= carve.MAX_FILES:
                    return index

        return index

    def _store_artifact(self, carved, data: bytes) -> None:
        """Write a carved file to disk so it can be retrieved intact."""
        if not self.artifact_dir:
            return
        try:
            directory = Path(self.artifact_dir)
            directory.mkdir(parents=True, exist_ok=True)
            # Named by hash: identical transfers collapse to one file, and
            # the name cannot be influenced by anything on the wire.
            target = directory / f"{carved.sha256}.bin"
            if not target.exists():
                target.write_bytes(data)
            carved.stored = True
        except OSError:
            carved.stored = False

    def _finalise_voip(self):
        """Attach media streams to the calls that negotiated them."""
        r = self.result
        if not r.calls and not r.rtp_streams:
            return

        for stream in r.rtp_streams.values():
            expected = stream["last_sequence"] - stream["first_sequence"] + 1
            if expected < 1:
                expected = stream["packets"]
            # Sequence numbers wrap at 16 bits; a negative span means the
            # stream ran past the wrap rather than lost everything.
            if expected < stream["packets"]:
                expected = stream["packets"]
            stream["expected_packets"] = expected
            stream["lost_packets"] = max(0, expected - stream["packets"])
            stream["loss_percent"] = round(
                stream["lost_packets"] / expected * 100, 1
            ) if expected else 0.0
            duration = stream["last_seen"] - stream["first_seen"]
            stream["duration"] = round(duration, 1)

        endpoints = {}
        for stream in r.rtp_streams.values():
            endpoints.setdefault(f"{stream['src']}:{stream['src_port']}", []).append(stream)
            endpoints.setdefault(f"{stream['dst']}:{stream['dst_port']}", []).append(stream)

        for call in r.calls.values():
            for endpoint in call.media_endpoints:
                for stream in endpoints.get(endpoint, []):
                    summary = {
                        "from": f"{stream['src']}:{stream['src_port']}",
                        "to": f"{stream['dst']}:{stream['dst_port']}",
                        "codec": stream["codec"],
                        "packets": stream["packets"],
                        "duration": stream["duration"],
                        "loss_percent": stream["loss_percent"],
                        "ssrc": stream["ssrc"],
                    }
                    if summary not in call.rtp_streams:
                        call.rtp_streams.append(summary)

    # -- enrichment ---------------------------------------------------------

    def _enrich_hosts(self):
        """Attach offline ownership context to every external address."""
        r = self.result
        for ip, host in r.hosts.items():
            if host.is_private:
                continue
            info = enrich.enrich(ip)
            r.enrichment[ip] = info
            if info.get("operator"):
                host.tags.add(info["operator"])
            if info.get("category") in ("anonymity", "suspicious"):
                host.tags.add(info["category"])

    # -- timeline -----------------------------------------------------------

    def _bump_timeline(self, ts: float, size: int, proto: str):
        if not ts:
            return
        bucket = int(ts)
        entry = self.result.timeline.get(bucket)
        if entry is None:
            if len(self.result.timeline) > 200_000:
                return
            entry = {"packets": 0, "bytes": 0, "protocols": Counter()}
            self.result.timeline[bucket] = entry
        entry["packets"] += 1
        entry["bytes"] += size
        entry["protocols"][proto] += 1

    # -- profiling ----------------------------------------------------------

    def _build_profile(self):
        """
        Work out what kind of capture this is, so the report can lead with
        an accurate one-line characterisation instead of raw counts.
        """
        r = self.result
        total = max(1, sum(r.protocol_counts.values()))

        internal = [h for h in r.hosts.values() if h.is_private]
        external = [h for h in r.hosts.values() if not h.is_private]

        share = {k: v / total for k, v in r.protocol_counts.items()}
        dns_share = len(r.dns_records) / max(1, r.capture.packets)
        service_counts = Counter(f.service for f in r.flows.values() if f.service)

        traits: list[str] = []
        if service_counts.get("SMB", 0) or service_counts.get("Kerberos", 0):
            traits.append("windows-domain")
        if service_counts.get("HTTP", 0) > 20:
            traits.append("web-traffic")
        if service_counts.get("HTTPS", 0) > 20:
            traits.append("encrypted-web")
        if dns_share > 0.15:
            traits.append("dns-heavy")
        if len(external) > len(internal) * 3 and external:
            traits.append("internet-facing")
        if internal and not external:
            traits.append("internal-only")
        if share.get("ICMP", 0) > 0.2:
            traits.append("icmp-heavy")
        if r.encapsulations.get("VLAN"):
            traits.append("vlan-tagged")
        if any(h.version == 6 for h in r.hosts.values()):
            traits.append("dual-stack" if any(h.version == 4 for h in r.hosts.values()) else "ipv6-only")

        ipv6_hosts = sum(1 for h in r.hosts.values() if h.version == 6)

        r.profile = {
            "traits": traits,
            "internal_hosts": len(internal),
            "external_hosts": len(external),
            "ipv6_hosts": ipv6_hosts,
            "top_services": service_counts.most_common(10),
            "protocol_share": sorted(
                share.items(), key=lambda kv: kv[1], reverse=True
            )[:12],
            "summary": self._profile_sentence(traits, internal, external),
        }

    def _profile_sentence(self, traits, internal, external) -> str:
        r = self.result
        info = r.capture
        duration = info.duration
        if duration >= 3600:
            dur_text = f"{duration / 3600:.1f} hours"
        elif duration >= 60:
            dur_text = f"{duration / 60:.1f} minutes"
        else:
            dur_text = f"{duration:.1f} seconds"

        shape = "mixed traffic"
        if "windows-domain" in traits:
            shape = "Windows domain activity"
        elif "dns-heavy" in traits:
            shape = "DNS-dominated traffic"
        elif "encrypted-web" in traits and "web-traffic" not in traits:
            shape = "mostly encrypted web traffic"
        elif "web-traffic" in traits:
            shape = "web traffic"
        elif "icmp-heavy" in traits:
            shape = "unusually ICMP-heavy traffic"

        scope = "internal network only"
        if "internet-facing" in traits:
            scope = "traffic crossing the network edge"
        elif external and internal:
            scope = "internal hosts talking to external services"

        return (
            f"{info.packets:,} packets over {dur_text}, {len(internal)} internal "
            f"and {len(external)} external hosts. Dominated by {shape}, "
            f"showing {scope}."
        )

    # -- scoring ------------------------------------------------------------

    def _finalise(self):
        r = self.result

        # Push finding severity onto the hosts they name.
        weight = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
        for f in r.findings:
            for ip in f.hosts:
                host = r.hosts.get(ip)
                if host:
                    host.risk = min(100, host.risk + weight.get(f.severity, 0))
                    host.tags.add(f.category)

        for host in r.hosts.values():
            if host.macs:
                vendors = {lookup_vendor(m) for m in host.macs}
                vendors.discard(None)
                if vendors:
                    host.tags.add(next(iter(vendors)))

        r.findings.sort(
            key=lambda f: (
                -{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
                    f.severity, 0
                ),
                -f.count,
            )
        )

        score = risk_score(r.findings)
        sev_counts = Counter(f.severity for f in r.findings)

        r.stats = {
            "risk_score": score,
            "risk_band": risk_band(score),
            "verdict": risk_verdict(score, r.findings),
            "findings_total": len(r.findings),
            "severity_counts": dict(sev_counts),
            "hosts": len(r.hosts),
            "flows": len(r.flows),
            "dns_queries": sum(
                len(d["queries"]) for d in r.dns_records if not d["is_response"]
            ),
            "unique_domains": len(
                {
                    q["name"].lower()
                    for d in r.dns_records
                    for q in d["queries"]
                    if q["name"]
                }
            ),
            "http_requests": sum(
                1 for h in r.http_records if h.get("kind") == "request"
            ),
            "tls_sessions": len(r.tls_records),
            "unique_sni": len({t["sni"] for t in r.tls_records if t.get("sni")}),
            "certificates": len(r.certificates),
            "dropped_flows": r.dropped_flows,
            "dropped_hosts": r.dropped_hosts,
        }


def summarise_intervals(times: list[float]) -> dict:
    """
    Timing statistics used by beacon scoring.

    Returns coefficient of variation and median absolute deviation of the
    gaps between events. Low variation across many events is the signature
    of an automated callback rather than human-driven traffic.
    """
    if len(times) < 4:
        return {}
    times = sorted(times)
    gaps = [b - a for a, b in zip(times, times[1:]) if b > a]
    if len(gaps) < 3:
        return {}

    mean_gap = statistics.fmean(gaps)
    if mean_gap <= 0:
        return {}
    stdev = statistics.pstdev(gaps)
    median_gap = statistics.median(gaps)
    mad = statistics.median([abs(g - median_gap) for g in gaps]) if gaps else 0.0

    return {
        "count": len(gaps),
        "mean": mean_gap,
        "median": median_gap,
        "stdev": stdev,
        "cv": stdev / mean_gap,
        "mad": mad,
        "mad_ratio": (mad / median_gap) if median_gap else 1.0,
        "min": min(gaps),
        "max": max(gaps),
    }


def _preview(data: bytes, limit: int = 900) -> str:
    """
    Render the start of a stream as readable text.

    Non-printable bytes become dots rather than being dropped, so the
    offset of anything readable still lines up with its real position.
    """
    if not data:
        return ""
    window = data[:limit]
    out = []
    for byte in window:
        if byte in (9, 10, 13) or 32 <= byte < 127:
            out.append(chr(byte))
        else:
            out.append(".")
    text = "".join(out)
    if len(data) > limit:
        text += f"\n… {len(data) - limit:,} more bytes"
    return text
