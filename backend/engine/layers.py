"""
WireCub frame decoder.

Walks a frame from the link layer down to the transport payload, peeling
encapsulation as it goes. Pure Python, no external dissector.

Encapsulation handled: VLAN (802.1Q and QinQ), MPLS, PPPoE, GRE, VXLAN,
ERSPAN, IP-in-IP, 6in4, and Linux cooked capture. Nested combinations
work because the decoder loops rather than assuming a fixed stack.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

from .reader import (
    LINKTYPE_ETHERNET,
    LINKTYPE_IEEE802_11,
    LINKTYPE_IEEE802_11_RADIOTAP,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_LOOP,
    LINKTYPE_NULL,
    LINKTYPE_PPP,
    LINKTYPE_RAW,
    LINKTYPE_RAW_IPV4,
    LINKTYPE_RAW_IPV6,
)

# EtherTypes
ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_VLAN = 0x8100
ETH_QINQ = 0x88A8
ETH_QINQ_ALT = 0x9100
ETH_IPV6 = 0x86DD
ETH_MPLS_UC = 0x8847
ETH_MPLS_MC = 0x8848
ETH_PPPOE_DISC = 0x8863
ETH_PPPOE_SESS = 0x8864
ETH_LLDP = 0x88CC
ETH_EAPOL = 0x888E

# IP protocol numbers
IP_ICMP = 1
IP_IGMP = 2
IP_IPIP = 4
IP_TCP = 6
IP_UDP = 17
IP_IPV6 = 41
IP_GRE = 47
IP_ESP = 50
IP_AH = 51
IP_ICMPV6 = 58
IP_NONXT = 59
IP_OSPF = 89
IP_SCTP = 132

# IPv6 extension headers we must walk past to reach the transport header
IPV6_EXT_HEADERS = {
    0,    # Hop-by-Hop Options
    43,   # Routing
    44,   # Fragment
    51,   # Authentication Header
    60,   # Destination Options
    135,  # Mobility
    139,  # HIP
    140,  # Shim6
}

PROTO_NAMES = {
    IP_ICMP: "ICMP",
    IP_IGMP: "IGMP",
    IP_TCP: "TCP",
    IP_UDP: "UDP",
    IP_GRE: "GRE",
    IP_ESP: "ESP",
    IP_AH: "AH",
    IP_ICMPV6: "ICMPv6",
    IP_OSPF: "OSPF",
    IP_SCTP: "SCTP",
    IP_IPIP: "IPIP",
    IP_IPV6: "IPv6-in-IPv4",
}

# TCP flag bits
TH_FIN, TH_SYN, TH_RST, TH_PSH, TH_ACK, TH_URG, TH_ECE, TH_CWR = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
)

VXLAN_PORT = 4789
GENEVE_PORT = 6081


@dataclass(slots=True)
class Decoded:
    """Everything the decoder could establish about one frame."""

    # Link layer
    src_mac: str | None = None
    dst_mac: str | None = None
    ethertype: int | None = None

    # Network layer
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_version: int | None = None
    ttl: int | None = None
    ip_len: int | None = None
    ip_id: int | None = None
    ip_flags: int | None = None
    frag_offset: int | None = None
    dscp: int | None = None
    flow_label: int | None = None      # IPv6 only
    protocol: int | None = None

    # Transport layer
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int | None = None
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    tcp_window: int | None = None
    tcp_options: bytes | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None

    # ARP
    arp_op: int | None = None
    arp_sender_ip: str | None = None
    arp_sender_mac: str | None = None
    arp_target_ip: str | None = None
    arp_target_mac: str | None = None

    # Payload and provenance
    payload: bytes = b""
    payload_offset: int = 0
    encapsulation: list[str] = field(default_factory=list)
    vlan_ids: list[int] = field(default_factory=list)
    mpls_labels: list[int] = field(default_factory=list)
    tunnel_depth: int = 0
    error: str | None = None

    @property
    def is_ipv6(self) -> bool:
        return self.ip_version == 6

    @property
    def transport(self) -> str:
        if self.protocol is None:
            return "—"
        return PROTO_NAMES.get(self.protocol, f"IP proto {self.protocol}")

    @property
    def tcp_flag_str(self) -> str:
        if self.tcp_flags is None:
            return ""
        names = []
        for bit, name in (
            (TH_CWR, "C"), (TH_ECE, "E"), (TH_URG, "U"), (TH_ACK, "A"),
            (TH_PSH, "P"), (TH_RST, "R"), (TH_SYN, "S"), (TH_FIN, "F"),
        ):
            if self.tcp_flags & bit:
                names.append(name)
        return "".join(names)


def _mac(raw: bytes) -> str:
    # hex(sep) is a single C call; the generator-and-join version showed up
    # as the hottest line in the profile at two calls per packet.
    return raw.hex(":")


def _ipv4(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET, raw)


def _ipv6(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, raw)


# ---------------------------------------------------------------------------
# Link layer entry points
# ---------------------------------------------------------------------------

def decode(data: bytes, linktype: int) -> Decoded:
    """Decode one frame. Never raises: failures land in Decoded.error."""
    d = Decoded()
    try:
        if linktype == LINKTYPE_ETHERNET:
            _ethernet(data, 0, d)
        elif linktype in (LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2):
            _linux_cooked(data, d, v2=(linktype == LINKTYPE_LINUX_SLL2))
        elif linktype in (LINKTYPE_RAW, LINKTYPE_RAW_IPV4):
            _ip(data, 0, d)
        elif linktype == LINKTYPE_RAW_IPV6:
            _ipv6_header(data, 0, d)
        elif linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
            _null_loopback(data, d)
        elif linktype == LINKTYPE_PPP:
            _ppp(data, 0, d)
        elif linktype in (LINKTYPE_IEEE802_11, LINKTYPE_IEEE802_11_RADIOTAP):
            _dot11(data, d, radiotap=(linktype == LINKTYPE_IEEE802_11_RADIOTAP))
        else:
            # Unknown link type: try to find an IP header anyway.
            _ip(data, 0, d)
    except (struct.error, IndexError, ValueError, OSError) as exc:
        d.error = f"{type(exc).__name__}: {exc}"
    return d


def _ethernet(data: bytes, off: int, d: Decoded) -> None:
    if len(data) - off < 14:
        d.error = "Frame shorter than an Ethernet header"
        return
    d.dst_mac = _mac(data[off:off + 6])
    d.src_mac = _mac(data[off + 6:off + 12])
    etype = struct.unpack("!H", data[off + 12:off + 14])[0]
    off += 14
    _after_ethertype(data, off, etype, d)


def _after_ethertype(data: bytes, off: int, etype: int, d: Decoded) -> None:
    """Peel VLAN/MPLS/PPPoE tags until we reach a real network layer."""
    guard = 0
    while guard < 12:
        guard += 1

        if etype in (ETH_VLAN, ETH_QINQ, ETH_QINQ_ALT):
            if len(data) - off < 4:
                d.error = "Truncated VLAN tag"
                return
            tci = struct.unpack("!H", data[off:off + 2])[0]
            vid = tci & 0x0FFF
            d.vlan_ids.append(vid)
            d.encapsulation.append(f"VLAN {vid}")
            etype = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
            continue

        if etype in (ETH_MPLS_UC, ETH_MPLS_MC):
            while len(data) - off >= 4:
                label_bits = struct.unpack("!I", data[off:off + 4])[0]
                label = label_bits >> 12
                bottom = (label_bits >> 8) & 1
                d.mpls_labels.append(label)
                off += 4
                if bottom:
                    break
            d.encapsulation.append(
                "MPLS " + "/".join(str(x) for x in d.mpls_labels)
            )
            # After the label stack the payload is IP; sniff the version.
            if len(data) > off:
                version = data[off] >> 4
                etype = ETH_IPV6 if version == 6 else ETH_IPV4
                continue
            return

        if etype == ETH_PPPOE_SESS:
            if len(data) - off < 8:
                d.error = "Truncated PPPoE header"
                return
            d.encapsulation.append("PPPoE")
            off += 6
            _ppp(data, off, d)
            return

        break

    d.ethertype = etype

    if etype == ETH_IPV4:
        _ip(data, off, d)
    elif etype == ETH_IPV6:
        _ipv6_header(data, off, d)
    elif etype == ETH_ARP:
        _arp(data, off, d)
    else:
        d.payload = data[off:]
        d.payload_offset = off


def _linux_cooked(data: bytes, d: Decoded, v2: bool = False) -> None:
    if v2:
        if len(data) < 20:
            d.error = "Truncated Linux cooked v2 header"
            return
        etype = struct.unpack("!H", data[0:2])[0]
        addr_len = struct.unpack("!H", data[10:12])[0]
        if addr_len == 6:
            d.src_mac = _mac(data[12:18])
        off = 20
    else:
        if len(data) < 16:
            d.error = "Truncated Linux cooked header"
            return
        addr_len = struct.unpack("!H", data[4:6])[0]
        if addr_len == 6:
            d.src_mac = _mac(data[6:12])
        etype = struct.unpack("!H", data[14:16])[0]
        off = 16
    d.encapsulation.append("Linux cooked")
    _after_ethertype(data, off, etype, d)


def _null_loopback(data: bytes, d: Decoded) -> None:
    if len(data) < 4:
        d.error = "Truncated loopback header"
        return
    family = struct.unpack("<I", data[0:4])[0]
    if family > 0xFFFF:  # wrong endianness
        family = struct.unpack(">I", data[0:4])[0]
    if family == 2:
        _ip(data, 4, d)
    elif family in (24, 28, 30):
        _ipv6_header(data, 4, d)
    else:
        d.payload = data[4:]


def _ppp(data: bytes, off: int, d: Decoded) -> None:
    if len(data) - off < 2:
        d.error = "Truncated PPP header"
        return
    proto = struct.unpack("!H", data[off:off + 2])[0]
    off += 2
    if proto == 0x0021:
        _ip(data, off, d)
    elif proto == 0x0057:
        _ipv6_header(data, off, d)
    else:
        d.payload = data[off:]


def _dot11(data: bytes, d: Decoded, radiotap: bool) -> None:
    off = 0
    if radiotap:
        if len(data) < 4:
            d.error = "Truncated radiotap header"
            return
        rt_len = struct.unpack("<H", data[2:4])[0]
        off += rt_len
        d.encapsulation.append("Radiotap")
    if len(data) - off < 24:
        d.error = "Truncated 802.11 header"
        return
    fc = struct.unpack("<H", data[off:off + 2])[0]
    ftype = (fc >> 2) & 0x3
    d.encapsulation.append("802.11")
    d.dst_mac = _mac(data[off + 4:off + 10])
    d.src_mac = _mac(data[off + 10:off + 16])
    if ftype != 2:  # only data frames carry IP
        d.payload = data[off + 24:]
        return
    off += 24
    # LLC/SNAP
    if len(data) - off >= 8 and data[off:off + 3] == b"\xaa\xaa\x03":
        etype = struct.unpack("!H", data[off + 6:off + 8])[0]
        _after_ethertype(data, off + 8, etype, d)
    else:
        d.payload = data[off:]


# ---------------------------------------------------------------------------
# Network layer
# ---------------------------------------------------------------------------

def _ip(data: bytes, off: int, d: Decoded) -> None:
    if len(data) - off < 20:
        d.error = "Truncated IPv4 header"
        return
    vhl = data[off]
    version = vhl >> 4

    if version == 6:
        _ipv6_header(data, off, d)
        return
    if version != 4:
        d.error = f"Not an IP header (version field is {version})"
        return

    ihl = (vhl & 0x0F) * 4
    if ihl < 20:
        d.error = "IPv4 header length below minimum"
        return

    tos = data[off + 1]
    total_len, ip_id, flags_frag, ttl, proto = struct.unpack(
        "!HHHBB", data[off + 2:off + 10]
    )

    d.ip_version = 4
    d.dscp = tos >> 2
    d.ip_len = total_len
    d.ip_id = ip_id
    d.ip_flags = flags_frag >> 13
    d.frag_offset = (flags_frag & 0x1FFF) * 8
    d.ttl = ttl
    d.protocol = proto
    d.src_ip = _ipv4(data[off + 12:off + 16])
    d.dst_ip = _ipv4(data[off + 16:off + 20])

    # Any fragment, first or not, is handed over whole. Fragment offsets are
    # measured from the start of the IP payload, so consuming the transport
    # header here would shift every subsequent fragment by its length.
    more_fragments = bool(d.ip_flags & 0x01)
    if d.frag_offset or more_fragments:
        d.payload = data[off + ihl:off + total_len] if total_len >= ihl else data[off + ihl:]
        d.payload_offset = off + ihl
        d.encapsulation.append("IPv4 fragment")
        return

    # Trim to the length IP declares, discarding any link-layer padding.
    end = off + total_len if ihl <= total_len <= len(data) - off else len(data)
    _transport(data, off + ihl, proto, d, end)


def _ipv6_header(data: bytes, off: int, d: Decoded) -> None:
    if len(data) - off < 40:
        d.error = "Truncated IPv6 header"
        return

    first_word = struct.unpack("!I", data[off:off + 4])[0]
    version = first_word >> 28
    if version != 6:
        d.error = f"Not an IPv6 header (version field is {version})"
        return

    traffic_class = (first_word >> 20) & 0xFF
    flow_label = first_word & 0xFFFFF
    payload_len, next_header, hop_limit = struct.unpack(
        "!HBB", data[off + 4:off + 8]
    )

    d.ip_version = 6
    d.dscp = traffic_class >> 2
    d.flow_label = flow_label
    d.ip_len = payload_len + 40
    d.ttl = hop_limit
    d.src_ip = _ipv6(data[off + 8:off + 24])
    d.dst_ip = _ipv6(data[off + 24:off + 40])

    pos = off + 40
    proto = next_header
    guard = 0
    is_fragment = False

    # Walk the extension header chain to reach the transport header.
    while proto in IPV6_EXT_HEADERS and guard < 16:
        guard += 1
        if len(data) - pos < 2:
            d.error = "Truncated IPv6 extension header"
            d.protocol = proto
            return

        if proto == 44:  # Fragment header is a fixed 8 bytes
            frag_off_field = struct.unpack("!H", data[pos + 2:pos + 4])[0]
            d.frag_offset = (frag_off_field >> 3) * 8
            # Bit 0 is the more-fragments flag, the IPv6 equivalent of the
            # IPv4 MF bit. Reassembly needs it to know where a datagram ends.
            d.ip_flags = frag_off_field & 0x01
            is_fragment = True
            d.encapsulation.append("IPv6 fragment")
            proto = data[pos]
            pos += 8
            d.protocol = proto
            d.payload = data[pos:]
            d.payload_offset = pos
            return

        if proto == 51:  # Authentication Header uses a different length unit
            ext_len = (data[pos + 1] + 2) * 4
        else:
            ext_len = (data[pos + 1] + 1) * 8

        d.encapsulation.append(f"IPv6 ext {proto}")
        proto = data[pos]
        pos += ext_len

    d.protocol = proto
    if proto == IP_NONXT:
        d.payload = b""
        return
    _transport(data, pos, proto, d)


def _arp(data: bytes, off: int, d: Decoded) -> None:
    if len(data) - off < 28:
        d.error = "Truncated ARP packet"
        return
    hw_type, proto_type, hw_len, proto_len, op = struct.unpack(
        "!HHBBH", data[off:off + 8]
    )
    if hw_len != 6 or proto_len != 4:
        return
    d.arp_op = op
    d.arp_sender_mac = _mac(data[off + 8:off + 14])
    d.arp_sender_ip = _ipv4(data[off + 14:off + 18])
    d.arp_target_mac = _mac(data[off + 18:off + 24])
    d.arp_target_ip = _ipv4(data[off + 24:off + 28])
    d.protocol = None


# ---------------------------------------------------------------------------
# Transport layer and tunnels
# ---------------------------------------------------------------------------

def _transport(data: bytes, off: int, proto: int, d: Decoded,
               end: int | None = None) -> None:
    # A frame padded up to the Ethernet minimum carries bytes past the end
    # of the IP datagram. Those are not payload and must not reach the
    # reassembler, where they would appear as data in the middle of a
    # stream.
    if end is not None and 0 < end <= len(data):
        data = data[:end]

    if proto == IP_TCP:
        _tcp(data, off, d)
    elif proto == IP_UDP:
        _udp(data, off, d)
    elif proto == IP_ICMP:
        _icmp(data, off, d)
    elif proto == IP_ICMPV6:
        _icmpv6(data, off, d)
    elif proto == IP_GRE:
        _gre(data, off, d)
    elif proto in (IP_IPIP, IP_IPV6):
        # IP directly inside IP: a tunnel, so recurse into the inner packet.
        d.tunnel_depth += 1
        if d.tunnel_depth > 4:
            d.error = "Tunnel nesting too deep"
            return
        d.encapsulation.append("IP-in-IP" if proto == IP_IPIP else "6in4")
        if proto == IP_IPIP:
            _ip(data, off, d)
        else:
            _ipv6_header(data, off, d)
    else:
        d.payload = data[off:]
        d.payload_offset = off


def _tcp(data: bytes, off: int, d: Decoded) -> None:
    if len(data) - off < 20:
        d.error = "Truncated TCP header"
        return
    (src_port, dst_port, seq, ack, offx, flags, window) = struct.unpack(
        "!HHIIBBH", data[off:off + 16]
    )
    hdr_len = (offx >> 4) * 4
    if hdr_len < 20:
        hdr_len = 20

    d.src_port = src_port
    d.dst_port = dst_port
    d.tcp_seq = seq
    d.tcp_ack = ack
    d.tcp_flags = flags
    d.tcp_window = window
    if hdr_len > 20:
        d.tcp_options = data[off + 20:off + hdr_len]
    d.payload = data[off + hdr_len:]
    d.payload_offset = off + hdr_len


def _udp(data: bytes, off: int, d: Decoded) -> None:
    if len(data) - off < 8:
        d.error = "Truncated UDP header"
        return
    src_port, dst_port, length, _cksum = struct.unpack("!HHHH", data[off:off + 8])
    d.src_port = src_port
    d.dst_port = dst_port
    payload_start = off + 8
    d.payload = data[payload_start:]
    d.payload_offset = payload_start

    # VXLAN and Geneve carry a whole inner Ethernet frame.
    if dst_port == VXLAN_PORT and len(d.payload) >= 8:
        d.tunnel_depth += 1
        if d.tunnel_depth > 4:
            return
        vni = struct.unpack("!I", b"\x00" + d.payload[4:7])[0]
        d.encapsulation.append(f"VXLAN {vni}")
        _ethernet(data, payload_start + 8, d)
    elif dst_port == GENEVE_PORT and len(d.payload) >= 8:
        d.tunnel_depth += 1
        if d.tunnel_depth > 4:
            return
        opt_len = (d.payload[0] & 0x3F) * 4
        inner_type = struct.unpack("!H", d.payload[2:4])[0]
        d.encapsulation.append("Geneve")
        inner_start = payload_start + 8 + opt_len
        if inner_type == 0x6558:
            # Transparent Ethernet bridging: the payload is a whole frame,
            # not a bare IP packet. Geneve carries this far more often than
            # it carries IP directly.
            _ethernet(data, inner_start, d)
        else:
            _after_ethertype(data, inner_start, inner_type, d)


def _icmp(data: bytes, off: int, d: Decoded) -> None:
    if len(data) - off < 4:
        d.error = "Truncated ICMP header"
        return
    d.icmp_type = data[off]
    d.icmp_code = data[off + 1]
    d.payload = data[off + 8:] if len(data) - off >= 8 else b""
    d.payload_offset = off + 8


def _icmpv6(data: bytes, off: int, d: Decoded) -> None:
    if len(data) - off < 4:
        d.error = "Truncated ICMPv6 header"
        return
    d.icmp_type = data[off]
    d.icmp_code = data[off + 1]
    d.payload = data[off + 4:]
    d.payload_offset = off + 4


def _gre(data: bytes, off: int, d: Decoded) -> None:
    if len(data) - off < 4:
        d.error = "Truncated GRE header"
        return
    flags, proto = struct.unpack("!HH", data[off:off + 4])
    hdr = 4
    if flags & 0x8000:  # checksum present
        hdr += 4
    if flags & 0x2000:  # key present
        hdr += 4
    if flags & 0x1000:  # sequence present
        hdr += 4

    d.tunnel_depth += 1
    if d.tunnel_depth > 4:
        d.error = "Tunnel nesting too deep"
        return

    # ERSPAN rides on GRE with its own shim header.
    if proto in (0x88BE, 0x22EB):
        d.encapsulation.append("ERSPAN")
        shim = 8 if proto == 0x88BE else 12
        _ethernet(data, off + hdr + shim, d)
        return

    d.encapsulation.append("GRE")
    if proto == 0x6558:  # transparent Ethernet bridging
        _ethernet(data, off + hdr, d)
    else:
        _after_ethertype(data, off + hdr, proto, d)


def rebuild_from_payload(original: Decoded, payload: bytes) -> Decoded:
    """
    Re-decode a datagram once its fragments have been reassembled.

    The first fragment carried the network header but only part of the
    transport header. With the whole payload in hand the transport layer
    can be read properly, so the result is the original network-layer
    facts plus a complete transport decode.
    """
    rebuilt = Decoded(
        src_mac=original.src_mac,
        dst_mac=original.dst_mac,
        ethertype=original.ethertype,
        src_ip=original.src_ip,
        dst_ip=original.dst_ip,
        ip_version=original.ip_version,
        ttl=original.ttl,
        ip_len=len(payload),
        ip_id=original.ip_id,
        dscp=original.dscp,
        flow_label=original.flow_label,
        protocol=original.protocol,
        encapsulation=list(original.encapsulation) + ["reassembled"],
        vlan_ids=list(original.vlan_ids),
        mpls_labels=list(original.mpls_labels),
        tunnel_depth=original.tunnel_depth,
    )

    try:
        _transport(payload, 0, original.protocol or 0, rebuilt)
    except (struct.error, IndexError, ValueError):
        rebuilt.payload = payload
        rebuilt.error = "Reassembled datagram could not be decoded"

    return rebuilt
