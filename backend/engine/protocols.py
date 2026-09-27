"""
WireCub application-layer decoders.

Lightweight parsers for the protocols that carry the most investigative
signal: DNS, HTTP, and TLS. Each returns plain dicts and never raises, so
a malformed packet degrades to "no result" instead of killing the run.

TLS fingerprinting (JA3, JA3S, JA4) is computed here from raw handshake
bytes, so it works without any external dissector.
"""

from __future__ import annotations

import hashlib
import math
import struct

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 46: "RRSIG", 47: "NSEC",
    48: "DNSKEY", 65: "HTTPS", 99: "SPF", 252: "AXFR", 255: "ANY", 10: "NULL",
}

DNS_RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}


def _dns_name(data: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    """Read a DNS name, following compression pointers."""
    labels: list[str] = []
    jumped = False
    end_off = off
    guard = 0

    while off < len(data) and guard < 128:
        guard += 1
        length = data[off]

        if length == 0:
            off += 1
            if not jumped:
                end_off = off
            break

        if length & 0xC0 == 0xC0:  # compression pointer
            if off + 2 > len(data) or depth > 8:
                break
            pointer = struct.unpack("!H", data[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end_off = off + 2
                jumped = True
            if pointer >= len(data) or pointer == off:
                break
            off = pointer
            depth += 1
            continue

        off += 1
        labels.append(data[off:off + length].decode("utf-8", "replace"))
        off += length
        if not jumped:
            end_off = off

    return ".".join(labels), end_off


def parse_dns(payload: bytes) -> dict | None:
    """Parse a DNS message into queries and answers."""
    if len(payload) < 12:
        return None
    try:
        txn_id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", payload[:12])
    except struct.error:
        return None

    is_response = bool(flags & 0x8000)
    rcode = flags & 0x000F
    off = 12
    queries = []

    for _ in range(min(qd, 32)):
        try:
            name, off = _dns_name(payload, off)
            if off + 4 > len(payload):
                break
            qtype, qclass = struct.unpack("!HH", payload[off:off + 4])
            off += 4
            queries.append({"name": name, "type": DNS_TYPES.get(qtype, str(qtype))})
        except (struct.error, IndexError):
            break

    answers = []
    for _ in range(min(an, 64)):
        try:
            name, off = _dns_name(payload, off)
            if off + 10 > len(payload):
                break
            rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", payload[off:off + 10])
            off += 10
            rdata = payload[off:off + rdlen]
            value = None
            if rtype == 1 and rdlen == 4:
                value = ".".join(str(b) for b in rdata)
            elif rtype == 28 and rdlen == 16:
                import socket as _s
                value = _s.inet_ntop(_s.AF_INET6, rdata)
            elif rtype in (5, 2, 12):
                value, _ = _dns_name(payload, off)
            elif rtype == 16:
                value = rdata[1:].decode("utf-8", "replace") if rdata else ""
            off += rdlen
            answers.append(
                {
                    "name": name,
                    "type": DNS_TYPES.get(rtype, str(rtype)),
                    "value": value,
                    "ttl": ttl,
                }
            )
        except (struct.error, IndexError):
            break

    return {
        "txn_id": txn_id,
        "is_response": is_response,
        "rcode": rcode,
        "rcode_name": DNS_RCODES.get(rcode, str(rcode)),
        "queries": queries,
        "answers": answers,
        "answer_count": an,
        "authority_count": ns,
        "additional_count": ar,
    }


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character. Drives DGA/tunnel scoring."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def byte_entropy(data: bytes) -> float:
    """Shannon entropy of raw bytes, 0-8. High values suggest encryption."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    total = 0.0
    for c in counts:
        if c:
            p = c / n
            total -= p * math.log2(p)
    return total


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

HTTP_METHODS = (
    b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS",
    b"PATCH", b"TRACE", b"CONNECT", b"PROPFIND", b"SEARCH",
)

# Prebuilt so the check is one C-level call rather than eleven string
# concatenations per payload inspected.
_HTTP_PREFIXES = tuple(method + b" " for method in HTTP_METHODS)


def parse_http_request(payload: bytes) -> dict | None:
    """Parse an HTTP request head. Returns None if this is not one."""
    if len(payload) < 16:
        return None
    if not payload.startswith(_HTTP_PREFIXES):
        return None

    head, _, body = payload.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines:
        return None

    # Request line is: METHOD SP request-target SP HTTP-VERSION.
    # Attack payloads routinely contain raw spaces in the target, so split
    # from both ends rather than assuming exactly three space-separated parts.
    method_part, sep, rest = lines[0].partition(b" ")
    if not sep:
        return None
    if rest.rfind(b" HTTP/") != -1:
        uri_part, version_part = rest.rsplit(b" ", 1)
    else:
        uri_part, version_part = rest, b""

    method = method_part.decode("ascii", "replace")
    uri = uri_part.decode("utf-8", "replace")
    version = version_part.decode("ascii", "replace")

    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if sep:
            headers[name.decode("ascii", "replace").strip().lower()] = (
                value.decode("utf-8", "replace").strip()
            )

    return {
        "kind": "request",
        "method": method,
        "uri": uri,
        "version": version,
        "host": headers.get("host"),
        "user_agent": headers.get("user-agent"),
        "referer": headers.get("referer"),
        "content_type": headers.get("content-type"),
        "content_length": headers.get("content-length"),
        "authorization": headers.get("authorization"),
        "cookie": headers.get("cookie"),
        "headers": headers,
        "body_preview": body[:2048],
    }


def parse_http_response(payload: bytes) -> dict | None:
    """Parse an HTTP response head. Returns None if this is not one."""
    if not payload.startswith(b"HTTP/"):
        return None

    head, _, body = payload.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ", 2)
    if len(parts) < 2:
        return None

    try:
        status = int(parts[1])
    except ValueError:
        return None

    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if sep:
            headers[name.decode("ascii", "replace").strip().lower()] = (
                value.decode("utf-8", "replace").strip()
            )

    return {
        "kind": "response",
        "status": status,
        "reason": parts[2].decode("utf-8", "replace") if len(parts) > 2 else "",
        "content_type": headers.get("content-type"),
        "content_length": headers.get("content-length"),
        "server": headers.get("server"),
        "headers": headers,
        "body_preview": body[:4096],
    }


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------

TLS_VERSIONS = {
    0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
    0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}

# GREASE values must be stripped before fingerprinting (RFC 8701)
GREASE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


def _ja4_alpn(alpn: list[str]) -> str:
    if not alpn:
        return "00"
    first = alpn[0]
    if len(first) < 2:
        return f"{first}{first}" if first else "00"
    return f"{first[0]}{first[-1]}"


def parse_tls_client_hello(payload: bytes) -> dict | None:
    """
    Parse a TLS ClientHello and compute JA3 and JA4 fingerprints.

    Returns None when the payload is not a ClientHello record.
    """
    if len(payload) < 45 or payload[0] != 0x16:  # handshake record
        return None

    try:
        record_version = struct.unpack("!H", payload[1:3])[0]
        record_len = struct.unpack("!H", payload[3:5])[0]
        if payload[5] != 0x01:  # ClientHello
            return None

        pos = 9  # skip record header + handshake header
        client_version = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        pos += 32  # random
        session_id_len = payload[pos]
        pos += 1 + session_id_len

        cipher_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        ciphers = [
            struct.unpack("!H", payload[pos + i:pos + i + 2])[0]
            for i in range(0, cipher_len, 2)
        ]
        pos += cipher_len

        comp_len = payload[pos]
        pos += 1 + comp_len

        sni = None
        alpn: list[str] = []
        extensions: list[int] = []
        curves: list[int] = []
        point_formats: list[int] = []
        sig_algs: list[int] = []
        supported_versions: list[int] = []

        if pos + 2 <= len(payload):
            ext_total = struct.unpack("!H", payload[pos:pos + 2])[0]
            pos += 2
            ext_end = min(pos + ext_total, len(payload))

            while pos + 4 <= ext_end:
                ext_type, ext_len = struct.unpack("!HH", payload[pos:pos + 4])
                pos += 4
                ext_data = payload[pos:pos + ext_len]
                pos += ext_len
                extensions.append(ext_type)

                if ext_type == 0x0000 and len(ext_data) >= 5:  # server_name
                    name_len = struct.unpack("!H", ext_data[3:5])[0]
                    sni = ext_data[5:5 + name_len].decode("utf-8", "replace")

                elif ext_type == 0x000A and len(ext_data) >= 2:  # supported_groups
                    glen = struct.unpack("!H", ext_data[:2])[0]
                    curves = [
                        struct.unpack("!H", ext_data[2 + i:4 + i])[0]
                        for i in range(0, min(glen, len(ext_data) - 2), 2)
                    ]

                elif ext_type == 0x000B and len(ext_data) >= 1:  # ec_point_formats
                    plen = ext_data[0]
                    point_formats = list(ext_data[1:1 + plen])

                elif ext_type == 0x000D and len(ext_data) >= 2:  # signature_algorithms
                    slen = struct.unpack("!H", ext_data[:2])[0]
                    sig_algs = [
                        struct.unpack("!H", ext_data[2 + i:4 + i])[0]
                        for i in range(0, min(slen, len(ext_data) - 2), 2)
                    ]

                elif ext_type == 0x0010 and len(ext_data) >= 2:  # ALPN
                    apos = 2
                    while apos < len(ext_data):
                        plen = ext_data[apos]
                        apos += 1
                        alpn.append(ext_data[apos:apos + plen].decode("ascii", "replace"))
                        apos += plen

                elif ext_type == 0x002B and len(ext_data) >= 1:  # supported_versions
                    vlen = ext_data[0]
                    supported_versions = [
                        struct.unpack("!H", ext_data[1 + i:3 + i])[0]
                        for i in range(0, min(vlen, len(ext_data) - 1), 2)
                    ]

    except (struct.error, IndexError, ValueError):
        return None

    # --- JA3: version,ciphers,extensions,curves,point_formats ---
    def clean(values):
        return [v for v in values if v not in GREASE]

    ja3_str = ",".join(
        [
            str(client_version),
            "-".join(str(c) for c in clean(ciphers)),
            "-".join(str(e) for e in clean(extensions)),
            "-".join(str(c) for c in clean(curves)),
            "-".join(str(p) for p in point_formats),
        ]
    )
    ja3 = hashlib.md5(ja3_str.encode()).hexdigest()

    # --- JA4: protocol/version/sni/counts/alpn _ ciphers _ extensions ---
    real_versions = clean(supported_versions) or [client_version]
    negotiated = max(real_versions)
    ver_map = {
        0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3",
    }
    ja4_ver = ver_map.get(negotiated, "00")
    clean_ciphers = clean(ciphers)
    clean_exts = [e for e in clean(extensions) if e not in (0x0000, 0x0010)]

    ja4_a = (
        f"t{ja4_ver}{'d' if sni else 'i'}"
        f"{min(len(clean_ciphers), 99):02d}"
        f"{min(len(clean_exts), 99):02d}"
        f"{_ja4_alpn(alpn)}"
    )
    ja4_b = hashlib.sha256(
        ",".join(f"{c:04x}" for c in sorted(clean_ciphers)).encode()
    ).hexdigest()[:12]
    ja4_c = hashlib.sha256(
        (
            ",".join(f"{e:04x}" for e in sorted(clean_exts))
            + "_"
            + ",".join(f"{s:04x}" for s in clean(sig_algs))
        ).encode()
    ).hexdigest()[:12]
    ja4 = f"{ja4_a}_{ja4_b}_{ja4_c}"

    return {
        "sni": sni,
        "ja3": ja3,
        "ja3_string": ja3_str,
        "ja4": ja4,
        "alpn": alpn,
        "version": TLS_VERSIONS.get(negotiated, f"0x{negotiated:04x}"),
        "record_version": TLS_VERSIONS.get(record_version, f"0x{record_version:04x}"),
        "cipher_count": len(clean_ciphers),
        "extension_count": len(clean_exts),
        "record_len": record_len,
    }


def parse_tls_server_hello(payload: bytes) -> dict | None:
    """Parse a ServerHello, computing JA3S."""
    if len(payload) < 45 or payload[0] != 0x16 or payload[5] != 0x02:
        return None
    try:
        pos = 9
        server_version = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + 32
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        cipher = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + 1  # cipher + compression

        extensions: list[int] = []
        if pos + 2 <= len(payload):
            ext_total = struct.unpack("!H", payload[pos:pos + 2])[0]
            pos += 2
            ext_end = min(pos + ext_total, len(payload))
            while pos + 4 <= ext_end:
                ext_type, ext_len = struct.unpack("!HH", payload[pos:pos + 4])
                pos += 4 + ext_len
                if ext_type not in GREASE:
                    extensions.append(ext_type)
    except (struct.error, IndexError):
        return None

    ja3s_str = (
        f"{server_version},{cipher},"
        + "-".join(str(e) for e in extensions)
    )
    return {
        "ja3s": hashlib.md5(ja3s_str.encode()).hexdigest(),
        "cipher": cipher,
        "version": TLS_VERSIONS.get(server_version, f"0x{server_version:04x}"),
    }


def extract_tls_certificates(payload: bytes) -> list[dict]:
    """
    Pull subject and issuer common names out of a TLS Certificate message.

    This is a deliberately shallow DER walk: it looks for commonName OIDs
    rather than fully parsing X.509, which keeps it fast and dependency free.
    """
    certs: list[dict] = []
    if len(payload) < 10 or payload[0] != 0x16:
        return certs
    if payload[5] != 0x0B:  # Certificate handshake message
        return certs

    cn_oid = b"\x06\x03\x55\x04\x03"  # OID 2.5.4.3 commonName
    org_oid = b"\x06\x03\x55\x04\x0a"  # OID 2.5.4.10 organizationName

    names: list[str] = []
    pos = 0
    while True:
        idx = payload.find(cn_oid, pos)
        if idx == -1 or len(names) >= 8:
            break
        vpos = idx + len(cn_oid)
        if vpos + 2 <= len(payload):
            tag = payload[vpos]
            length = payload[vpos + 1]
            if tag in (0x0C, 0x13, 0x16) and 0 < length < 100:
                value = payload[vpos + 2:vpos + 2 + length]
                names.append(value.decode("utf-8", "replace"))
        pos = idx + 1

    orgs: list[str] = []
    pos = 0
    while True:
        idx = payload.find(org_oid, pos)
        if idx == -1 or len(orgs) >= 4:
            break
        vpos = idx + len(org_oid)
        if vpos + 2 <= len(payload):
            length = payload[vpos + 1]
            if 0 < length < 100:
                orgs.append(
                    payload[vpos + 2:vpos + 2 + length].decode("utf-8", "replace")
                )
        pos = idx + 1

    if names:
        certs.append(
            {
                "subject_cn": names[0],
                "issuer_cn": names[1] if len(names) > 1 else None,
                "organizations": orgs,
                "chain_names": names,
                "self_signed": len(names) > 1 and names[0] == names[1],
            }
        )
    return certs


def is_tls_record(payload: bytes) -> bool:
    """Cheap check for a TLS record header, used before full parsing."""
    return (
        len(payload) >= 6
        and payload[0] in (0x14, 0x15, 0x16, 0x17)
        and payload[1] == 0x03
        and payload[2] <= 0x04
    )
