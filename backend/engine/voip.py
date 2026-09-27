"""
VoIP: SIP signalling and RTP media.

SIP is the call setup protocol and RTP carries the audio. Both matter to
an investigation for different reasons. SIP names the parties, carries the
authentication, and shows who called whom and when. RTP shows whether the
call actually happened, how long it lasted, and whether the audio was
encrypted.

Cleartext SIP is the norm on internal networks, which means the digest
authentication credentials, the caller and callee identities, and the
media endpoints are all readable from a capture. The same fact makes SIP
a standing target: toll fraud, registration hijacking and INVITE floods
all show up here.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

SIP_METHODS = (
    b"INVITE", b"ACK", b"BYE", b"CANCEL", b"REGISTER", b"OPTIONS",
    b"SUBSCRIBE", b"NOTIFY", b"REFER", b"INFO", b"UPDATE", b"PRACK",
    b"MESSAGE", b"PUBLISH",
)

SIP_PORTS = {5060, 5061, 5062, 5080}

# Payload type numbers from the RTP audio/video profile. Anything above 95
# is negotiated dynamically in the SDP.
RTP_PAYLOAD_TYPES = {
    0: "G.711 u-law", 3: "GSM", 4: "G.723", 5: "DVI4 8kHz",
    6: "DVI4 16kHz", 7: "LPC", 8: "G.711 A-law", 9: "G.722",
    10: "L16 stereo", 11: "L16 mono", 12: "QCELP", 13: "Comfort noise",
    14: "MPEG audio", 15: "G.728", 16: "DVI4 11kHz", 17: "DVI4 22kHz",
    18: "G.729", 25: "CelB", 26: "JPEG", 28: "nv", 31: "H.261",
    32: "MPEG video", 33: "MPEG2 TS", 34: "H.263",
}

_HEADER = re.compile(rb"^([A-Za-z\-]+)\s*:\s*(.*)$", re.MULTILINE)
_URI = re.compile(r"<?(sips?:[^>;\s]+)>?")
_TAG = re.compile(r'(\w+)="?([^",;]+)"?')


@dataclass
class SipMessage:
    """One parsed SIP request or response."""

    is_request: bool
    method: str | None = None
    status: int | None = None
    reason: str | None = None
    from_uri: str | None = None
    to_uri: str | None = None
    call_id: str | None = None
    user_agent: str | None = None
    contact: str | None = None
    cseq: str | None = None
    auth: dict | None = None
    sdp: dict | None = None
    via_hosts: list[str] = field(default_factory=list)


def looks_like_sip(payload: bytes) -> bool:
    """Cheap check before committing to a parse."""
    if len(payload) < 12:
        return False
    return payload.startswith(b"SIP/2.0") or payload.startswith(SIP_METHODS)


def parse_sip(payload: bytes) -> SipMessage | None:
    """
    Parse a SIP message.

    Only the fields an investigation uses are extracted: who, to whom,
    which call, what software, and any authentication.
    """
    if not looks_like_sip(payload):
        return None

    head, _, body = payload.partition(b"\r\n\r\n")
    try:
        text = head.decode("utf-8", "replace")
    except Exception:
        return None

    lines = text.split("\r\n")
    if not lines:
        return None

    start = lines[0]
    message = SipMessage(is_request=not start.startswith("SIP/2.0"))

    if message.is_request:
        parts = start.split(" ")
        message.method = parts[0] if parts else None
    else:
        parts = start.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            message.status = int(parts[1])
        if len(parts) >= 3:
            message.reason = parts[2]

    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep:
            continue
        headers.setdefault(name.strip().lower(), []).append(value.strip())

    def first(*names: str) -> str | None:
        for name in names:
            values = headers.get(name)
            if values:
                return values[0]
        return None

    def extract_uri(value: str | None) -> str | None:
        if not value:
            return None
        match = _URI.search(value)
        return match.group(1) if match else value.split(";")[0].strip()

    message.from_uri = extract_uri(first("from", "f"))
    message.to_uri = extract_uri(first("to", "t"))
    message.call_id = first("call-id", "i")
    message.user_agent = first("user-agent", "server")
    message.contact = extract_uri(first("contact", "m"))
    message.cseq = first("cseq")

    for via in headers.get("via", []) + headers.get("v", []):
        # "SIP/2.0/UDP host:port;branch=..."
        segments = via.split(" ")
        if len(segments) >= 2:
            message.via_hosts.append(segments[1].split(";")[0])

    # Authentication appears as a challenge from the server or a response
    # from the client. Both are worth recording: the challenge carries the
    # nonce the response was computed against.
    for header_name, direction in (
        ("authorization", "response"),
        ("proxy-authorization", "response"),
        ("www-authenticate", "challenge"),
        ("proxy-authenticate", "challenge"),
    ):
        value = first(header_name)
        if not value:
            continue
        scheme = value.split(" ", 1)[0]
        fields = dict(_TAG.findall(value))
        message.auth = {
            "direction": direction,
            "scheme": scheme,
            "username": fields.get("username"),
            "realm": fields.get("realm"),
            "nonce": fields.get("nonce"),
            "response": fields.get("response"),
            "uri": fields.get("uri"),
            "algorithm": fields.get("algorithm", "MD5"),
        }
        break

    if body and b"m=" in body[:2000]:
        message.sdp = parse_sdp(body)

    return message


def parse_sdp(body: bytes) -> dict:
    """
    Parse the session description that negotiates the media stream.

    The connection address and port say where the audio will flow, which
    is what links a signalling exchange to the RTP that follows. The
    presence of an encryption key attribute says whether that audio is
    protected.
    """
    result: dict = {
        "address": None,
        "media": [],
        "encrypted": False,
        "session_name": None,
        "origin": None,
    }

    for raw_line in body.decode("utf-8", "replace").split("\n"):
        line = raw_line.strip()
        if len(line) < 2 or line[1] != "=":
            continue
        kind, value = line[0], line[2:]

        if kind == "c":
            parts = value.split()
            if len(parts) >= 3:
                result["address"] = parts[2].split("/")[0]
        elif kind == "s":
            result["session_name"] = value
        elif kind == "o":
            result["origin"] = value
        elif kind == "m":
            parts = value.split()
            if len(parts) >= 4:
                result["media"].append(
                    {
                        "type": parts[0],
                        "port": int(parts[1]) if parts[1].isdigit() else None,
                        "protocol": parts[2],
                        "formats": parts[3:],
                        # SAVP means SRTP: the media is encrypted.
                        "encrypted": "SAVP" in parts[2].upper(),
                    }
                )
                if "SAVP" in parts[2].upper():
                    result["encrypted"] = True
        elif kind == "a" and value.startswith("crypto:"):
            result["encrypted"] = True

    return result


# ---------------------------------------------------------------------------
# RTP
# ---------------------------------------------------------------------------

def parse_rtp(payload: bytes) -> dict | None:
    """
    Parse an RTP header.

    RTP has no port convention and no magic bytes, so identification is
    structural: version 2, a sane payload type, and a header long enough
    for the CSRC count it declares. That is enough to be right nearly
    always and to fail safely when it is not.
    """
    if len(payload) < 12:
        return None

    first = payload[0]
    if (first >> 6) != 2:  # version must be 2
        return None

    csrc_count = first & 0x0F
    header_len = 12 + csrc_count * 4
    if len(payload) < header_len:
        return None

    second = payload[1]
    marker = bool(second & 0x80)
    payload_type = second & 0x7F

    # Payload types 72-76 are RTCP sender/receiver reports sharing the
    # port range; they are not media.
    if 72 <= payload_type <= 76:
        return None

    sequence, timestamp, ssrc = struct.unpack("!HII", payload[2:12])

    return {
        "payload_type": payload_type,
        "codec": RTP_PAYLOAD_TYPES.get(payload_type,
                                       f"dynamic {payload_type}"),
        "sequence": sequence,
        "timestamp": timestamp,
        "ssrc": ssrc,
        "marker": marker,
        "payload_size": len(payload) - header_len,
        "dynamic": payload_type >= 96,
    }


def parse_rtcp(payload: bytes) -> dict | None:
    """Parse an RTCP control packet, which carries call quality reports."""
    if len(payload) < 8:
        return None
    if (payload[0] >> 6) != 2:
        return None
    packet_type = payload[1]
    if not (200 <= packet_type <= 207):
        return None

    names = {
        200: "Sender report", 201: "Receiver report", 202: "Source description",
        203: "Goodbye", 204: "Application", 205: "Transport feedback",
        206: "Payload feedback", 207: "Extended report",
    }

    result = {"type": packet_type, "type_name": names.get(packet_type)}

    if packet_type in (200, 201) and len(payload) >= 28:
        # Report blocks carry loss and jitter, the numbers that say whether
        # the call was actually usable.
        offset = 28 if packet_type == 200 else 8
        if len(payload) >= offset + 24:
            fraction_lost = payload[offset + 4]
            cumulative_lost = int.from_bytes(
                payload[offset + 5:offset + 8], "big"
            )
            jitter = struct.unpack("!I", payload[offset + 12:offset + 16])[0]
            result.update(
                {
                    "fraction_lost_percent": round(fraction_lost / 255 * 100, 1),
                    "packets_lost": cumulative_lost,
                    "jitter": jitter,
                }
            )

    return result


def is_probable_rtp(payload: bytes, src_port: int, dst_port: int) -> bool:
    """
    Decide whether a UDP payload is RTP.

    Media usually runs on even ports in the ephemeral range with RTCP on
    the odd port above, so the port is a supporting signal rather than the
    test. The structural check does the real work.
    """
    if len(payload) < 12:
        return False
    if (payload[0] >> 6) != 2:
        return False
    payload_type = payload[1] & 0x7F
    if 72 <= payload_type <= 76:
        return False
    if payload_type > 127:
        return False
    # Well-known service ports are never RTP, whatever the bytes look like.
    if src_port < 1024 or dst_port < 1024:
        return False
    return True


# ---------------------------------------------------------------------------
# Call reconstruction
# ---------------------------------------------------------------------------

@dataclass
class Call:
    """A SIP dialogue, assembled from its messages."""

    call_id: str
    caller: str | None = None
    callee: str | None = None
    caller_ip: str | None = None
    callee_ip: str | None = None
    user_agents: set = field(default_factory=set)
    started: float = 0.0
    ringing_at: float | None = None
    answered_at: float | None = None
    ended_at: float | None = None
    final_status: int | None = None
    final_reason: str | None = None
    methods: list = field(default_factory=list)
    auth_attempts: list = field(default_factory=list)
    media_endpoints: set = field(default_factory=set)
    media_encrypted: bool = False
    rtp_streams: list = field(default_factory=list)
    packets: int = 0

    @property
    def answered(self) -> bool:
        return self.answered_at is not None

    @property
    def duration(self) -> float | None:
        if self.answered_at and self.ended_at:
            return self.ended_at - self.answered_at
        return None

    @property
    def setup_time(self) -> float | None:
        if self.answered_at:
            return self.answered_at - self.started
        return None

    def to_dict(self) -> dict:
        return {
            "call_id": self.call_id,
            "caller": self.caller,
            "callee": self.callee,
            "caller_ip": self.caller_ip,
            "callee_ip": self.callee_ip,
            "user_agents": sorted(self.user_agents),
            "started": self.started,
            "answered_at": self.answered_at,
            "ended_at": self.ended_at,
            "answered": self.answered,
            "duration": round(self.duration, 1) if self.duration else None,
            "setup_time": round(self.setup_time, 2) if self.setup_time else None,
            "final_status": self.final_status,
            "final_reason": self.final_reason,
            "methods": self.methods[:30],
            "auth_attempts": self.auth_attempts,
            "media_endpoints": sorted(self.media_endpoints),
            "media_encrypted": self.media_encrypted,
            "rtp_streams": self.rtp_streams,
            "packets": self.packets,
        }
