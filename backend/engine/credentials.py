"""
Credential extraction.

Pulls usernames, passwords and authentication hashes out of protocols
that carry them without encryption, or with encoding that is not
encryption. Base64 is not a protection mechanism; anyone holding the
packets holds the credential.

Everything here works on reassembled streams rather than single packets,
because most of these exchanges span several round trips and Telnet in
character mode sends one keystroke per packet.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

MAX_CREDENTIALS = 500


@dataclass
class Credential:
    """One recovered authentication attempt."""

    protocol: str
    method: str
    username: str | None
    secret: str | None            # password, hash, or encoded blob
    secret_kind: str              # password | hash | token | challenge-response
    client: str
    server: str
    server_port: int
    packet: int = 0
    ts: float = 0.0
    realm: str | None = None
    crackable: bool = True
    note: str = ""
    raw: str | None = None

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "method": self.method,
            "username": self.username,
            "secret": self.secret,
            "secret_kind": self.secret_kind,
            "client": self.client,
            "server": self.server,
            "server_port": self.server_port,
            "packet": self.packet,
            "ts": self.ts,
            "realm": self.realm,
            "crackable": self.crackable,
            "note": self.note,
        }


def _b64(data: str) -> bytes | None:
    """Decode base64, tolerating missing padding."""
    try:
        cleaned = data.strip()
        padding = (-len(cleaned)) % 4
        return base64.b64decode(cleaned + "=" * padding, validate=False)
    except (binascii.Error, ValueError):
        return None


def _text(data: bytes, limit: int = 200) -> str:
    return data[:limit].decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Telnet
# ---------------------------------------------------------------------------

# Telnet interleaves option negotiation with the data stream. IAC is 255;
# the three-byte commands WILL/WONT/DO/DONT are 251-254, and subnegotiation
# runs from SB (250) to SE (240).
def strip_telnet_control(data: bytes) -> bytes:
    """Remove Telnet option negotiation, leaving the typed characters."""
    out = bytearray()
    i = 0
    while i < len(data):
        byte = data[i]
        if byte == 255:  # IAC
            if i + 1 >= len(data):
                break
            command = data[i + 1]
            if command == 255:      # escaped literal 0xFF
                out.append(255)
                i += 2
            elif 251 <= command <= 254:
                i += 3
            elif command == 250:    # subnegotiation, runs until IAC SE
                end = data.find(b"\xff\xf0", i)
                i = end + 2 if end != -1 else len(data)
            else:
                i += 2
        else:
            out.append(byte)
            i += 1
    return bytes(out)


def parse_telnet(to_server: bytes, to_client: bytes) -> list[tuple[str, str]]:
    """
    Recover a Telnet login.

    Character mode sends one keystroke per packet and the server echoes it
    back, so the client stream is the typed text. Line mode sends whole
    lines. Both end up as readable text once negotiation is stripped, and
    the password is whatever follows the server's password prompt.
    """
    typed = strip_telnet_control(to_server)
    echoed = strip_telnet_control(to_client)

    # Backspace and delete need applying, or a corrected typo lands in the
    # extracted credential.
    def apply_edits(raw: bytes) -> str:
        buffer: list[str] = []
        for byte in raw:
            if byte in (8, 127):
                if buffer:
                    buffer.pop()
            elif byte in (10, 13, 0):
                buffer.append("\n")
            elif 32 <= byte < 127:
                buffer.append(chr(byte))
        return "".join(buffer)

    client_text = apply_edits(typed)
    server_text = apply_edits(echoed)

    lines = [line.strip() for line in client_text.split("\n") if line.strip()]
    found: list[tuple[str, str]] = []

    # The server's prompts tell us which typed line is which.
    lowered = server_text.lower()
    has_login_prompt = any(
        marker in lowered for marker in ("login:", "username:", "user:")
    )
    has_password_prompt = "password:" in lowered

    if has_login_prompt and has_password_prompt and len(lines) >= 2:
        found.append((lines[0], lines[1]))
    elif has_password_prompt and lines:
        # Password prompt but no login prompt seen: the password is the line
        # typed after the prompt appeared.
        found.append((None, lines[0] if len(lines) == 1 else lines[1]))

    return found


# ---------------------------------------------------------------------------
# Line-based protocols: FTP, POP3, IMAP, SMTP
# ---------------------------------------------------------------------------

def parse_ftp(to_server: bytes, to_client: bytes) -> list[dict]:
    """FTP sends USER and PASS as plain commands."""
    results = []
    user = None
    for line in to_server.split(b"\r\n"):
        upper = line[:5].upper()
        if upper.startswith(b"USER "):
            user = _text(line[5:]).strip()
        elif upper.startswith(b"PASS "):
            results.append(
                {
                    "method": "USER/PASS",
                    "username": user,
                    "secret": _text(line[5:]).strip(),
                    "secret_kind": "password",
                }
            )
            user = None
    return results


def parse_pop3(to_server: bytes, to_client: bytes) -> list[dict]:
    """POP3 USER/PASS, and APOP which sends a digest instead."""
    results = []
    user = None
    for line in to_server.split(b"\r\n"):
        upper = line[:5].upper()
        if upper.startswith(b"USER "):
            user = _text(line[5:]).strip()
        elif upper.startswith(b"PASS "):
            results.append(
                {
                    "method": "USER/PASS",
                    "username": user,
                    "secret": _text(line[5:]).strip(),
                    "secret_kind": "password",
                }
            )
            user = None
        elif upper.startswith(b"APOP "):
            parts = _text(line[5:]).strip().split()
            if len(parts) == 2:
                results.append(
                    {
                        "method": "APOP",
                        "username": parts[0],
                        "secret": parts[1],
                        "secret_kind": "hash",
                        "note": "MD5 digest of a shared timestamp and the "
                                "password. Crackable offline.",
                    }
                )
        elif upper.startswith(b"AUTH "):
            results.extend(_parse_sasl(to_server, to_client, "POP3"))
            break
    return results


IMAP_LOGIN = re.compile(rb'^\S+\s+LOGIN\s+(.+)$', re.IGNORECASE)
IMAP_AUTH = re.compile(rb'^\S+\s+AUTHENTICATE\s+(\S+)', re.IGNORECASE)


def parse_imap(to_server: bytes, to_client: bytes) -> list[dict]:
    """
    IMAP LOGIN in the clear, and the AUTHENTICATE mechanisms.

    Covers PLAIN and LOGIN (base64, which is not encryption), CRAM-MD5 and
    DIGEST-MD5 (challenge-response, crackable offline), and vendor
    mechanisms such as XYMPKI.
    """
    results = []
    lines = to_server.split(b"\r\n")

    for index, line in enumerate(lines):
        match = IMAP_LOGIN.match(line.strip())
        if match:
            argument = match.group(1).strip()
            # Arguments may be quoted, and a password can contain spaces.
            parts = _split_quoted(_text(argument, 400))
            if len(parts) >= 2:
                results.append(
                    {
                        "method": "LOGIN",
                        "username": parts[0],
                        "secret": parts[1],
                        "secret_kind": "password",
                    }
                )
            continue

        match = IMAP_AUTH.match(line.strip())
        if match:
            mechanism = match.group(1).decode("ascii", "replace").upper()
            payload_lines = [
                l.strip() for l in lines[index + 1:index + 4] if l.strip()
            ]
            results.extend(
                _decode_sasl(mechanism, payload_lines, to_client, "IMAP")
            )

    return results


SMTP_AUTH = re.compile(rb'^AUTH\s+(\S+)\s*(\S*)', re.IGNORECASE)


def parse_smtp(to_server: bytes, to_client: bytes) -> list[dict]:
    """SMTP AUTH PLAIN, LOGIN and CRAM-MD5."""
    results = []
    lines = to_server.split(b"\r\n")

    for index, line in enumerate(lines):
        match = SMTP_AUTH.match(line.strip())
        if not match:
            continue
        mechanism = match.group(1).decode("ascii", "replace").upper()
        inline = match.group(2)

        payload_lines = []
        if inline:
            payload_lines.append(inline)
        payload_lines.extend(
            l.strip() for l in lines[index + 1:index + 4] if l.strip()
        )
        results.extend(
            _decode_sasl(mechanism, payload_lines, to_client, "SMTP")
        )

    return results


def _parse_sasl(to_server: bytes, to_client: bytes, protocol: str) -> list[dict]:
    """Generic SASL handling for protocols that share the mechanism set."""
    results = []
    lines = to_server.split(b"\r\n")
    for index, line in enumerate(lines):
        upper = line[:5].upper()
        if not upper.startswith(b"AUTH "):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        mechanism = parts[1].decode("ascii", "replace").upper()
        payload_lines = [parts[2]] if len(parts) > 2 else []
        payload_lines.extend(
            l.strip() for l in lines[index + 1:index + 4] if l.strip()
        )
        results.extend(_decode_sasl(mechanism, payload_lines, to_client, protocol))
    return results


def _decode_sasl(mechanism: str, payload_lines: list[bytes],
                 to_client: bytes, protocol: str) -> list[dict]:
    """
    Decode one SASL exchange.

    PLAIN and LOGIN carry the credential itself, merely base64 encoded.
    CRAM-MD5 and DIGEST-MD5 carry a response computed over a server
    challenge, which does not reveal the password directly but can be
    attacked offline at the attacker's leisure.
    """
    results: list[dict] = []
    blobs = [b for b in payload_lines if b and b not in (b"+", b"*")]

    if mechanism == "PLAIN":
        for blob in blobs:
            decoded = _b64(_text(blob, 600))
            if not decoded:
                continue
            # PLAIN is authzid NUL authcid NUL password
            parts = decoded.split(b"\x00")
            if len(parts) >= 3:
                results.append(
                    {
                        "method": "AUTH PLAIN",
                        "username": _text(parts[1], 120),
                        "secret": _text(parts[2], 120),
                        "secret_kind": "password",
                        "note": "Base64 encoded, which is not encryption.",
                    }
                )
                break

    elif mechanism == "LOGIN":
        # LOGIN sends the username and password as separate base64 blobs,
        # each after a server prompt.
        decoded_blobs = []
        for blob in blobs:
            decoded = _b64(_text(blob, 400))
            if decoded and all(32 <= c < 127 for c in decoded[:64]) and decoded:
                decoded_blobs.append(_text(decoded, 120))
        if decoded_blobs:
            results.append(
                {
                    "method": "AUTH LOGIN",
                    "username": decoded_blobs[0] if decoded_blobs else None,
                    "secret": decoded_blobs[1] if len(decoded_blobs) > 1 else None,
                    "secret_kind": "password",
                    "note": "Base64 encoded, which is not encryption.",
                }
            )

    elif mechanism in ("CRAM-MD5", "DIGEST-MD5"):
        challenge = None
        for line in to_client.split(b"\r\n"):
            stripped = line.strip()
            if stripped.startswith(b"+ ") or stripped.startswith(b"334 "):
                candidate = _b64(_text(stripped.split(b" ", 1)[-1], 400))
                if candidate:
                    challenge = _text(candidate, 200)
                    break
        for blob in blobs:
            decoded = _b64(_text(blob, 600))
            if not decoded:
                continue
            text = _text(decoded, 400)
            username = None
            if mechanism == "CRAM-MD5":
                # response is "username<space>hexdigest"
                parts = text.split(" ")
                username = parts[0] if parts else None
            else:
                username = _first_group(r'username="?([^",]+)"?', text)
            results.append(
                {
                    "method": f"AUTH {mechanism}",
                    "username": username,
                    "secret": text,
                    "secret_kind": "challenge-response",
                    "realm": _first_group(r'realm="?([^",]+)"?', text),
                    "note": f"Response to a server challenge. The password is "
                            f"not sent, but this can be attacked offline."
                            + (f" Challenge: {challenge}" if challenge else ""),
                }
            )
            break

    elif mechanism in ("XOAUTH2", "OAUTHBEARER"):
        for blob in blobs:
            decoded = _b64(_text(blob, 800))
            if not decoded:
                continue
            text = _text(decoded, 400)
            user_match = re.search(r'user=([^\x01]+)', text)
            results.append(
                {
                    "method": f"AUTH {mechanism}",
                    "username": user_match.group(1) if user_match else None,
                    "secret": text[:160],
                    "secret_kind": "token",
                    "note": "Bearer token. Anyone holding it can access the "
                            "mailbox until it expires.",
                }
            )
            break

    else:
        # Vendor and certificate mechanisms such as XYMPKI. Record that
        # authentication happened even when the payload is opaque.
        if blobs:
            results.append(
                {
                    "method": f"AUTH {mechanism}",
                    "username": None,
                    "secret": _text(blobs[0], 120),
                    "secret_kind": "token",
                    "crackable": False,
                    "note": f"{mechanism} is a non-standard mechanism; the "
                            "payload is recorded but not decoded.",
                }
            )

    return results


def _first_group(pattern: str, text: str) -> str | None:
    """Return the first capture group, or None. Never raises on no match."""
    match = re.search(pattern, text)
    return match.group(1) if match else None


def _split_quoted(text: str) -> list[str]:
    """Split on spaces, honouring double quotes and braces."""
    parts: list[str] = []
    current = ""
    in_quotes = False
    for char in text:
        if char == '"':
            in_quotes = not in_quotes
        elif char == " " and not in_quotes:
            if current:
                parts.append(current)
                current = ""
        else:
            current += char
    if current:
        parts.append(current)
    return parts


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

AUTH_HEADER = re.compile(rb'^(?:Proxy-)?Authorization:\s*(\S+)\s*(.*)$',
                         re.IGNORECASE | re.MULTILINE)
WWW_AUTH = re.compile(rb'^(?:Proxy-)?WWW-Authenticate:\s*(\S+)\s*(.*)$',
                      re.IGNORECASE | re.MULTILINE)


def parse_http_auth(to_server: bytes, to_client: bytes) -> list[dict]:
    """
    Recover HTTP authentication.

    Basic is the credential in base64. Digest is a challenge-response that
    can be cracked offline. NTLM and Negotiate carry the Windows
    authentication exchange, which is handled by the NTLM decoder.
    """
    results = []
    seen: set[tuple] = set()

    for match in AUTH_HEADER.finditer(to_server[:120_000]):
        scheme = match.group(1).decode("ascii", "replace")
        value = match.group(2).strip()
        lowered = scheme.lower()

        signature = (lowered, value[:400])
        if signature in seen:
            continue
        seen.add(signature)

        if lowered == "basic":
            decoded = _b64(_text(value, 400))
            if decoded and b":" in decoded:
                username, _, password = decoded.partition(b":")
                results.append(
                    {
                        "method": "HTTP Basic",
                        "username": _text(username, 120),
                        "secret": _text(password, 120),
                        "secret_kind": "password",
                        "note": "Base64 encoded, which is not encryption.",
                    }
                )

        elif lowered == "digest":
            text = _text(value, 700)
            fields = dict(re.findall(r'(\w+)="?([^",]+)"?', text))
            results.append(
                {
                    "method": "HTTP Digest",
                    "username": fields.get("username"),
                    "secret": fields.get("response"),
                    "secret_kind": "challenge-response",
                    "realm": fields.get("realm"),
                    "note": "MD5 response over a server nonce. The password "
                            "is not sent, but the response can be attacked "
                            f"offline. Nonce: {fields.get('nonce', 'unknown')}",
                }
            )

        elif lowered in ("ntlm", "negotiate"):
            decoded = _b64(_text(value, 3000))
            if not decoded:
                continue
            from .protocols_ext import parse_ntlm

            if decoded[:7] == b"NTLMSSP":
                ntlm = parse_ntlm(decoded)
            else:
                # Negotiate wraps NTLM in a GSSAPI/SPNEGO token; the NTLMSSP
                # signature is still findable inside it.
                ntlm = parse_ntlm(decoded)

            if not ntlm:
                results.append(
                    {
                        "method": f"HTTP {scheme} (Kerberos)",
                        "username": None,
                        "secret": None,
                        "secret_kind": "token",
                        "crackable": False,
                        "note": "GSSAPI token carrying Kerberos rather than "
                                "NTLM. No password material is exposed.",
                    }
                )
                continue

            if ntlm.get("stage") == "authenticate":
                domain = ntlm.get("domain") or ""
                user = ntlm.get("user") or ""
                results.append(
                    {
                        "method": f"HTTP {scheme} ({ntlm.get('ntlm_version')})",
                        "username": f"{domain}\\{user}".strip("\\"),
                        "secret": ntlm.get("nt_response"),
                        "secret_kind": "hash",
                        "note": f"Workstation {ntlm.get('workstation')}. "
                        + ("NTLMv1 responses can be reversed to the password "
                           "hash with precomputed tables."
                           if ntlm.get("ntlm_version") == "NTLMv1"
                           else "NTLMv2 response, crackable offline against a "
                                "wordlist."),
                    }
                )

    return results


def parse_smb_ntlm(to_server: bytes, to_client: bytes) -> list[dict]:
    """
    Recover NTLM authentication carried inside SMB.

    Both the older SessionSetupAndX form and NTLMSSP inside SMB2 put the
    same authenticate message on the wire, so one scan over the stream
    covers both. The server challenge is taken from the reverse direction
    where present, since a response is only crackable with the challenge
    it was computed against.
    """
    from .protocols_ext import parse_ntlm

    results: list[dict] = []

    challenge = None
    position = 0
    while True:
        index = to_client.find(b"NTLMSSP\x00", position)
        if index == -1:
            break
        parsed = parse_ntlm(to_client[index:index + 2048])
        position = index + 8
        if parsed and parsed.get("stage") == "challenge":
            challenge = parsed.get("challenge")
            break

    seen: set[tuple] = set()
    position = 0
    while True:
        index = to_server.find(b"NTLMSSP\x00", position)
        if index == -1:
            break
        position = index + 8
        parsed = parse_ntlm(to_server[index:index + 4096])
        if not parsed or parsed.get("stage") != "authenticate":
            continue

        domain = parsed.get("domain") or ""
        user = parsed.get("user") or ""
        # A null session authenticates with no username at all. That is not
        # a credential to crack, but it is worth surfacing: it means the
        # server accepted an unauthenticated session.
        anonymous = not user
        account = f"{domain}\\{user}".strip("\\") if user else "(null session)"
        key = (account, parsed.get("nt_response"))
        if key in seen:
            continue
        seen.add(key)

        version = parsed.get("ntlm_version")
        note = f"Workstation {parsed.get('workstation') or 'unknown'}."
        if challenge:
            note += f" Server challenge {challenge}."
        if anonymous:
            note += (
                " No username was supplied, so this is a null session: the "
                "server was asked to accept an unauthenticated connection."
            )
        note += (
            " NTLMv1 responses can be reversed to the password hash using "
            "precomputed tables rather than guessed."
            if version == "NTLMv1"
            else " NTLMv2 response: crackable offline against a wordlist, "
                 "and relayable to another server if SMB signing is off."
        )

        results.append(
            {
                "method": f"SMB NTLMSSP ({version})",
                "username": account,
                "secret": parsed.get("nt_response"),
                "secret_kind": "hash",
                "realm": domain or None,
                "crackable": not anonymous,
                "note": note,
            }
        )

    return results


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

# Which parser applies to which port. Ports are the only reliable signal
# before the payload is read, and these protocols are all well-known-port.
PORT_PARSERS = {
    21: ("FTP", parse_ftp),
    23: ("Telnet", None),          # handled separately, needs both directions
    25: ("SMTP", parse_smtp),
    110: ("POP3", parse_pop3),
    143: ("IMAP", parse_imap),
    465: ("SMTP", parse_smtp),
    587: ("SMTP", parse_smtp),
    993: ("IMAP", parse_imap),
    995: ("POP3", parse_pop3),
    2525: ("SMTP", parse_smtp),
}

HTTP_PORTS = {80, 8000, 8080, 8081, 8888, 3128}

# Ports worth running credential parsers over. Gating on this keeps the
# work off the other several hundred thousand streams in a large capture.
AUTH_PORTS = set(PORT_PARSERS) | HTTP_PORTS | {23, 139, 445}


def extract_from_stream(stream, to_server: bytes, to_client: bytes) -> list[Credential]:
    """Run whichever credential parsers apply to this conversation."""
    port = stream.server_port
    found: list[Credential] = []

    def build(protocol: str, entry: dict) -> Credential:
        return Credential(
            protocol=protocol,
            method=entry.get("method", "unknown"),
            username=entry.get("username"),
            secret=entry.get("secret"),
            secret_kind=entry.get("secret_kind", "password"),
            client=stream.client,
            server=stream.server,
            server_port=port,
            packet=stream.first_packet,
            ts=stream.first_seen,
            realm=entry.get("realm"),
            crackable=entry.get("crackable", True),
            note=entry.get("note", ""),
        )

    if port in (445, 139):
        for entry in parse_smb_ntlm(to_server, to_client):
            found.append(build("SMB", entry))
        return found

    if port == 23 or stream.service == "Telnet":
        for username, password in parse_telnet(to_server, to_client):
            found.append(
                build("Telnet", {
                    "method": "Login",
                    "username": username,
                    "secret": password,
                    "secret_kind": "password",
                    "note": "Telnet has no encryption at all. Everything "
                            "typed, including the password, crossed the "
                            "network as readable text.",
                })
            )
        return found

    if port in PORT_PARSERS:
        protocol, parser = PORT_PARSERS[port]
        if parser:
            for entry in parser(to_server, to_client):
                found.append(build(protocol, entry))
        return found

    if port in HTTP_PORTS or to_server[:5] in (b"GET /", b"POST ", b"HEAD "):
        for entry in parse_http_auth(to_server, to_client):
            found.append(build("HTTP", entry))

    return found
