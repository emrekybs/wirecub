"""
Additional protocol decoders.

Covers the protocols that matter for specific environments: Windows
authentication, industrial control, building automation, IoT messaging,
wireless management frames, and QUIC. Each is parsed only as far as the
detections need, which keeps them fast and hard to crash.
"""

from __future__ import annotations

import struct

from .crypto import aes_ecb_encrypt_block, aes_gcm_decrypt, hkdf_expand_label, hkdf_extract

# ---------------------------------------------------------------------------
# QUIC / HTTP3
# ---------------------------------------------------------------------------

# Published per-version salts. QUIC Initial packets are encrypted with a
# key derived from these and the connection ID in the header, so the
# handshake is readable by anyone holding the packet.
QUIC_INITIAL_SALTS = {
    0x00000001: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    0x6b3343cf: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
    0xff00001d: bytes.fromhex("afbfec289993d24c9e9786f19c6111e04390a899"),
}

QUIC_VERSIONS = {
    0x00000001: "QUIC v1",
    0x6b3343cf: "QUIC v2",
    0xff00001d: "draft-29",
    0x51303530: "Q050",
}


def _quic_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Read a QUIC variable-length integer. Returns (value, new position)."""
    if pos >= len(data):
        return 0, pos
    prefix = data[pos] >> 6
    length = 1 << prefix
    if pos + length > len(data):
        return 0, len(data)
    value = data[pos] & 0x3F
    for i in range(1, length):
        value = (value << 8) | data[pos + i]
    return value, pos + length


def decrypt_quic_initial(payload: bytes, version: int, dcid: bytes,
                         header_end: int, length_field: int,
                         pn_offset: int) -> bytes | None:
    """
    Decrypt a QUIC Initial packet payload.

    Header protection is removed first to recover the packet number, then
    the payload is opened with AES-128-GCM. Both keys come from the
    published salt and the destination connection ID.
    """
    salt = QUIC_INITIAL_SALTS.get(version)
    if salt is None:
        return None

    initial_secret = hkdf_extract(salt, dcid)
    client_secret = hkdf_expand_label(initial_secret, "client in", b"", 32)
    key = hkdf_expand_label(client_secret, "quic key", b"", 16)
    iv = hkdf_expand_label(client_secret, "quic iv", b"", 12)
    hp_key = hkdf_expand_label(client_secret, "quic hp", b"", 16)

    # The header protection sample starts four bytes past the packet number.
    sample_offset = pn_offset + 4
    if sample_offset + 16 > len(payload):
        return None
    mask = aes_ecb_encrypt_block(hp_key, payload[sample_offset:sample_offset + 16])

    first_byte = payload[0] ^ (mask[0] & 0x0F)
    pn_length = (first_byte & 0x03) + 1

    if pn_offset + pn_length > len(payload):
        return None
    pn_bytes = bytes(
        payload[pn_offset + i] ^ mask[1 + i] for i in range(pn_length)
    )
    packet_number = int.from_bytes(pn_bytes, "big")

    header = bytearray(payload[:pn_offset + pn_length])
    header[0] = first_byte
    for i in range(pn_length):
        header[pn_offset + i] = pn_bytes[i]

    body_start = pn_offset + pn_length
    body_end = pn_offset + length_field
    if body_end > len(payload) or body_end <= body_start:
        body_end = len(payload)
    body = payload[body_start:body_end]
    if len(body) < 16:
        return None

    nonce = bytes(
        a ^ b
        for a, b in zip(iv, packet_number.to_bytes(12, "big"))
    )

    return aes_gcm_decrypt(key, nonce, body, bytes(header))


def extract_crypto_frames(plaintext: bytes) -> bytes:
    """
    Pull CRYPTO frame contents out of a decrypted Initial payload.

    Frames may arrive out of order and with gaps, so each is placed at its
    declared offset rather than concatenated.
    """
    chunks: dict[int, bytes] = {}
    pos = 0
    guard = 0

    while pos < len(plaintext) and guard < 512:
        guard += 1
        frame_type = plaintext[pos]

        if frame_type == 0x00:  # PADDING, runs to the end in practice
            pos += 1
            continue
        if frame_type == 0x01:  # PING
            pos += 1
            continue
        if frame_type == 0x02 or frame_type == 0x03:  # ACK
            pos += 1
            for _ in range(4):
                _, pos = _quic_varint(plaintext, pos)
            if frame_type == 0x03:
                for _ in range(3):
                    _, pos = _quic_varint(plaintext, pos)
            continue
        if frame_type == 0x06:  # CRYPTO
            pos += 1
            offset, pos = _quic_varint(plaintext, pos)
            length, pos = _quic_varint(plaintext, pos)
            if length > len(plaintext):
                break
            chunks[offset] = plaintext[pos:pos + length]
            pos += length
            continue
        if frame_type == 0x1c:  # CONNECTION_CLOSE
            break

        # Any other frame type is not something an Initial packet needs.
        break

    if not chunks:
        return b""

    out = bytearray()
    for offset in sorted(chunks):
        if offset > len(out):
            if offset - len(out) > 65536:
                break
            out.extend(b"\x00" * (offset - len(out)))
        out[offset:offset + len(chunks[offset])] = chunks[offset]
    return bytes(out)


def parse_quic_initial(payload: bytes, decrypt: bool = True) -> dict | None:
    """
    Read a QUIC Initial packet, decrypting it to recover the server name.

    QUIC encrypts its handshake, but an Initial packet is protected with a
    key derived from a published salt and the connection ID carried in the
    clear. That defeats middlebox tampering, not observation, so the
    ClientHello inside is recoverable and the server name with it.
    """
    if len(payload) < 7:
        return None

    first = payload[0]
    if not (first & 0x80):  # short header: mid-session, no metadata
        return None

    try:
        version = struct.unpack("!I", payload[1:5])[0]
    except struct.error:
        return None

    if version == 0:
        return {"type": "version_negotiation", "version_name": "negotiation"}

    pos = 5
    if pos >= len(payload):
        return None
    dcid_len = payload[pos]
    pos += 1
    if dcid_len > 20 or pos + dcid_len > len(payload):
        return None
    dcid = payload[pos:pos + dcid_len]
    pos += dcid_len

    if pos >= len(payload):
        return None
    scid_len = payload[pos]
    pos += 1
    if scid_len > 20 or pos + scid_len > len(payload):
        return None
    scid = payload[pos:pos + scid_len]

    packet_types = {0: "initial", 1: "0-RTT", 2: "handshake", 3: "retry"}
    packet_type = packet_types.get((first & 0x30) >> 4, "unknown")

    result = {
        "version": version,
        "version_name": QUIC_VERSIONS.get(version, f"0x{version:08x}"),
        "type": packet_type,
        "dcid": dcid.hex(),
        "scid": scid.hex(),
        "is_known_version": version in QUIC_VERSIONS,
        "sni": None,
        "alpn": [],
        "ja4": None,
        "decrypted": False,
    }

    if not decrypt or packet_type != "initial":
        return result

    pos += scid_len
    # Initial packets carry a token, then the length of the protected part.
    token_length, pos = _quic_varint(payload, pos)
    pos += token_length
    if pos >= len(payload):
        return result
    length_field, pos = _quic_varint(payload, pos)

    plaintext = decrypt_quic_initial(
        payload, version, dcid, pos, length_field, pos
    )
    if not plaintext:
        return result

    result["decrypted"] = True
    crypto = extract_crypto_frames(plaintext)
    if len(crypto) < 6 or crypto[0] != 0x01:
        return result

    # Wrap the bare handshake message in a TLS record so the existing
    # ClientHello parser can read it unchanged.
    from .protocols import parse_tls_client_hello

    record = b"\x16\x03\x01" + struct.pack("!H", len(crypto)) + crypto
    hello = parse_tls_client_hello(record)
    if hello:
        result["sni"] = hello.get("sni")
        result["alpn"] = hello.get("alpn", [])
        result["ja4"] = hello.get("ja4")
        result["ja3"] = hello.get("ja3")
        result["tls_version"] = hello.get("version")

    return result


# ---------------------------------------------------------------------------
# SMB and Windows authentication
# ---------------------------------------------------------------------------

SMB2_COMMANDS = {
    0: "Negotiate", 1: "SessionSetup", 2: "Logoff", 3: "TreeConnect",
    4: "TreeDisconnect", 5: "Create", 6: "Close", 7: "Flush", 8: "Read",
    9: "Write", 10: "Lock", 11: "Ioctl", 12: "Cancel", 13: "Echo",
    14: "QueryDirectory", 15: "ChangeNotify", 16: "QueryInfo",
    17: "SetInfo", 18: "OplockBreak",
}


def parse_smb(payload: bytes) -> dict | None:
    """Identify an SMB message and pull out the parts used for detection."""
    # NetBIOS session header sits in front of SMB over port 445.
    offset = 0
    if len(payload) >= 4 and payload[0] == 0x00:
        offset = 4

    if len(payload) < offset + 8:
        return None

    header = payload[offset:offset + 4]

    if header == b"\xfeSMB":
        try:
            command = struct.unpack("<H", payload[offset + 12:offset + 14])[0]
            flags = struct.unpack("<I", payload[offset + 16:offset + 20])[0]
        except struct.error:
            return None
        return {
            "version": "SMB2/3",
            "command": SMB2_COMMANDS.get(command, str(command)),
            "command_id": command,
            "is_response": bool(flags & 0x01),
            "signed": bool(flags & 0x08),
        }

    if header == b"\xffSMB":
        return {
            "version": "SMB1",
            "command": f"0x{payload[offset + 4]:02x}",
            "command_id": payload[offset + 4],
            "is_response": bool(payload[offset + 9] & 0x80),
            "signed": False,
        }

    return None


def parse_ntlm(payload: bytes) -> dict | None:
    """
    Extract NTLM authentication details.

    NTLMSSP messages appear inside SMB, HTTP, LDAP and RPC. Message type 3
    carries the username, domain, workstation, and the response hashes
    themselves, which is what makes captured NTLM traffic crackable.
    """
    index = payload.find(b"NTLMSSP\x00")
    if index == -1 or index + 12 > len(payload):
        return None

    try:
        msg_type = struct.unpack("<I", payload[index + 8:index + 12])[0]
    except struct.error:
        return None

    result: dict = {"message_type": msg_type}

    if msg_type == 1:
        result["stage"] = "negotiate"
        return result

    if msg_type == 2:
        result["stage"] = "challenge"
        if index + 32 <= len(payload):
            result["challenge"] = payload[index + 24:index + 32].hex()
        return result

    if msg_type != 3:
        return result

    result["stage"] = "authenticate"

    def read_field(field_offset: int) -> bytes:
        try:
            length, _alloc, offset = struct.unpack(
                "<HHI", payload[index + field_offset:index + field_offset + 8]
            )
        except struct.error:
            return b""
        start = index + offset
        if start < 0 or start + length > len(payload) or length > 1024:
            return b""
        return payload[start:start + length]

    lm_response = read_field(12)
    nt_response = read_field(20)
    domain = read_field(28)
    user = read_field(36)
    workstation = read_field(44)

    # Whether the strings are UTF-16 or OEM is announced in the negotiate
    # flags. Assuming UTF-16 turns an ASCII username into interleaved
    # nulls and an empty-looking field.
    try:
        flags = struct.unpack("<I", payload[index + 60:index + 64])[0]
    except struct.error:
        flags = 1
    unicode_strings = bool(flags & 0x00000001)

    def decode(raw: bytes) -> str:
        if not raw:
            return ""
        if unicode_strings:
            return raw.decode("utf-16-le", "replace")
        return raw.decode("cp437", "replace")

    result.update(
        {
            "user": decode(user),
            "domain": decode(domain),
            "workstation": decode(workstation),
            "nt_response_length": len(nt_response),
            "lm_response_length": len(lm_response),
            # A 24-byte NT response means NTLMv1, which is trivially
            # crackable. Longer means NTLMv2.
            "ntlm_version": "NTLMv1" if len(nt_response) == 24 else "NTLMv2",
            "unicode": unicode_strings,
            "anonymous": not user,
            "nt_response": nt_response[:64].hex() if nt_response else None,
        }
    )
    return result


# Kerberos encryption types. 23 is RC4-HMAC, the type Kerberoasting
# requests because RC4 tickets can be cracked offline at speed.
KERB_ETYPES = {
    1: "DES-CBC-CRC", 3: "DES-CBC-MD5", 17: "AES128-CTS", 18: "AES256-CTS",
    23: "RC4-HMAC", 24: "RC4-HMAC-EXP",
}

KERB_MSG_TYPES = {
    10: "AS-REQ", 11: "AS-REP", 12: "TGS-REQ", 13: "TGS-REP",
    14: "AP-REQ", 15: "AP-REP", 30: "KRB-ERROR",
}


def _der_read(data: bytes, pos: int) -> tuple[int, bool, int, int] | None:
    """
    Read one DER tag-length header.

    Returns (tag, constructed, content start, content end), or None when
    the encoding is malformed. Long-form lengths are handled; indefinite
    length is rejected because DER does not permit it.
    """
    if pos + 2 > len(data):
        return None
    tag = data[pos]
    constructed = bool(tag & 0x20)
    pos += 1

    length = data[pos]
    pos += 1
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            return None
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count

    if length > len(data) or pos + length > len(data):
        return None
    return tag, constructed, pos, pos + length


def _der_walk(data: bytes, start: int, end: int, depth: int = 0):
    """Yield (tag, content start, content end, constructed) for each element."""
    pos = start
    guard = 0
    while pos < end and guard < 256:
        guard += 1
        header = _der_read(data, pos)
        if header is None:
            return
        tag, constructed, content_start, content_end = header
        yield tag, content_start, content_end, constructed
        pos = content_end


def _der_int(data: bytes, start: int, end: int) -> int | None:
    """Read a DER INTEGER value."""
    if end <= start or end - start > 8:
        return None
    return int.from_bytes(data[start:end], "big", signed=False)


def _der_find(data: bytes, start: int, end: int, path: list[int],
              depth: int = 0, budget: list[int] | None = None
              ) -> tuple[int, int] | None:
    """
    Follow a sequence of context tags down to a value.

    Kerberos nests everything under numbered context tags, so addressing a
    field by its tag path is more robust than scanning for byte patterns.
    """
    if depth > 12:
        return None
    if not path:
        return start, end
    # One budget shared by the whole search. The walk re-descends wrappers
    # with the full path, so without it a nested packet costs far more than
    # its size suggests, and port 88 is parsed on every packet.
    if budget is None:
        budget = [4000]

    wanted = path[0]
    for tag, content_start, content_end, constructed in _der_walk(data, start, end):
        budget[0] -= 1
        if budget[0] <= 0:
            return None
        # Application and context tags both carry the number in the low bits.
        if (tag & 0x1F) == wanted or tag == wanted:
            if len(path) == 1:
                return content_start, content_end
            found = _der_find(data, content_start, content_end, path[1:], depth + 1, budget)
            if found:
                return found
        # Descend through wrappers that are not themselves the target.
        if constructed and len(path) >= 1:
            found = _der_find(data, content_start, content_end, path, depth + 1, budget)
            if found:
                return found
    return None


def _der_strings(data: bytes, start: int, end: int, limit: int = 8) -> list[str]:
    """Collect GeneralString values, which is how Kerberos carries names."""
    out: list[str] = []
    for tag, content_start, content_end, constructed in _der_walk(data, start, end):
        if tag == 0x1B and content_end - content_start < 256:  # GeneralString
            out.append(data[content_start:content_end].decode("utf-8", "replace"))
        elif constructed and len(out) < limit:
            out.extend(_der_strings(data, content_start, content_end, limit))
        if len(out) >= limit:
            break
    return out[:limit]


def parse_kerberos(payload: bytes) -> dict | None:
    """
    Parse a Kerberos message using a real DER walk.

    Returns the message type, the encryption types requested, and the
    principal names involved. Encryption type is what the Kerberoasting
    detection turns on: a client asking for RC4 when the domain supports
    AES is asking for a ticket it can crack offline.
    """
    offset = 0
    # Kerberos over TCP is prefixed with a four-byte length.
    if len(payload) > 4:
        declared = int.from_bytes(payload[:4], "big")
        if 0 < declared <= len(payload) - 4 and 0x60 <= payload[4] <= 0x7F:
            offset = 4

    if len(payload) < offset + 2:
        return None

    header = _der_read(payload, offset)
    if header is None:
        return None
    app_tag, _constructed, start, end = header

    # Kerberos messages are APPLICATION tagged: 10 for AS-REQ up to 30 for
    # KRB-ERROR. Anything outside that range is not Kerberos.
    app_number = app_tag & 0x1F
    if not (0x60 <= app_tag <= 0x7F) or app_number not in KERB_MSG_TYPES:
        # Some messages wrap the real one, so look one level in.
        if not (0x60 <= app_tag <= 0x7F):
            return None

    msg_type = None
    found = _der_find(payload, start, end, [2])   # msg-type is context [2]
    if found:
        for tag, content_start, content_end, _c in _der_walk(payload, *found):
            if tag == 0x02:
                msg_type = _der_int(payload, content_start, content_end)
                break
    if msg_type is None and app_number in KERB_MSG_TYPES:
        msg_type = app_number

    # etype list lives under context [8] of the request body.
    etypes: list[int] = []
    found = _der_find(payload, start, end, [8])
    if found:
        for tag, content_start, content_end, _c in _der_walk(payload, *found):
            if tag == 0x30:  # SEQUENCE OF INTEGER
                for inner_tag, inner_start, inner_end, _ic in _der_walk(
                    payload, content_start, content_end
                ):
                    if inner_tag == 0x02:
                        value = _der_int(payload, inner_start, inner_end)
                        if value is not None:
                            etypes.append(value)
                break

    # For a reply, the ticket's own etype is under the encrypted part.
    if not etypes:
        found = _der_find(payload, start, end, [0])
        if found:
            for tag, content_start, content_end, _c in _der_walk(payload, *found):
                if tag == 0x02:
                    value = _der_int(payload, content_start, content_end)
                    if value is not None and value in KERB_ETYPES:
                        etypes.append(value)

    names = _der_strings(payload, start, end)
    realm = next((n for n in names if n.isupper() and "." in n), None)
    principals = [n for n in names if n != realm][:4]

    if msg_type is None and not etypes and not names:
        return None

    return {
        "message_type": KERB_MSG_TYPES.get(msg_type, str(msg_type)),
        "message_type_id": msg_type,
        "etypes": etypes,
        "etype_names": [KERB_ETYPES.get(e, str(e)) for e in etypes],
        "weak_etype": any(e in (1, 3, 23, 24) for e in etypes),
        "realm": realm,
        "principals": principals,
        "service": next(
            (p for p in principals if "/" in p or p.endswith("$")), None
        ),
    }


# ---------------------------------------------------------------------------
# Industrial control protocols
# ---------------------------------------------------------------------------

MODBUS_FUNCTIONS = {
    1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers",
    4: "Read Input Registers", 5: "Write Single Coil",
    6: "Write Single Register", 8: "Diagnostics", 15: "Write Multiple Coils",
    16: "Write Multiple Registers", 20: "Read File Record",
    21: "Write File Record", 22: "Mask Write Register",
    23: "Read/Write Multiple Registers", 43: "Read Device Identification",
}

# Function codes that change plant state rather than just reading it.
MODBUS_WRITE_FUNCTIONS = {5, 6, 15, 16, 21, 22, 23}


def parse_modbus(payload: bytes) -> dict | None:
    """Parse a Modbus/TCP application header."""
    if len(payload) < 8:
        return None
    try:
        txn, proto, length, unit, function = struct.unpack("!HHHBB", payload[:8])
    except struct.error:
        return None
    if proto != 0 or length < 2 or length > 300:
        return None

    is_exception = bool(function & 0x80)
    base_function = function & 0x7F

    return {
        "transaction": txn,
        "unit_id": unit,
        "function": base_function,
        "function_name": MODBUS_FUNCTIONS.get(base_function, f"Function {base_function}"),
        "is_write": base_function in MODBUS_WRITE_FUNCTIONS,
        "is_exception": is_exception,
        "exception_code": payload[8] if is_exception and len(payload) > 8 else None,
    }


S7_FUNCTIONS = {
    0x00: "CPU services", 0x04: "Read variable", 0x05: "Write variable",
    0x1A: "Request download", 0x1B: "Download block",
    0x1C: "Download ended", 0x1D: "Start upload", 0x1E: "Upload",
    0x1F: "End upload", 0x28: "PLC control", 0x29: "PLC stop",
    0xF0: "Setup communication",
}

# Operations that stop or reprogram a controller.
S7_DANGEROUS = {0x1A, 0x1B, 0x1C, 0x28, 0x29}


def parse_s7comm(payload: bytes) -> dict | None:
    """Parse S7comm inside a TPKT/COTP envelope."""
    if len(payload) < 4 or payload[0] != 0x03:
        return None
    try:
        tpkt_len = struct.unpack("!H", payload[2:4])[0]
        if tpkt_len > len(payload) + 8:
            return None
        cotp_len = payload[4]
        s7_start = 5 + cotp_len
        if s7_start + 10 > len(payload) or payload[s7_start] != 0x32:
            return None

        rosctr = payload[s7_start + 1]
        param_len = struct.unpack("!H", payload[s7_start + 6:s7_start + 8])[0]
        function = payload[s7_start + 10] if param_len else None
    except (struct.error, IndexError):
        return None

    rosctr_names = {1: "Job", 2: "Ack", 3: "Ack-Data", 7: "Userdata"}

    return {
        "rosctr": rosctr_names.get(rosctr, str(rosctr)),
        "function": function,
        "function_name": S7_FUNCTIONS.get(function, f"Function {function}"),
        "dangerous": function in S7_DANGEROUS,
    }


DNP3_FUNCTIONS = {
    0: "Confirm", 1: "Read", 2: "Write", 3: "Select", 4: "Operate",
    5: "Direct Operate", 13: "Cold Restart", 14: "Warm Restart",
    18: "Stop Application", 20: "Enable Unsolicited",
    21: "Disable Unsolicited",
}

DNP3_DANGEROUS = {3, 4, 5, 13, 14, 18}


def parse_dnp3(payload: bytes) -> dict | None:
    """Parse a DNP3 link header and application function."""
    if len(payload) < 10 or payload[:2] != b"\x05\x64":
        return None
    try:
        length = payload[2]
        control = payload[3]
        destination, source = struct.unpack("<HH", payload[4:8])
        function = payload[12] if len(payload) > 12 else None
    except (struct.error, IndexError):
        return None

    return {
        "source": source,
        "destination": destination,
        "length": length,
        "function": function,
        "function_name": DNP3_FUNCTIONS.get(function, f"Function {function}"),
        "dangerous": function in DNP3_DANGEROUS,
    }


BACNET_SERVICES = {
    0: "Acknowledge Alarm", 12: "Read Property", 14: "Read Property Multiple",
    15: "Write Property", 16: "Write Property Multiple",
    17: "Device Communication Control", 20: "Reinitialize Device",
}

BACNET_DANGEROUS = {15, 16, 17, 20}


def parse_bacnet(payload: bytes) -> dict | None:
    """Parse a BACnet/IP APDU far enough to name the service."""
    if len(payload) < 6 or payload[0] != 0x81:
        return None
    try:
        npdu_start = 4
        version = payload[npdu_start]
        if version != 0x01:
            return None
        control = payload[npdu_start + 1]
        apdu_start = npdu_start + 2
        if control & 0x20:  # destination present
            apdu_start += 3
            if apdu_start < len(payload):
                apdu_start += payload[apdu_start - 1]
        if control & 0x08:  # source present
            apdu_start += 3
            if apdu_start < len(payload):
                apdu_start += payload[apdu_start - 1]
        if control & 0x20:
            apdu_start += 1  # hop count

        if apdu_start + 2 > len(payload):
            return None
        pdu_type = payload[apdu_start] >> 4
        service = payload[apdu_start + 3] if apdu_start + 3 < len(payload) else None
    except (IndexError, struct.error):
        return None

    return {
        "pdu_type": pdu_type,
        "service": service,
        "service_name": BACNET_SERVICES.get(service, f"Service {service}"),
        "dangerous": service in BACNET_DANGEROUS,
    }


# ---------------------------------------------------------------------------
# IoT messaging
# ---------------------------------------------------------------------------

MQTT_TYPES = {
    1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK",
    8: "SUBSCRIBE", 9: "SUBACK", 10: "UNSUBSCRIBE", 12: "PINGREQ",
    14: "DISCONNECT",
}


def parse_mqtt(payload: bytes) -> dict | None:
    """Parse an MQTT control packet, including CONNECT credentials."""
    if len(payload) < 2:
        return None

    packet_type = payload[0] >> 4
    if packet_type not in MQTT_TYPES:
        return None

    # Remaining length is a variable-length integer.
    multiplier = 1
    remaining = 0
    pos = 1
    for _ in range(4):
        if pos >= len(payload):
            return None
        byte = payload[pos]
        remaining += (byte & 0x7F) * multiplier
        pos += 1
        if not (byte & 0x80):
            break
        multiplier *= 128

    result = {"type": MQTT_TYPES[packet_type], "type_id": packet_type}

    if packet_type == 1:  # CONNECT
        try:
            proto_len = struct.unpack("!H", payload[pos:pos + 2])[0]
            pos += 2 + proto_len
            level = payload[pos]
            flags = payload[pos + 1]
            pos += 4  # level, flags, keepalive

            client_len = struct.unpack("!H", payload[pos:pos + 2])[0]
            pos += 2
            client_id = payload[pos:pos + client_len].decode("utf-8", "replace")
            pos += client_len

            username = password_present = None
            if flags & 0x04:  # will flag: skip will topic and message
                for _ in range(2):
                    field_len = struct.unpack("!H", payload[pos:pos + 2])[0]
                    pos += 2 + field_len
            if flags & 0x80:  # username present
                field_len = struct.unpack("!H", payload[pos:pos + 2])[0]
                pos += 2
                username = payload[pos:pos + field_len].decode("utf-8", "replace")
                pos += field_len
            password_present = bool(flags & 0x40)

            result.update(
                {
                    "client_id": client_id,
                    "username": username,
                    "has_password": password_present,
                    "protocol_level": level,
                    "anonymous": not (flags & 0x80),
                }
            )
        except (struct.error, IndexError):
            pass

    elif packet_type == 3:  # PUBLISH
        try:
            topic_len = struct.unpack("!H", payload[pos:pos + 2])[0]
            pos += 2
            result["topic"] = payload[pos:pos + topic_len].decode("utf-8", "replace")
        except (struct.error, IndexError):
            pass

    return result


COAP_CODES = {
    1: "GET", 2: "POST", 3: "PUT", 4: "DELETE",
    69: "2.05 Content", 132: "4.04 Not Found", 133: "4.05 Method Not Allowed",
}


def parse_coap(payload: bytes) -> dict | None:
    """Parse a CoAP header."""
    if len(payload) < 4:
        return None
    version = payload[0] >> 6
    if version != 1:
        return None
    msg_type = (payload[0] >> 4) & 0x03
    code = payload[1]
    message_id = struct.unpack("!H", payload[2:4])[0]

    type_names = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}
    return {
        "type": type_names.get(msg_type, str(msg_type)),
        "code": code,
        "code_name": COAP_CODES.get(code, f"{code >> 5}.{code & 0x1F:02d}"),
        "message_id": message_id,
    }


def parse_ssdp(payload: bytes) -> dict | None:
    """Parse an SSDP discovery or notification message."""
    if len(payload) < 8:
        return None
    head = payload[:1024]
    if not (
        head.startswith(b"M-SEARCH")
        or head.startswith(b"NOTIFY")
        or head.startswith(b"HTTP/1.1")
    ):
        return None

    lines = head.split(b"\r\n")
    method = lines[0].split(b" ")[0].decode("ascii", "replace")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if sep:
            headers[name.strip().lower().decode("ascii", "replace")] = (
                value.strip().decode("utf-8", "replace")
            )

    return {
        "method": method,
        "search_target": headers.get("st") or headers.get("nt"),
        "server": headers.get("server"),
        "location": headers.get("location"),
        "usn": headers.get("usn"),
    }


# ---------------------------------------------------------------------------
# 802.11 management frames
# ---------------------------------------------------------------------------

DEAUTH_REASONS = {
    1: "Unspecified", 2: "Previous authentication no longer valid",
    3: "Station is leaving", 4: "Inactivity", 6: "Class 2 frame from "
    "non-authenticated station", 7: "Class 3 frame from non-associated "
    "station", 8: "Station is leaving the BSS", 15: "4-way handshake timeout",
}


def parse_dot11_management(data: bytes, offset: int = 0) -> dict | None:
    """
    Parse an 802.11 management frame.

    Beacons and probe responses carry the SSID and security settings, which
    is what evil twin detection compares. Deauthentication frames are the
    attack itself: they are unauthenticated by design in networks without
    management frame protection, so anyone can forge them.
    """
    if len(data) - offset < 24:
        return None

    frame_control = struct.unpack("<H", data[offset:offset + 2])[0]
    frame_type = (frame_control >> 2) & 0x03
    subtype = (frame_control >> 4) & 0x0F

    if frame_type != 0:  # management frames only
        return None

    def mac(raw: bytes) -> str:
        return ":".join(f"{b:02x}" for b in raw)

    destination = mac(data[offset + 4:offset + 10])
    source = mac(data[offset + 10:offset + 16])
    bssid = mac(data[offset + 16:offset + 22])

    subtype_names = {
        0: "AssocRequest", 1: "AssocResponse", 2: "ReassocRequest",
        4: "ProbeRequest", 5: "ProbeResponse", 8: "Beacon",
        10: "Disassociation", 11: "Authentication", 12: "Deauthentication",
    }

    result = {
        "subtype": subtype_names.get(subtype, str(subtype)),
        "subtype_id": subtype,
        "source": source,
        "destination": destination,
        "bssid": bssid,
        "broadcast": destination == "ff:ff:ff:ff:ff:ff",
    }

    if subtype in (10, 12):  # disassociation or deauthentication
        body = offset + 24
        if body + 2 <= len(data):
            reason = struct.unpack("<H", data[body:body + 2])[0]
            result["reason_code"] = reason
            result["reason"] = DEAUTH_REASONS.get(reason, f"Reason {reason}")
        return result

    if subtype in (5, 8):  # probe response or beacon
        pos = offset + 24 + 12  # fixed parameters
        privacy = False
        rsn = False
        wpa = False
        ssid = None

        while pos + 2 <= len(data):
            element_id = data[pos]
            element_len = data[pos + 1]
            value = data[pos + 2:pos + 2 + element_len]
            pos += 2 + element_len

            if element_id == 0:
                ssid = value.decode("utf-8", "replace") or "<hidden>"
            elif element_id == 48:
                rsn = True
            elif element_id == 221 and value[:4] == b"\x00\x50\xf2\x01":
                wpa = True

            if pos > offset + 512:
                break

        capabilities = struct.unpack("<H", data[offset + 34:offset + 36])[0] \
            if offset + 36 <= len(data) else 0
        privacy = bool(capabilities & 0x0010)

        security = "Open"
        if rsn:
            security = "WPA2/WPA3"
        elif wpa:
            security = "WPA"
        elif privacy:
            security = "WEP"

        result.update({"ssid": ssid, "security": security, "encrypted": privacy})

    return result


def is_eapol(payload: bytes) -> dict | None:
    """Identify an EAPOL key frame, the WPA four-way handshake."""
    if len(payload) < 4 or payload[0] != 0x01:
        return None
    packet_type = payload[1]
    if packet_type != 3:  # EAPOL-Key
        return None
    if len(payload) < 9:
        return None
    key_info = struct.unpack("!H", payload[5:7])[0] if len(payload) > 6 else 0

    # Message number is derived from the key info flags.
    pairwise = bool(key_info & 0x0008)
    install = bool(key_info & 0x0040)
    ack = bool(key_info & 0x0080)
    mic = bool(key_info & 0x0100)

    if pairwise and ack and not mic:
        message = 1
    elif pairwise and mic and not ack and not install:
        message = 2
    elif pairwise and install and ack and mic:
        message = 3
    elif pairwise and mic and not ack:
        message = 4
    else:
        message = 0

    return {"handshake_message": message, "pairwise": pairwise}


# ---------------------------------------------------------------------------
# SMB2 file transfer reconstruction
# ---------------------------------------------------------------------------

def iter_smb2_messages(stream: bytes, limit: int = 6000):
    """
    Walk a reassembled SMB stream, yielding one message at a time.

    SMB over TCP prefixes each message with a four-byte NetBIOS length, so
    the stream can be split exactly rather than scanned for signatures.
    """
    pos = 0
    count = 0

    while pos + 4 <= len(stream) and count < limit:
        count += 1
        if stream[pos] != 0x00:
            # Not a NetBIOS session message; resynchronise on the next
            # SMB signature rather than abandoning the stream.
            marker = stream.find(b"\xfeSMB", pos + 1)
            if marker == -1:
                return
            pos = max(0, marker - 4)
            continue

        length = int.from_bytes(stream[pos + 1:pos + 4], "big")
        if length == 0 or length > 16 * 1024 * 1024:
            return
        body = stream[pos + 4:pos + 4 + length]
        if len(body) < 64:
            return
        yield body
        pos += 4 + length


def parse_smb2_create(body: bytes) -> str | None:
    """Read the filename out of an SMB2 Create request."""
    try:
        if body[:4] != b"\xfeSMB":
            return None
        command = struct.unpack("<H", body[12:14])[0]
        flags = struct.unpack("<I", body[16:20])[0]
        if command != 5 or (flags & 0x01):  # Create request only
            return None

        header_len = 64
        name_offset = struct.unpack("<H", body[header_len + 44:header_len + 46])[0]
        name_length = struct.unpack("<H", body[header_len + 46:header_len + 48])[0]
        if not name_length or name_length > 2048:
            return None
        raw = body[name_offset:name_offset + name_length]
        return raw.decode("utf-16-le", "replace")
    except (struct.error, IndexError):
        return None


def parse_smb2_transfer(body: bytes) -> dict | None:
    """
    Read the data payload out of an SMB2 Read response or Write request.

    Returns the file offset and bytes, which is what reassembling a
    transferred file needs.
    """
    try:
        if body[:4] != b"\xfeSMB":
            return None
        command = struct.unpack("<H", body[12:14])[0]
        flags = struct.unpack("<I", body[16:20])[0]
        is_response = bool(flags & 0x01)

        header_len = 64
        if command == 8 and is_response:          # Read response
            data_offset = body[header_len + 2]
            data_length = struct.unpack(
                "<I", body[header_len + 4:header_len + 8]
            )[0]
            file_offset = None
            direction = "read"
        elif command == 9 and not is_response:    # Write request
            data_offset = struct.unpack(
                "<H", body[header_len + 2:header_len + 4]
            )[0]
            data_length = struct.unpack(
                "<I", body[header_len + 4:header_len + 8]
            )[0]
            file_offset = struct.unpack(
                "<Q", body[header_len + 8:header_len + 16]
            )[0]
            direction = "write"
        else:
            return None

        if not data_length or data_length > 16 * 1024 * 1024:
            return None
        data = body[data_offset:data_offset + data_length]
        if not data:
            return None

        return {
            "direction": direction,
            "offset": file_offset,
            "data": data,
        }
    except (struct.error, IndexError):
        return None
