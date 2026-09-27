"""
TCP stream reassembly.

Rebuilds byte streams from segments so anything larger than one packet —
a downloaded file, a long HTTP response, an SMB transfer — can be read as
a whole. Without this, WireCub only ever sees the first packet of a
transfer and can say what was requested but not what actually arrived.

Reassembly is bounded on every axis: how many streams are tracked, how
much each may hold, and how long a gap is tolerated before a stream is
abandoned. Captures from busy networks contain hundreds of thousands of
concurrent connections, and unbounded reassembly on one of those is how
an analysis tool runs a host out of memory.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Bounds. Deep scan raises the stream count; the per-stream ceiling stays
# fixed because a single stream large enough to exceed it is already more
# than any detection needs to reach a verdict.
MAX_STREAMS = 3_000
MAX_STREAM_BYTES = 6 * 1024 * 1024
MAX_SEGMENTS_PER_STREAM = 4_000
MAX_HOLE_BYTES = 512 * 1024      # give up if this much is missing


@dataclass(slots=True)
class Direction:
    """One half of a conversation: bytes flowing one way."""

    segments: dict[int, bytes] = field(default_factory=dict)
    base_seq: int | None = None
    highest: int = 0
    bytes_seen: int = 0
    packets: int = 0
    overlaps: int = 0
    retransmits: int = 0
    finished: bool = False
    overflowed: bool = False

    def add(self, seq: int, payload: bytes) -> None:
        if not payload or self.overflowed:
            return
        if self.base_seq is None:
            self.base_seq = seq

        # Normalise into an offset from the first sequence number seen, so
        # a wrapped 32-bit counter does not reorder the stream.
        offset = (seq - self.base_seq) & 0xFFFFFFFF
        if offset > 0x7FFFFFFF:          # sequence before the base: ignore
            return

        if offset in self.segments:
            if self.segments[offset] == payload:
                self.retransmits += 1
            else:
                self.overlaps += 1
            return

        if len(self.segments) >= MAX_SEGMENTS_PER_STREAM:
            self.overflowed = True
            return
        if self.bytes_seen + len(payload) > MAX_STREAM_BYTES:
            self.overflowed = True
            return

        self.segments[offset] = payload
        self.bytes_seen += len(payload)
        self.packets += 1
        self.highest = max(self.highest, offset + len(payload))

    def assemble(self) -> tuple[bytes, int]:
        """
        Join segments in sequence order.

        Returns the bytes and how many were missing. Holes are filled with
        nulls rather than silently closed up, because closing a gap would
        splice unrelated bytes together and produce content that was never
        on the wire.
        """
        if not self.segments:
            return b"", 0

        out = bytearray()
        missing = 0
        cursor = 0

        for offset in sorted(self.segments):
            payload = self.segments[offset]

            if offset < cursor:
                # Overlapping retransmission: keep what arrived first.
                skip = cursor - offset
                if skip >= len(payload):
                    continue
                payload = payload[skip:]
                offset = cursor

            gap = offset - cursor
            if gap > 0:
                # Each hole is bounded, and so is the sum of them: sparse
                # segments spaced just under the hole limit would otherwise
                # rebuild into gigabytes of zero fill from a few kilobytes.
                if gap > MAX_HOLE_BYTES or len(out) + gap > MAX_STREAM_BYTES:
                    break
                out.extend(b"\x00" * gap)
                missing += gap

            if len(out) + len(payload) > MAX_STREAM_BYTES:
                payload = payload[:MAX_STREAM_BYTES - len(out)]
                out.extend(payload)
                break
            out.extend(payload)
            cursor = offset + len(payload)

        return bytes(out), missing


@dataclass(slots=True)
class Stream:
    """A full TCP conversation, both directions."""

    key: tuple
    client: str
    server: str
    client_port: int
    server_port: int
    service: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    first_packet: int = 0
    to_server: Direction = field(default_factory=Direction)
    to_client: Direction = field(default_factory=Direction)
    reset: bool = False
    closed: bool = False

    @property
    def bytes_total(self) -> int:
        return self.to_server.bytes_seen + self.to_client.bytes_seen

    @property
    def complete(self) -> bool:
        return not (self.to_server.overflowed or self.to_client.overflowed)


class Reassembler:
    """Tracks TCP streams across a capture."""

    def __init__(self, max_streams: int = MAX_STREAMS):
        self.streams: dict[tuple, Stream] = {}
        self.max_streams = max_streams
        self.dropped = 0

    def add(self, decoded, ts: float, packet_number: int, service: str = "") -> None:
        """Feed one decoded TCP packet in."""
        if decoded.protocol != 6 or decoded.src_port is None:
            return
        payload = decoded.payload
        flags = decoded.tcp_flags or 0

        # A pure ACK with no payload carries nothing to reassemble, but a
        # SYN still matters: it establishes which side is the client.
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)

        if not payload and not (syn and not ack):
            if flags & 0x04:  # RST
                key = self._key(decoded)
                stream = self.streams.get(key)
                if stream:
                    stream.reset = True
                    stream.last_seen = ts
            return

        key = self._key(decoded)
        stream = self.streams.get(key)

        if stream is None:
            if len(self.streams) >= self.max_streams:
                self.dropped += 1
                return
            # Whoever sent the bare SYN is the client. Failing that, the
            # higher port number is the client by convention.
            if syn and not ack:
                client, server = decoded.src_ip, decoded.dst_ip
                cport, sport = decoded.src_port, decoded.dst_port
            elif (decoded.src_port or 0) > (decoded.dst_port or 0):
                client, server = decoded.src_ip, decoded.dst_ip
                cport, sport = decoded.src_port, decoded.dst_port
            else:
                client, server = decoded.dst_ip, decoded.src_ip
                cport, sport = decoded.dst_port, decoded.src_port

            stream = Stream(
                key=key,
                client=client,
                server=server,
                client_port=cport or 0,
                server_port=sport or 0,
                service=service,
                first_seen=ts,
                first_packet=packet_number,
            )
            self.streams[key] = stream

        stream.last_seen = ts

        if flags & 0x04:
            stream.reset = True
        if flags & 0x01:
            stream.closed = True

        if payload:
            seq = decoded.tcp_seq or 0
            if (decoded.src_ip, decoded.src_port) == (stream.client,
                                                      stream.client_port):
                stream.to_server.add(seq, payload)
            else:
                stream.to_client.add(seq, payload)

    @staticmethod
    def _key(decoded) -> tuple:
        a = (decoded.src_ip, decoded.src_port)
        b = (decoded.dst_ip, decoded.dst_port)
        return (a, b) if a <= b else (b, a)

    def finish(self) -> list[Stream]:
        """Streams worth inspecting, largest first."""
        return sorted(
            (s for s in self.streams.values() if s.bytes_total > 0),
            key=lambda s: -s.bytes_total,
        )


def split_http_messages(data: bytes, limit: int = 400) -> list[bytes]:
    """
    Split a reassembled stream into individual HTTP messages.

    Keep-alive connections carry many messages back to back, so getting
    the boundaries right decides whether file carving produces the actual
    files or one enormous blob. Three rules matter and all three come from
    the status line rather than the headers:

    a 1xx, 204 or 304 response has no body no matter what the headers say;
    a response to HEAD has no body; and only a response with neither
    Content-Length nor chunked encoding runs to the end of the stream.
    Treating a bodyless 304 as "no length, so take the rest" swallows
    every message after it.
    """
    messages: list[bytes] = []
    pos = 0
    guard = 0

    while pos < len(data) and guard < limit:
        guard += 1
        head_end = data.find(b"\r\n\r\n", pos)
        if head_end == -1:
            if pos < len(data):
                messages.append(data[pos:])
            break

        head = data[pos:head_end]
        body_start = head_end + 4
        lines = head.split(b"\r\n")
        start_line = lines[0] if lines else b""

        status = None
        is_response = start_line.startswith(b"HTTP/")
        if is_response:
            parts = start_line.split(b" ")
            if len(parts) > 1 and parts[1].isdigit():
                status = int(parts[1])

        length = None
        chunked = False
        connection_close = False

        for line in lines[1:]:
            name, sep, value = line.partition(b":")
            if not sep:
                continue
            lname = name.strip().lower()
            if lname == b"content-length":
                try:
                    length = int(value.strip())
                except ValueError:
                    length = None
            elif lname == b"transfer-encoding" and b"chunked" in value.lower():
                chunked = True
            elif lname == b"connection" and b"close" in value.lower():
                connection_close = True

        # Statuses that are defined to carry no body, whatever the headers.
        bodyless = is_response and (
            status is not None and (100 <= status < 200 or status in (204, 304))
        )

        if bodyless:
            messages.append(data[pos:body_start])
            pos = body_start
        elif chunked:
            body, consumed = _read_chunked(data, body_start)
            messages.append(head + b"\r\n\r\n" + body)
            pos = body_start + consumed
        elif length is not None:
            end = min(body_start + length, len(data))
            messages.append(data[pos:end])
            pos = end
        elif not is_response:
            # A request with no length declared has no body.
            messages.append(data[pos:body_start])
            pos = body_start
        else:
            # A response with no length and no chunking runs until the
            # connection closes, so it must be the last one.
            messages.append(data[pos:])
            break

        if pos <= head_end:
            break

    return messages


def _read_chunked(data: bytes, start: int) -> tuple[bytes, int]:
    """Decode a chunked transfer body. Returns (body, bytes consumed)."""
    body = bytearray()
    pos = start
    guard = 0

    while pos < len(data) and guard < 4000:
        guard += 1
        line_end = data.find(b"\r\n", pos)
        if line_end == -1:
            break
        size_field = data[pos:line_end].split(b";")[0].strip()
        try:
            size = int(size_field, 16)
        except ValueError:
            break
        pos = line_end + 2
        if size == 0:
            pos += 2  # trailing CRLF
            break
        body.extend(data[pos:pos + size])
        pos += size + 2

    return bytes(body), pos - start


# ---------------------------------------------------------------------------
# IP fragment reassembly
# ---------------------------------------------------------------------------

MAX_FRAGMENT_SETS = 4_000
MAX_FRAGMENT_BYTES = 128 * 1024      # well above a normal 64 KB datagram
FRAGMENT_TIMEOUT = 60.0              # seconds before an incomplete set is dropped


class FragmentReassembler:
    """
    Rebuilds fragmented IPv4 and IPv6 datagrams.

    Fragmentation matters for more than completeness: splitting a payload
    across fragments is a long-standing way to slip past inspection that
    only reads the first fragment. Reassembling before inspection is what
    closes that gap.
    """

    def __init__(self):
        # key -> {"fragments": {offset: bytes}, "last_seen": ts,
        #         "total": int|None, "meta": dict}
        self.pending: dict[tuple, dict] = {}
        self.completed = 0
        self.dropped = 0
        self.overlapping = 0

    def add(self, decoded, ts: float) -> bytes | None:
        """
        Feed a fragment in.

        Returns the reassembled payload when the datagram is complete,
        otherwise None.
        """
        if decoded.frag_offset is None:
            return None

        more_fragments = bool((decoded.ip_flags or 0) & 0x01)

        # An IPv4 packet with no offset and no more-fragments flag is whole.
        if decoded.ip_version == 4:
            if not decoded.frag_offset and not more_fragments:
                return None
            key = (
                decoded.src_ip, decoded.dst_ip,
                decoded.ip_id, decoded.protocol,
            )
        else:
            # IPv6 fragmentation is signalled by the extension header, which
            # the decoder records as an encapsulation entry.
            if not any("fragment" in e.lower() for e in decoded.encapsulation):
                return None
            key = (decoded.src_ip, decoded.dst_ip, decoded.protocol, "v6")

        payload = decoded.payload
        if not payload:
            return None

        entry = self.pending.get(key)
        if entry is None:
            if len(self.pending) >= MAX_FRAGMENT_SETS:
                self._expire(ts)
                if len(self.pending) >= MAX_FRAGMENT_SETS:
                    self.dropped += 1
                    return None
            entry = {
                "fragments": {},
                "last_seen": ts,
                "first_seen": ts,
                "total": None,
                "bytes": 0,
            }
            self.pending[key] = entry

        entry["last_seen"] = ts
        offset = decoded.frag_offset

        if offset in entry["fragments"]:
            self.overlapping += 1
        else:
            if entry["bytes"] + len(payload) > MAX_FRAGMENT_BYTES:
                self.pending.pop(key, None)
                self.dropped += 1
                return None
            entry["fragments"][offset] = payload
            entry["bytes"] += len(payload)

        # The final fragment is the one that tells us how long the whole
        # datagram is: everything before it has the more-fragments bit set.
        if not more_fragments:
            entry["total"] = offset + len(payload)

        if entry["total"] is None:
            return None

        # Complete only when the fragments cover the whole length with no gaps.
        cursor = 0
        for frag_offset in sorted(entry["fragments"]):
            if frag_offset > cursor:
                return None
            cursor = max(cursor, frag_offset + len(entry["fragments"][frag_offset]))

        if cursor < entry["total"]:
            return None

        assembled = bytearray()
        for frag_offset in sorted(entry["fragments"]):
            fragment = entry["fragments"][frag_offset]
            if frag_offset < len(assembled):
                # Overlapping fragments: keep what arrived first, which is
                # what most operating systems do.
                skip = len(assembled) - frag_offset
                if skip >= len(fragment):
                    continue
                fragment = fragment[skip:]
            assembled.extend(fragment)

        self.pending.pop(key, None)
        self.completed += 1
        return bytes(assembled)

    def _expire(self, now: float) -> None:
        """Drop fragment sets that will never complete."""
        stale = [
            key for key, entry in self.pending.items()
            if now - entry["last_seen"] > FRAGMENT_TIMEOUT
        ]
        for key in stale:
            self.pending.pop(key, None)
            self.dropped += 1

    def stats(self) -> dict:
        return {
            "datagrams_reassembled": self.completed,
            "fragment_sets_incomplete": len(self.pending),
            "fragment_sets_dropped": self.dropped,
            "overlapping_fragments": self.overlapping,
        }
