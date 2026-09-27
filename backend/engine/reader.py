"""
WireCub capture reader.

Pure-Python streaming reader for pcap and pcapng captures. No external
binaries, no full-file buffering: records are yielded one at a time so a
10 GB capture costs the same memory as a 10 MB one.

Handles:
  - classic pcap (both endiannesses, us and ns timestamp resolution)
  - pcapng (SHB/IDB/EPB/SPB/ISB, per-interface link types and tsresol)
  - gzip, bzip2 and zstd compressed captures (transparent)
  - captures with multiple interfaces of differing link types
"""

from __future__ import annotations

import bz2
import gzip
import io
import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

# ---------------------------------------------------------------------------
# Link layer types (LINKTYPE_* from the pcap spec)
# ---------------------------------------------------------------------------

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_PPP = 9
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IEEE802_11 = 105
LINKTYPE_IEEE802_11_RADIOTAP = 127
LINKTYPE_RAW_IPV4 = 228
LINKTYPE_RAW_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

LINKTYPE_NAMES = {
    LINKTYPE_NULL: "BSD loopback",
    LINKTYPE_ETHERNET: "Ethernet",
    LINKTYPE_PPP: "PPP",
    LINKTYPE_RAW: "Raw IP",
    LINKTYPE_LOOP: "OpenBSD loopback",
    LINKTYPE_LINUX_SLL: "Linux cooked v1",
    LINKTYPE_IEEE802_11: "802.11",
    LINKTYPE_IEEE802_11_RADIOTAP: "802.11 + radiotap",
    LINKTYPE_RAW_IPV4: "Raw IPv4",
    LINKTYPE_RAW_IPV6: "Raw IPv6",
    LINKTYPE_LINUX_SLL2: "Linux cooked v2",
}

# pcap magic numbers
PCAP_MAGIC_LE = 0xA1B2C3D4       # microsecond, little endian
PCAP_MAGIC_BE = 0xD4C3B2A1       # microsecond, big endian
PCAP_MAGIC_NS_LE = 0xA1B23C4D    # nanosecond, little endian
PCAP_MAGIC_NS_BE = 0x4D3CB2A1    # nanosecond, big endian

# pcapng block types
BLK_SHB = 0x0A0D0D0A
BLK_IDB = 0x00000001
BLK_SPB = 0x00000003
BLK_EPB = 0x00000006
BLK_ISB = 0x00000005

SHB_BYTE_ORDER_MAGIC = 0x1A2B3C4D


class CaptureError(Exception):
    """Raised when a file cannot be read as a capture."""


@dataclass(slots=True)
class Packet:
    """One captured frame, with the metadata needed to decode it."""

    number: int          # 1-based index within the capture
    ts: float            # epoch seconds, fractional
    caplen: int          # bytes actually stored
    wirelen: int         # bytes originally on the wire
    linktype: int        # LINKTYPE_* for this frame's interface
    data: bytes          # raw frame bytes

    @property
    def truncated(self) -> bool:
        return self.caplen < self.wirelen


@dataclass(slots=True)
class CaptureInfo:
    """What we learned about the capture container itself."""

    fmt: str = "unknown"              # "pcap" or "pcapng"
    compression: str | None = None    # "gzip" | "bzip2" | "zstd" | None
    byte_order: str = "little"
    linktypes: dict[int, int] | None = None   # interface id -> linktype
    snaplen: int = 0
    os_desc: str | None = None
    app_desc: str | None = None
    hardware: str | None = None
    interfaces: list[dict] | None = None
    # Counters filled in as we stream
    packets: int = 0
    bytes_on_wire: int = 0
    bytes_captured: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    truncated_packets: int = 0
    # Reported by ISB blocks when the capture tool recorded drops
    drops_reported: int | None = None

    def __post_init__(self):
        if self.linktypes is None:
            self.linktypes = {}
        if self.interfaces is None:
            self.interfaces = []

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def linktype_names(self) -> list[str]:
        seen: list[str] = []
        for lt in self.linktypes.values():
            name = LINKTYPE_NAMES.get(lt, f"Link type {lt}")
            if name not in seen:
                seen.append(name)
        return seen


# ---------------------------------------------------------------------------
# Transparent decompression
# ---------------------------------------------------------------------------

def _open_maybe_compressed(path: str) -> tuple[BinaryIO, str | None]:
    """Open a capture, transparently decompressing if needed."""
    with open(path, "rb") as probe:
        head = probe.read(4)

    if head[:2] == b"\x1f\x8b":
        return gzip.open(path, "rb"), "gzip"           # type: ignore[return-value]
    if head[:3] == b"BZh":
        return bz2.open(path, "rb"), "bzip2"           # type: ignore[return-value]
    if head[:4] == b"\x28\xb5\x2f\xfd":
        try:
            import zstandard  # optional dependency
        except ImportError as exc:  # pragma: no cover
            raise CaptureError(
                "This capture is zstd compressed. Install the 'zstandard' "
                "package to read it, or decompress it first."
            ) from exc
        raw = open(path, "rb")
        dctx = zstandard.ZstdDecompressor()
        return dctx.stream_reader(raw), "zstd"         # type: ignore[return-value]

    return open(path, "rb"), None


def _buffered(stream: BinaryIO) -> BinaryIO:
    """Wrap in a large read buffer. Decompressors especially need this."""
    if isinstance(stream, io.BufferedReader):
        return stream
    return io.BufferedReader(stream, buffer_size=1 << 20)  # type: ignore[arg-type]


def _read_exact(stream: BinaryIO, n: int) -> bytes:
    """Read exactly n bytes, or fewer at clean end of file."""
    if n <= 0:
        return b""
    chunks: list[bytes] = []
    remaining = n
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# Format sniffing
# ---------------------------------------------------------------------------

def detect_format(path: str) -> tuple[str, str | None]:
    """Return (format, compression) without consuming the capture."""
    stream, compression = _open_maybe_compressed(path)
    try:
        head = _read_exact(_buffered(stream), 4)
    finally:
        stream.close()

    if len(head) < 4:
        raise CaptureError("File is too small to be a capture.")

    magic = struct.unpack("<I", head)[0]
    magic_be = struct.unpack(">I", head)[0]

    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE):
        return "pcap", compression
    if magic_be in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE):
        return "pcap", compression
    if magic == BLK_SHB or magic_be == BLK_SHB:
        return "pcapng", compression

    raise CaptureError(
        "Unrecognised file. WireCub reads pcap and pcapng captures, "
        "optionally gzip, bzip2 or zstd compressed."
    )


# ---------------------------------------------------------------------------
# Classic pcap
# ---------------------------------------------------------------------------

def _iter_pcap(stream: BinaryIO, info: CaptureInfo) -> Iterator[Packet]:
    header = _read_exact(stream, 24)
    if len(header) < 24:
        raise CaptureError("Truncated pcap file header.")

    magic = struct.unpack("<I", header[:4])[0]
    if magic == PCAP_MAGIC_LE:
        endian, ts_divisor = "<", 1_000_000
    elif magic == PCAP_MAGIC_NS_LE:
        endian, ts_divisor = "<", 1_000_000_000
    elif magic == PCAP_MAGIC_BE:
        endian, ts_divisor = ">", 1_000_000
    elif magic == PCAP_MAGIC_NS_BE:
        endian, ts_divisor = ">", 1_000_000_000
    else:
        raise CaptureError("Bad pcap magic number.")

    (_maj, _min, _tz, _sig, snaplen, linktype) = struct.unpack(
        endian + "HHiIII", header[4:24]
    )

    info.fmt = "pcap"
    info.byte_order = "little" if endian == "<" else "big"
    info.snaplen = snaplen
    info.linktypes[0] = linktype
    info.interfaces.append(
        {
            "id": 0,
            "name": "Interface 0",
            "linktype": linktype,
            "linktype_name": LINKTYPE_NAMES.get(linktype, f"Link type {linktype}"),
            "snaplen": snaplen,
        }
    )

    rec_hdr = struct.Struct(endian + "IIII")
    number = 0

    while True:
        raw = _read_exact(stream, 16)
        if len(raw) < 16:
            break
        ts_sec, ts_frac, caplen, wirelen = rec_hdr.unpack(raw)

        # Guard against corrupt length fields sending us into a huge alloc
        if caplen > 0x40000000:
            raise CaptureError(
                f"Packet {number + 1} declares an impossible length "
                f"({caplen} bytes). The capture is corrupt."
            )

        data = _read_exact(stream, caplen)
        if len(data) < caplen:
            break  # truncated final record, stop cleanly

        number += 1
        yield Packet(
            number=number,
            ts=ts_sec + ts_frac / ts_divisor,
            caplen=caplen,
            wirelen=wirelen,
            linktype=linktype,
            data=data,
        )


# ---------------------------------------------------------------------------
# pcapng
# ---------------------------------------------------------------------------

def _parse_options(body: bytes, endian: str) -> dict[int, list[bytes]]:
    """Parse a pcapng option list into {option_code: [values]}."""
    opts: dict[int, list[bytes]] = {}
    pos = 0
    while pos + 4 <= len(body):
        code, length = struct.unpack(endian + "HH", body[pos:pos + 4])
        pos += 4
        if code == 0:  # opt_endofopt
            break
        value = body[pos:pos + length]
        pos += length + (-length % 4)  # options are padded to 4 bytes
        opts.setdefault(code, []).append(value)
    return opts


def _iter_pcapng(stream: BinaryIO, info: CaptureInfo) -> Iterator[Packet]:
    info.fmt = "pcapng"
    endian = "<"
    iface_linktypes: dict[int, int] = {}
    iface_tsresol: dict[int, float] = {}
    iface_tsoffset: dict[int, int] = {}
    next_iface_id = 0
    number = 0

    while True:
        head = _read_exact(stream, 8)
        if len(head) < 8:
            break

        block_type = struct.unpack(endian + "I", head[:4])[0]

        # A section header can flip endianness mid-file.
        if block_type == BLK_SHB or struct.unpack(">I", head[:4])[0] == BLK_SHB:
            body_len = struct.unpack(endian + "I", head[4:8])[0]
            probe = _read_exact(stream, 4)
            if len(probe) < 4:
                break
            bom = struct.unpack("<I", probe)[0]
            if bom == SHB_BYTE_ORDER_MAGIC:
                endian = "<"
            else:
                endian = ">"
                body_len = struct.unpack(">I", head[4:8])[0]
            info.byte_order = "little" if endian == "<" else "big"

            rest = _read_exact(stream, max(0, body_len - 12))
            if len(rest) < body_len - 12:
                break
            # rest = version(4) + section_length(8) + options + trailing length(4)
            opts = _parse_options(rest[12:-4], endian) if len(rest) > 16 else {}
            if 3 in opts:
                info.os_desc = opts[3][0].decode("utf-8", "replace")
            if 4 in opts:
                info.app_desc = opts[4][0].decode("utf-8", "replace")
            if 2 in opts:
                info.hardware = opts[2][0].decode("utf-8", "replace")

            # New section: interface table resets
            iface_linktypes.clear()
            iface_tsresol.clear()
            iface_tsoffset.clear()
            next_iface_id = 0
            continue

        body_len = struct.unpack(endian + "I", head[4:8])[0]
        if body_len < 12 or body_len > 0x40000000:
            raise CaptureError(
                f"Corrupt pcapng block: declared length {body_len} bytes."
            )
        body = _read_exact(stream, body_len - 8)
        if len(body) < body_len - 8:
            break
        body = body[:-4]  # drop trailing block-length field

        if block_type == BLK_IDB:
            linktype, _reserved, snaplen = struct.unpack(endian + "HHI", body[:8])
            opts = _parse_options(body[8:], endian)

            name = None
            if 2 in opts:
                name = opts[2][0].decode("utf-8", "replace")

            tsresol = 1e-6
            if 9 in opts and opts[9][0]:
                raw_res = opts[9][0][0]
                if raw_res & 0x80:
                    tsresol = 2.0 ** -(raw_res & 0x7F)
                else:
                    tsresol = 10.0 ** -raw_res
            tsoffset = 0
            if 14 in opts and len(opts[14][0]) >= 8:
                tsoffset = struct.unpack(endian + "q", opts[14][0][:8])[0]

            iface_id = next_iface_id
            next_iface_id += 1
            iface_linktypes[iface_id] = linktype
            iface_tsresol[iface_id] = tsresol
            iface_tsoffset[iface_id] = tsoffset

            info.linktypes[iface_id] = linktype
            info.snaplen = max(info.snaplen, snaplen)
            info.interfaces.append(
                {
                    "id": iface_id,
                    "name": name or f"Interface {iface_id}",
                    "linktype": linktype,
                    "linktype_name": LINKTYPE_NAMES.get(
                        linktype, f"Link type {linktype}"
                    ),
                    "snaplen": snaplen,
                }
            )

        elif block_type == BLK_EPB:
            iface_id, ts_hi, ts_lo, caplen, wirelen = struct.unpack(
                endian + "IIIII", body[:20]
            )
            data = body[20:20 + caplen]
            resol = iface_tsresol.get(iface_id, 1e-6)
            offset = iface_tsoffset.get(iface_id, 0)
            ts = (((ts_hi << 32) | ts_lo) * resol) + offset
            number += 1
            yield Packet(
                number=number,
                ts=ts,
                caplen=caplen,
                wirelen=wirelen,
                linktype=iface_linktypes.get(iface_id, LINKTYPE_ETHERNET),
                data=data,
            )

        elif block_type == BLK_SPB:
            # Simple packet block: no timestamp, no interface id.
            wirelen = struct.unpack(endian + "I", body[:4])[0]
            data = body[4:]
            number += 1
            yield Packet(
                number=number,
                ts=0.0,
                caplen=len(data),
                wirelen=wirelen,
                linktype=iface_linktypes.get(0, LINKTYPE_ETHERNET),
                data=data,
            )

        elif block_type == BLK_ISB:
            opts = _parse_options(body[12:], endian)
            if 5 in opts and len(opts[5][0]) >= 8:  # isb_ifdrop
                drops = struct.unpack(endian + "Q", opts[5][0][:8])[0]
                info.drops_reported = (info.drops_reported or 0) + drops

        # Any other block type is skipped: we already consumed its bytes.


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def read_packets(path: str, info: CaptureInfo | None = None) -> Iterator[Packet]:
    """
    Stream every packet in a capture.

    Pass a CaptureInfo to have container metadata and running counters
    filled in as the stream is consumed.
    """
    if info is None:
        info = CaptureInfo()

    fmt, compression = detect_format(path)
    info.compression = compression

    raw_stream, _ = _open_maybe_compressed(path)
    stream = _buffered(raw_stream)

    try:
        source = _iter_pcap(stream, info) if fmt == "pcap" else _iter_pcapng(stream, info)
        for pkt in source:
            info.packets += 1
            info.bytes_on_wire += pkt.wirelen
            info.bytes_captured += pkt.caplen
            if pkt.truncated:
                info.truncated_packets += 1
            if pkt.ts:
                if info.first_ts is None or pkt.ts < info.first_ts:
                    info.first_ts = pkt.ts
                if info.last_ts is None or pkt.ts > info.last_ts:
                    info.last_ts = pkt.ts
            yield pkt
    finally:
        stream.close()


def probe(path: str) -> CaptureInfo:
    """Read only the container headers. Cheap: does not walk the packets."""
    info = CaptureInfo()
    fmt, compression = detect_format(path)
    info.compression = compression

    raw_stream, _ = _open_maybe_compressed(path)
    stream = _buffered(raw_stream)
    try:
        source = _iter_pcap(stream, info) if fmt == "pcap" else _iter_pcapng(stream, info)
        for _ in source:
            break  # one packet is enough to force header parsing
    except CaptureError:
        raise
    finally:
        stream.close()

    info.packets = 0
    info.bytes_on_wire = 0
    info.bytes_captured = 0
    info.first_ts = None
    info.last_ts = None
    return info
