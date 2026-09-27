"""
File carving and static triage.

Pulls transferred files out of reassembled streams, identifies them by
content rather than by declared name, hashes them, and runs a built-in
signature set over the bytes.

The signature engine is deliberately written in plain Python rather than
binding to YARA. WireCub is often installed on a machine an analyst does
not control, and a compiled dependency that fails to build turns a working
tool into a support ticket. If yara-python happens to be present, its
rules run in addition to these.
"""

from __future__ import annotations

import hashlib
import math
import re
import struct
from dataclasses import dataclass, field

MAX_FILES = 400
MAX_FILE_BYTES = 8 * 1024 * 1024
MIN_FILE_BYTES = 64

# Magic byte signatures, longest first so specific types win over generic.
FILE_TYPES: list[tuple[bytes, str, str, str]] = [
    (b"MZ",                     "exe",   "Windows executable",       "executable"),
    (b"\x7fELF",                "elf",   "Linux executable",         "executable"),
    (b"\xca\xfe\xba\xbe",       "class", "Java class",               "executable"),
    (b"\xcf\xfa\xed\xfe",       "macho", "macOS executable",         "executable"),
    (b"\xfe\xed\xfa\xce",       "macho", "macOS executable",         "executable"),
    (b"dex\n",                  "dex",   "Android bytecode",         "executable"),
    (b"%PDF",                   "pdf",   "PDF document",             "document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "Legacy Office document", "document"),
    (b"PK\x03\x04",             "zip",   "ZIP container",            "archive"),
    (b"Rar!\x1a\x07",           "rar",   "RAR archive",              "archive"),
    (b"7z\xbc\xaf\x27\x1c",     "7z",    "7-Zip archive",            "archive"),
    (b"\x1f\x8b\x08",           "gz",    "gzip stream",              "archive"),
    (b"BZh",                    "bz2",   "bzip2 archive",            "archive"),
    (b"\xfd7zXZ",               "xz",    "XZ archive",               "archive"),
    (b"\x89PNG\r\n\x1a\n",      "png",   "PNG image",                "image"),
    (b"\xff\xd8\xff",           "jpg",   "JPEG image",               "image"),
    (b"GIF87a",                 "gif",   "GIF image",                "image"),
    (b"GIF89a",                 "gif",   "GIF image",                "image"),
    (b"BM",                     "bmp",   "Bitmap image",             "image"),
    (b"RIFF",                   "riff",  "RIFF media container",     "media"),
    (b"\x00\x00\x01\xba",       "mpg",   "MPEG stream",              "media"),
    (b"ID3",                    "mp3",   "MP3 audio",                "media"),
    (b"OggS",                   "ogg",   "Ogg media",                "media"),
    (b"SQLite format 3",        "sqlite","SQLite database",          "data"),
    (b"-----BEGIN",             "pem",   "PEM encoded key or cert",  "credential"),
    (b"<?xml",                  "xml",   "XML document",             "text"),
    (b"<!DOCTYPE html",         "html",  "HTML document",            "text"),
    (b"<html",                  "html",  "HTML document",            "text"),
    (b"#!/",                    "script","Shell script",             "script"),
]

# ZIP containers that are really Office documents or Java archives.
ZIP_SUBTYPES = [
    (b"word/",              "docx", "Word document"),
    (b"xl/",                "xlsx", "Excel workbook"),
    (b"ppt/",               "pptx", "PowerPoint presentation"),
    (b"META-INF/MANIFEST",  "jar",  "Java archive"),
    (b"AndroidManifest",    "apk",  "Android package"),
    (b"vbaProject.bin",     "docm", "Office document with macros"),
]


@dataclass
class CarvedFile:
    """One file recovered from the wire."""

    index: int
    filename: str | None
    extension: str
    description: str
    category: str
    size: int
    md5: str
    sha1: str
    sha256: str
    entropy: float
    source: str            # server IP
    destination: str       # client IP
    protocol: str
    url: str | None = None
    content_type: str | None = None
    packet: int = 0
    ts: float = 0.0
    truncated: bool = False
    stored: bool = False
    signatures: list[dict] = field(default_factory=list)
    pe_info: dict | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "filename": self.filename,
            "extension": self.extension,
            "description": self.description,
            "category": self.category,
            "size": self.size,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "entropy": round(self.entropy, 2),
            "source": self.source,
            "destination": self.destination,
            "protocol": self.protocol,
            "url": self.url,
            "content_type": self.content_type,
            "packet": self.packet,
            "ts": self.ts,
            "truncated": self.truncated,
            "stored": self.stored,
            "signatures": self.signatures,
            "pe_info": self.pe_info,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Identification
# ---------------------------------------------------------------------------

def identify(data: bytes) -> tuple[str, str, str]:
    """Return (extension, description, category) from content alone."""
    if not data:
        return ("bin", "Empty", "unknown")

    for magic, ext, desc, category in FILE_TYPES:
        if data.startswith(magic):
            if ext == "zip":
                head = data[:8192]
                for marker, sub_ext, sub_desc in ZIP_SUBTYPES:
                    if marker in head:
                        category = "document" if sub_ext.startswith(("doc", "xls", "ppt")) else "executable"
                        return (sub_ext, sub_desc, category)
            if ext == "riff":
                if data[8:12] == b"WAVE":
                    return ("wav", "WAV audio", "media")
                if data[8:12] == b"AVI ":
                    return ("avi", "AVI video", "media")
                if data[8:12] == b"WEBP":
                    return ("webp", "WebP image", "image")
            return (ext, desc, category)

    # Printable text with no magic bytes.
    sample = data[:512]
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    if printable / max(1, len(sample)) > 0.92:
        lowered = sample.lower()
        if b"<?php" in lowered:
            return ("php", "PHP source", "script")
        if b"function" in lowered and b"var " in lowered:
            return ("js", "JavaScript source", "script")
        if b"powershell" in lowered or b"-encodedcommand" in lowered:
            return ("ps1", "PowerShell script", "script")
        return ("txt", "Plain text", "text")

    return ("bin", "Unrecognised binary", "unknown")


def entropy_of(data: bytes) -> float:
    """Shannon entropy in bits per byte. Near 8 means packed or encrypted."""
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
# PE analysis
# ---------------------------------------------------------------------------

def analyse_pe(data: bytes) -> dict | None:
    """
    Read the parts of a PE header that matter for triage.

    Includes imphash, the hash of the import table, which stays stable
    across recompilations of the same malware family and is therefore a
    stronger family indicator than the file hash itself.
    """
    if not data.startswith(b"MZ") or len(data) < 0x40:
        return None

    try:
        pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
        if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return None

        machine, section_count, timestamp, _sym, _nsym, opt_size, characteristics = (
            struct.unpack("<HHIIIHH", data[pe_offset + 4:pe_offset + 24])
        )

        opt_offset = pe_offset + 24
        magic = struct.unpack("<H", data[opt_offset:opt_offset + 2])[0]
        is_64 = magic == 0x20B

        subsystem = None
        if opt_offset + 70 <= len(data):
            sub_off = opt_offset + (68 if is_64 else 68)
            subsystem = struct.unpack("<H", data[sub_off:sub_off + 2])[0]

        # Sections: unusual names and high entropy indicate packing.
        section_offset = opt_offset + opt_size
        sections = []
        for i in range(min(section_count, 24)):
            base = section_offset + i * 40
            if base + 40 > len(data):
                break
            name = data[base:base + 8].rstrip(b"\x00").decode("ascii", "replace")
            virtual_size, virtual_addr, raw_size, raw_ptr = struct.unpack(
                "<IIII", data[base + 8:base + 24]
            )
            section_data = data[raw_ptr:raw_ptr + raw_size] if raw_size else b""
            sections.append(
                {
                    "name": name,
                    "virtual_size": virtual_size,
                    "raw_size": raw_size,
                    "entropy": round(entropy_of(section_data[:65536]), 2)
                    if section_data else 0.0,
                }
            )

        imports = _pe_imports(data, sections, opt_offset, opt_size, is_64)
        imphash = None
        if imports:
            normalised = ",".join(
                f"{dll.lower().rsplit('.', 1)[0]}.{func.lower()}"
                for dll, funcs in imports for func in funcs
            )
            imphash = hashlib.md5(normalised.encode()).hexdigest()

        machine_names = {
            0x014C: "x86", 0x8664: "x64", 0x01C0: "ARM",
            0xAA64: "ARM64", 0x0200: "IA64",
        }
        subsystem_names = {1: "native", 2: "GUI", 3: "console", 9: "Windows CE"}

        return {
            "architecture": machine_names.get(machine, f"0x{machine:04x}"),
            "subsystem": subsystem_names.get(subsystem, str(subsystem)),
            "compiled": timestamp,
            "is_dll": bool(characteristics & 0x2000),
            "sections": sections,
            "section_count": section_count,
            "imphash": imphash,
            "imported_dlls": [dll for dll, _ in imports][:20],
            "import_count": sum(len(f) for _, f in imports),
            "suspicious_imports": _suspicious_imports(imports),
        }
    except (struct.error, IndexError, ValueError):
        return None


def _pe_imports(data, sections, opt_offset, opt_size, is_64) -> list[tuple[str, list[str]]]:
    """Walk the import directory. Best effort: returns [] when unmapped."""
    try:
        dir_offset = opt_offset + (112 if is_64 else 96)
        import_rva, _import_size = struct.unpack(
            "<II", data[dir_offset + 8:dir_offset + 16]
        )
        if not import_rva:
            return []

        def rva_to_offset(rva: int) -> int | None:
            for section in sections:
                pass
            return None

        # Rebuild a section map with the fields needed for translation.
        section_offset = opt_offset + opt_size
        mapped = []
        for i in range(min(len(sections), 24)):
            base = section_offset + i * 40
            if base + 40 > len(data):
                break
            virtual_size, virtual_addr, raw_size, raw_ptr = struct.unpack(
                "<IIII", data[base + 8:base + 24]
            )
            mapped.append((virtual_addr, max(virtual_size, raw_size), raw_ptr))

        def translate(rva: int) -> int | None:
            for virtual_addr, size, raw_ptr in mapped:
                if virtual_addr <= rva < virtual_addr + size:
                    return raw_ptr + (rva - virtual_addr)
            return None

        table = translate(import_rva)
        if table is None:
            return []

        results: list[tuple[str, list[str]]] = []
        for i in range(64):
            entry = table + i * 20
            if entry + 20 > len(data):
                break
            lookup_rva, _ts, _fc, name_rva, thunk_rva = struct.unpack(
                "<IIIII", data[entry:entry + 20]
            )
            if not name_rva:
                break
            name_off = translate(name_rva)
            if name_off is None:
                break
            end = data.find(b"\x00", name_off, name_off + 128)
            dll = data[name_off:end if end != -1 else name_off + 32].decode(
                "ascii", "replace"
            )

            functions: list[str] = []
            thunks = translate(lookup_rva or thunk_rva)
            if thunks is not None:
                step = 8 if is_64 else 4
                fmt = "<Q" if is_64 else "<I"
                for j in range(400):
                    pos = thunks + j * step
                    if pos + step > len(data):
                        break
                    value = struct.unpack(fmt, data[pos:pos + step])[0]
                    if not value:
                        break
                    ordinal_flag = 0x8000000000000000 if is_64 else 0x80000000
                    if value & ordinal_flag:
                        functions.append(f"ord{value & 0xFFFF}")
                        continue
                    fn_off = translate(value)
                    if fn_off is None or fn_off + 2 >= len(data):
                        break
                    fn_end = data.find(b"\x00", fn_off + 2, fn_off + 160)
                    functions.append(
                        data[fn_off + 2:fn_end if fn_end != -1 else fn_off + 40]
                        .decode("ascii", "replace")
                    )
            results.append((dll, functions))
        return results
    except (struct.error, IndexError, ValueError):
        return []


# API calls that legitimate software uses too, but which cluster heavily in
# injection, persistence and anti-analysis code.
SUSPICIOUS_APIS = {
    "VirtualAllocEx": "allocates memory inside another process",
    "WriteProcessMemory": "writes into another process",
    "CreateRemoteThread": "starts code inside another process",
    "NtUnmapViewOfSection": "hollows out a process image",
    "SetWindowsHookEx": "hooks input, used by keyloggers",
    "GetAsyncKeyState": "reads keystrokes",
    "IsDebuggerPresent": "checks for a debugger",
    "CheckRemoteDebuggerPresent": "checks for a debugger",
    "NtQueryInformationProcess": "used for anti-debugging checks",
    "CryptEncrypt": "encrypts data",
    "CryptGenKey": "generates encryption keys",
    "InternetOpenUrlA": "downloads over HTTP",
    "URLDownloadToFileA": "downloads a file",
    "WinExec": "runs a command",
    "ShellExecuteA": "runs a command",
    "CreateServiceA": "installs a service for persistence",
    "RegSetValueExA": "writes a registry value",
    "AdjustTokenPrivileges": "raises process privileges",
    "LookupPrivilegeValueA": "raises process privileges",
    "EnumProcesses": "enumerates running processes",
    "Process32First": "enumerates running processes",
    "GetTickCount": "times execution, used to detect sandboxes",
}


def _suspicious_imports(imports) -> list[dict]:
    found = []
    for dll, functions in imports:
        for function in functions:
            base = function.rstrip("AW")
            for api, reason in SUSPICIOUS_APIS.items():
                if base == api.rstrip("AW"):
                    found.append({"api": function, "dll": dll, "reason": reason})
                    break
    return found[:20]


# ---------------------------------------------------------------------------
# Signature engine
# ---------------------------------------------------------------------------

@dataclass
class Signature:
    name: str
    severity: str
    description: str
    patterns: list[bytes] = field(default_factory=list)
    regexes: list[re.Pattern] = field(default_factory=list)
    require_all: bool = False
    min_matches: int = 1
    applies_to: set[str] | None = None


BUILTIN_SIGNATURES: list[Signature] = [
    Signature(
        "Embedded PowerShell with encoded command",
        "high",
        "Runs PowerShell with a base64 payload, which hides the actual "
        "command from anything inspecting the command line.",
        regexes=[re.compile(rb"(?i)powershell[^\n]{0,80}-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/]{40,}")],
    ),
    Signature(
        "PowerShell download and execute",
        "high",
        "Fetches a payload from the network and runs it without writing it "
        "to disk first, a standard fileless delivery pattern.",
        regexes=[re.compile(rb"(?i)(downloadstring|downloadfile|invoke-webrequest|iwr)\s*\(?")],
        patterns=[b"IEX", b"Invoke-Expression"],
        require_all=True,
    ),
    Signature(
        "Office document with auto-executing macro",
        "high",
        "Contains a macro that runs when the document opens rather than "
        "waiting for the user to click anything.",
        regexes=[re.compile(rb"(?i)(auto_?open|document_?open|workbook_?open|autoexec)")],
        applies_to={"docm", "ole", "docx", "xlsx", "xlsm"},
    ),
    Signature(
        "Office macro shelling out",
        "critical",
        "Macro code that starts an external process. Documents have no "
        "legitimate reason to launch a shell.",
        regexes=[re.compile(rb"(?i)(shell\s*\(|wscript\.shell|createobject\s*\(\s*[\"']wscript)")],
        applies_to={"docm", "ole", "docx", "xlsx", "xlsm", "vba"},
    ),
    Signature(
        "PDF with embedded JavaScript",
        "medium",
        "PDF carrying JavaScript that runs on open. Used to trigger reader "
        "vulnerabilities.",
        patterns=[b"/JavaScript", b"/JS"],
        applies_to={"pdf"},
    ),
    Signature(
        "PDF with automatic action",
        "medium",
        "PDF that performs an action without user interaction.",
        patterns=[b"/OpenAction", b"/AA"],
        applies_to={"pdf"},
    ),
    Signature(
        "PDF with embedded file",
        "medium",
        "PDF carrying another file inside it, a way to smuggle a payload "
        "past filters that only inspect the outer type.",
        patterns=[b"/EmbeddedFile", b"/Launch"],
        applies_to={"pdf"},
    ),
    Signature(
        "Web shell",
        "critical",
        "Server-side script that executes arbitrary commands supplied over "
        "HTTP. This is remote control of the web server.",
        regexes=[
            re.compile(rb"(?i)(eval|assert|system|exec|passthru|shell_exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"),
            re.compile(rb"(?i)Request\.(Item|QueryString|Form)\s*\[[^\]]+\]\s*\)?\s*\)?\s*(;|\))?\s*(Eval|Execute)"),
        ],
    ),
    Signature(
        "Reverse shell",
        "critical",
        "Opens a connection back to an attacker and attaches a command "
        "interpreter to it.",
        regexes=[
            re.compile(rb"(?i)(bash\s+-i\s*>&\s*/dev/tcp/|nc\s+-e\s+/bin/(ba)?sh|socket\.socket\([^)]*\)[^\n]{0,120}dup2)"),
            re.compile(rb"(?i)new-object\s+system\.net\.sockets\.tcpclient"),
        ],
    ),
    Signature(
        "Mimikatz",
        "critical",
        "Credential dumping tool that extracts passwords and hashes from "
        "memory.",
        patterns=[b"sekurlsa", b"gentilkiwi", b"mimikatz", b"logonpasswords"],
    ),
    Signature(
        "Cobalt Strike beacon artefact",
        "critical",
        "Strings associated with the Cobalt Strike post-exploitation "
        "framework, widely used in ransomware intrusions.",
        patterns=[b"beacon.dll", b"beacon.x64.dll", b"ReflectiveLoader",
                  b"%s%s.4%08x%08x%08x%08x%08x"],
    ),
    Signature(
        "Metasploit payload artefact",
        "critical",
        "Strings from the Meterpreter payload family.",
        patterns=[b"metsrv.dll", b"meterpreter", b"stdapi_", b"ReflectiveLoader"],
        min_matches=2,
    ),
    Signature(
        "Ransomware note",
        "critical",
        "Text matching the structure of a ransom demand: encrypted files, "
        "a payment instruction, and a contact channel.",
        regexes=[
            re.compile(rb"(?i)(your files (have been|are) encrypted|all your files.{0,40}encrypted)"),
            re.compile(rb"(?i)(bitcoin|monero|btc address|decrypt(ion)? key|onion)"),
        ],
        require_all=True,
    ),
    Signature(
        "Shadow copy deletion",
        "critical",
        "Deletes Windows backup snapshots, which ransomware does to stop "
        "victims restoring their files.",
        regexes=[re.compile(rb"(?i)(vssadmin[^\n]{0,60}delete\s+shadows|wbadmin[^\n]{0,40}delete\s+catalog|bcdedit[^\n]{0,60}recoveryenabled\s+no)")],
    ),
    Signature(
        "UPX packed",
        "low",
        "Compressed with UPX. Common in legitimate software, and also used "
        "to shrink and lightly obscure malware.",
        patterns=[b"UPX0", b"UPX1", b"UPX!"],
        min_matches=2,
    ),
    Signature(
        "Private key material",
        "high",
        "A private key transferred in the clear. Anyone who captured this "
        "traffic now holds the key.",
        patterns=[b"-----BEGIN RSA PRIVATE KEY", b"-----BEGIN PRIVATE KEY",
                  b"-----BEGIN OPENSSH PRIVATE KEY", b"-----BEGIN EC PRIVATE KEY"],
    ),
    Signature(
        "Cloud credentials",
        "high",
        "Access keys for a cloud provider found in transferred content.",
        regexes=[
            re.compile(rb"AKIA[0-9A-Z]{16}"),
            re.compile(rb"(?i)aws_secret_access_key\s*[=:]\s*\S{30,}"),
            re.compile(rb"ghp_[A-Za-z0-9]{36}"),
            re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,}"),
        ],
    ),
    Signature(
        "Mining configuration",
        "medium",
        "Cryptocurrency mining pool configuration, indicating mining "
        "software was delivered.",
        regexes=[re.compile(rb"(?i)(stratum\+tcp://|\"pool\"\s*:|--donate-level|xmrig)")],
    ),
    Signature(
        "Anti-analysis checks",
        "medium",
        "Looks for virtual machine and sandbox artefacts, which software "
        "does when it wants to behave differently while being watched.",
        patterns=[b"VMwareService", b"vboxservice", b"SbieDll.dll",
                  b"VBoxGuest", b"qemu-ga", b"wine_get_unix_file_name"],
        min_matches=2,
    ),
]


def scan_signatures(data: bytes, extension: str) -> list[dict]:
    """Run the built-in signature set, plus YARA if it happens to exist."""
    hits: list[dict] = []
    window = data[:2 * 1024 * 1024]

    for sig in BUILTIN_SIGNATURES:
        if sig.applies_to and extension not in sig.applies_to:
            continue

        pattern_hits = sum(1 for p in sig.patterns if p in window)
        regex_hits = sum(1 for r in sig.regexes if r.search(window))
        total = pattern_hits + regex_hits

        if sig.require_all:
            matched = (
                pattern_hits == len(sig.patterns)
                and regex_hits == len(sig.regexes)
            )
        else:
            matched = total >= sig.min_matches

        if matched:
            hits.append(
                {
                    "name": sig.name,
                    "severity": sig.severity,
                    "description": sig.description,
                    "matches": total,
                    "engine": "builtin",
                }
            )

    hits.extend(_yara_scan(window))
    return hits


_YARA_RULES = None


def _yara_scan(data: bytes) -> list[dict]:
    """Use yara-python only if it is installed. Never a hard requirement."""
    global _YARA_RULES
    if _YARA_RULES is False:
        return []
    if _YARA_RULES is None:
        try:
            import yara  # noqa: F401
            import os
            rules_path = os.environ.get("WIRECUB_YARA_RULES")
            if not rules_path or not os.path.exists(rules_path):
                _YARA_RULES = False
                return []
            _YARA_RULES = yara.compile(filepath=rules_path)
        except Exception:
            _YARA_RULES = False
            return []
    try:
        return [
            {
                "name": match.rule,
                "severity": match.meta.get("severity", "medium"),
                "description": match.meta.get("description", "User-supplied YARA rule matched."),
                "matches": len(match.strings),
                "engine": "yara",
            }
            for match in _YARA_RULES.match(data=data)
        ][:20]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Carving
# ---------------------------------------------------------------------------

def carve_file(
    data: bytes,
    *,
    index: int,
    source: str,
    destination: str,
    protocol: str,
    url: str | None = None,
    content_type: str | None = None,
    filename: str | None = None,
    packet: int = 0,
    ts: float = 0.0,
    truncated: bool = False,
) -> CarvedFile | None:
    """Turn a recovered byte blob into a triaged file record."""
    if len(data) < MIN_FILE_BYTES:
        return None
    if len(data) > MAX_FILE_BYTES:
        data = data[:MAX_FILE_BYTES]
        truncated = True

    extension, description, category = identify(data)
    file_entropy = entropy_of(data[:1024 * 1024])

    carved = CarvedFile(
        index=index,
        filename=filename,
        extension=extension,
        description=description,
        category=category,
        size=len(data),
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        entropy=file_entropy,
        source=source,
        destination=destination,
        protocol=protocol,
        url=url,
        content_type=content_type,
        packet=packet,
        ts=ts,
        truncated=truncated,
    )

    carved.signatures = scan_signatures(data, extension)

    if extension == "exe":
        carved.pe_info = analyse_pe(data)
        if carved.pe_info:
            packed = [
                s for s in carved.pe_info["sections"]
                if s["entropy"] > 7.2 and s["raw_size"] > 1024
            ]
            if packed:
                carved.notes.append(
                    "Sections with near-maximum entropy suggest the code is "
                    "packed or encrypted, which is done to defeat static "
                    "inspection."
                )
            if carved.pe_info["import_count"] < 8 and carved.pe_info["section_count"] > 2:
                carved.notes.append(
                    "Very few imports for a file this size, typical of a "
                    "packed binary that resolves its APIs at runtime."
                )

    # A declared type that disagrees with the content is deliberate evasion.
    if content_type:
        declared = content_type.split(";")[0].strip().lower()
        if category == "executable" and not any(
            token in declared
            for token in ("octet-stream", "executable", "msdownload",
                          "x-dosexec", "download", "binary")
        ):
            carved.notes.append(
                f"Server declared this as {declared} but the bytes are a "
                f"{description.lower()}."
            )

    if file_entropy > 7.8 and category not in ("archive", "image", "media"):
        carved.notes.append(
            "Entropy is close to the theoretical maximum, meaning the "
            "content is compressed or encrypted rather than plain code."
        )

    return carved


def filename_from_url(url: str | None) -> str | None:
    if not url:
        return None
    path = url.split("?")[0].split("#")[0]
    name = path.rstrip("/").rsplit("/", 1)[-1]
    return name if name and "." in name else None
