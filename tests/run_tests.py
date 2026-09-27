#!/usr/bin/env python3
"""
WireCub test suite.

Generates synthetic captures covering every decoder and detection path,
runs them through the full pipeline, and checks the results. Also verifies
the cryptographic primitives against published test vectors, because a
silent failure there would produce plausible-looking wrong answers rather
than an obvious crash.

Run from the project root:  python3 tests/run_tests.py
"""

import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "backend"))
HERE = os.path.dirname(os.path.abspath(__file__))

PASS, FAIL = [], []


def check(name, condition, detail=""):
    (PASS if condition else FAIL).append(name)
    mark = "  ok  " if condition else "  FAIL"
    print(f"{mark}  {name}" + (f"  — {detail}" if detail and not condition else ""))


def build_fixtures(tmp):
    """Run each generator, writing captures into the temp directory."""
    print("\nGenerating fixtures")
    for script in sorted(os.listdir(HERE)):
        if not script.startswith("fixtures_") or script == "fixtures_large.py":
            continue
        result = subprocess.run(
            [sys.executable, os.path.join(HERE, script)],
            capture_output=True, text=True, cwd=tmp,
        )
        ok = result.returncode == 0
        check(f"fixture {script}", ok, result.stderr.strip()[:200])


def test_crypto():
    print("\nCryptographic primitives")
    from engine.crypto import AES, aes_gcm_decrypt, hkdf_expand_label, hkdf_extract

    # FIPS-197
    ct = AES(bytes.fromhex("000102030405060708090a0b0c0d0e0f")).encrypt_block(
        bytes.fromhex("00112233445566778899aabbccddeeff")).hex()
    check("AES-128 matches FIPS-197", ct == "69c4e0d86a7b0430d8cdb78070b4c55a")

    ct = AES(bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )).encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff")).hex()
    check("AES-256 matches FIPS-197", ct == "8ea2b7ca516745bfeafc49904b496089")

    # NIST GCM test case 4
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    cipher = bytes.fromhex(
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")
    tag = bytes.fromhex("5bc94fbc3221a5db94fae95ae7121a47")
    plain = aes_gcm_decrypt(key, nonce, cipher + tag, aad)
    check("AES-GCM decrypts NIST vector", plain is not None and plain.hex().startswith("d9313225f884"))
    check("AES-GCM rejects a forged tag",
          aes_gcm_decrypt(key, nonce, cipher + b"\x00" * 16, aad) is None)

    # RFC 9001 A.1
    secret = hkdf_expand_label(
        hkdf_extract(bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
                     bytes.fromhex("8394c8f03e515708")),
        "client in", b"", 32)
    check("QUIC key schedule matches RFC 9001",
          hkdf_expand_label(secret, "quic key", b"", 16).hex()
          == "1f369613dd76d5467730efcbe3b1a22d")


def test_capture(path, expectations):
    """Analyse one capture and assert what it should contain."""
    from engine.analyzer import Analyzer
    from engine.serialize import build_report
    from engine import export

    name = os.path.basename(path)
    started = time.time()
    result = Analyzer(path, deep=True, artifact_dir=os.path.join(
        os.path.dirname(path), "artifacts")).run()
    elapsed = time.time() - started

    check(f"{name}: analysed without errors", len(result.errors) == 0,
          str(dict(result.errors))[:200])

    ids = {f.id for f in result.findings}
    for expected in expectations.get("findings", []):
        check(f"{name}: raises {expected}", expected in ids,
              f"got {sorted(ids)}")

    if "min_files" in expectations:
        check(f"{name}: carves {expectations['min_files']} file(s)",
              len(result.files) >= expectations["min_files"],
              f"got {len(result.files)}")

    if "sha256" in expectations:
        check(f"{name}: carved file hash is exact",
              any(f["sha256"] == expectations["sha256"] for f in result.files))

    for key, value in expectations.get("counts", {}).items():
        actual = len(getattr(result, key, []))
        check(f"{name}: {key} >= {value}", actual >= value, f"got {actual}")

    # Every report must survive serialisation and every export format.
    report = build_report(result, meta={
        "job_id": "test", "filename": name, "file_size": os.path.getsize(path),
        "mode": "deep", "analysed_at": 0, "analysis_seconds": round(elapsed, 2),
        "tool": "WireCub", "version": "1.0"})
    try:
        export.build_html_report(report)
        export.build_stix(report)
        export.build_misp_event(report)
        for table in ("findings", "hosts", "flows", "files", "iocs"):
            export.build_csv(report, table)
        check(f"{name}: all export formats build", True)
    except Exception as exc:
        check(f"{name}: all export formats build", False, str(exc)[:200])

    return result


def test_linktypes(tmp):
    print("\nLink types and encapsulation")
    from engine.analyzer import Analyzer

    directory = os.path.join(tmp, "links")
    if not os.path.isdir(directory):
        check("link-type fixtures present", False)
        return
    for name in sorted(os.listdir(directory)):
        result = Analyzer(os.path.join(directory, name), deep=True).run()
        check(f"{os.path.splitext(name)[0]} decodes to the transport layer",
              len(result.http_records) > 0 and len(result.errors) == 0)


def test_rejects_garbage(tmp):
    print("\nMalformed input")
    from engine.analyzer import Analyzer
    from engine.reader import CaptureError

    garbage = os.path.join(tmp, "garbage.pcap")
    with open(garbage, "wb") as handle:
        handle.write(b"this is not a capture" * 60)
    try:
        Analyzer(garbage).run()
        check("rejects a non-capture file", False, "no error raised")
    except CaptureError:
        check("rejects a non-capture file", True)

    # A capture cut off mid-record must analyse what it has, not crash.
    source = os.path.join(tmp, "scenario.pcapng")
    if os.path.exists(source):
        data = open(source, "rb").read()
        truncated = os.path.join(tmp, "truncated.pcapng")
        with open(truncated, "wb") as handle:
            handle.write(data[:len(data) // 3])
        result = Analyzer(truncated, deep=True).run()
        check("analyses a truncated capture", result.capture.packets > 0)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        # Generators write to the current working directory or /tmp paths,
        # so run them there and collect what they produced.
        cwd = os.getcwd()
        os.chdir(tmp)
        try:
            build_fixtures(tmp)
        finally:
            os.chdir(cwd)

        for name in ("scenario.pcapng", "scenario2.pcapng", "smb.pcapng",
                     "frag.pcapng", "wifi.pcapng", "credentials.pcapng",
                     "voip.pcapng"):
            source = os.path.join("/tmp", name)
            if os.path.exists(source) and not os.path.exists(os.path.join(tmp, name)):
                import shutil
                shutil.copy(source, tmp)
        if os.path.isdir("/tmp/links") and not os.path.isdir(os.path.join(tmp, "links")):
            import shutil
            shutil.copytree("/tmp/links", os.path.join(tmp, "links"))

        test_crypto()

        print("\nDetection coverage")
        test_capture(os.path.join(tmp, "scenario.pcapng"), {
            "findings": ["c2.beacon", "dns.tunneling", "recon.port_scan",
                         "web.sqli", "web.rce", "spoof.arp", "tunnel.icmp",
                         "cleartext.http_credentials", "anonymity.tor"],
        })
        test_capture(os.path.join(tmp, "scenario2.pcapng"), {
            "findings": ["ntlm.v1_in_use", "ntlm.password_spraying",
                         "kerberos.kerberoasting", "ics.control_commands",
                         "iot.mqtt_anonymous", "iot.mqtt_cleartext_credentials",
                         "ransomware.mass_file_operations", "quic.in_use",
                         "malware.content_type_mismatch"],
            "min_files": 1,
            "counts": {"quic_records": 5, "ics_records": 20,
                       "ntlm_records": 5, "kerberos_records": 5},
        })
        test_capture(os.path.join(tmp, "smb.pcapng"), {
            "findings": ["file.signature.reverse_shell"],
            "min_files": 1,
            "sha256": "90b28bbb122be66a2ceeb2f60f23193c291ee328d49cb62bfda4b4603e7c6eb9",
        })
        test_capture(os.path.join(tmp, "wifi.pcapng"), {
            "findings": ["wifi.deauth_flood", "wifi.evil_twin",
                         "wifi.handshake_captured"],
        })

        print("\nCredential extraction")
        result = test_capture(os.path.join(tmp, "credentials.pcapng"), {
            "findings": ["credentials.cleartext",
                         "credentials.crackable_hashes"],
        })
        creds = result.credentials
        by_protocol = {c["protocol"] for c in creds}
        for protocol in ("FTP", "Telnet", "POP3", "IMAP", "SMTP", "HTTP"):
            check(f"credentials: {protocol} recovered", protocol in by_protocol)
        pairs = {(c.get("username"), c.get("secret")) for c in creds}
        for user, secret in (
            ("anonymous", "Password123!"),
            ("admin", "Sup3rSecret"),
            ("operator", "Tr0ub4dor"),          # Telnet character mode
            ("mailuser", "letmein2024"),
            ("alice@corp.local", "Winter2024!"),
            ("bob@corp.local", "Passw0rd!"),
            ("smtpuser", "MailPass99"),
            ("erin@corp.local", "Sm7pL0gin!"),
            ("webadmin", "Adm1nP@ss"),
        ):
            check(f"credentials: {user} password exact", (user, secret) in pairs)
        methods = {c["method"] for c in creds}
        for method in ("AUTH CRAM-MD5", "AUTH DIGEST-MD5", "APOP",
                       "HTTP Digest", "HTTP NTLM (NTLMv1)", "AUTH XYMPKI"):
            check(f"credentials: {method} handled", method in methods)

        print("\nVoIP")
        result = test_capture(os.path.join(tmp, "voip.pcapng"), {
            "findings": ["voip.activity", "voip.unencrypted_media",
                         "voip.spoofed_invite"],
        })
        answered = [c for c in result.calls.values() if c.answered]
        check("voip: call reconstructed end to end", len(answered) == 1)
        if answered:
            call = answered[0]
            check("voip: caller and callee identified",
                  call.caller == "sip:alice@corp.local"
                  and call.callee == "sip:bob@corp.local")
            check("voip: duration measured", call.duration and 6 < call.duration < 8)
            check("voip: media matched to the call", len(call.rtp_streams) == 2)
            check("voip: codec identified",
                  all("G.711" in s["codec"] for s in call.rtp_streams))
        creds = [c for c in result.credentials if c["protocol"] == "SIP"]
        check("voip: SIP digest credential recovered",
              any(c["username"] == "alice" for c in creds))

        print("\nFragment reassembly")
        result = test_capture(os.path.join(tmp, "frag.pcapng"), {})
        check("IPv4 and IPv6 fragments reassembled",
              result.reassembly_stats.get("datagrams_reassembled", 0) >= 2)
        check("payload behind fragments is readable",
              len(result.dns_records) >= 1 and len(result.http_records) >= 1)

        test_linktypes(tmp)
        test_rejects_garbage(tmp)

    print(f"\n{'=' * 56}")
    print(f"{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        for name in FAIL:
            print(f"  failed: {name}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
