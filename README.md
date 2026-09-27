<p align="center">
  <img src="logo.png" alt="WireCub" width="460">
</p>

<p align="center">
  Packet capture analysis for SOC analysts and incident responders.
</p>

---

Drop in a `.pcap` or `.pcapng` and WireCub reads it end to end: decodes every
layer, rebuilds the conversations, pulls out the files and credentials that
crossed the wire, and ranks what is worth your attention — each finding with
what was seen, why it matters and what to do next.

## What it finds

- **Attacks** — port scans, C2 beaconing, DNS tunnelling, DGA, SQLi, XSS, path traversal, RCE, Log4Shell, exfiltration, lateral movement, web and reverse shells
- **Credentials** — FTP, Telnet, POP3, IMAP, SMTP, HTTP Basic/Digest, SMB, SIP
- **Windows** — NTLMv1, password spraying, Kerberoasting, SMB1, unsigned and null sessions
- **Files** — carved and hashed (MD5, SHA-1, SHA-256, imphash), with signatures for macros, PowerShell staging, ransom notes, credential dumpers
- **Telephony** — SIP calls rebuilt, unencrypted audio, spoofed INVITEs
- **OT, IoT, wireless** — Modbus, S7comm, DNP3, BACnet writes, anonymous MQTT, deauth floods, evil twins, WPA handshakes

Exports: HTML, JSON, STIX 2.1, MISP, CSV. Two captures can be compared side by side.

## Run locally

Requires Python 3.11+.

```bash
docker compose up -d --build
```

or

```bash
pip install -r requirements.txt
cd backend && python3 app.py
```

Open <http://localhost:8000>.

CCESS_KEY` (the key the app asks for) and `CRON_SECRET` (any random string).
4. Redeploy.

Hosted limits: 200 MB and 5 minutes per capture. Captures are deleted after analysis, reports after 7 days.
