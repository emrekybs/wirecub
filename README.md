# WireCub

A packet capture analysis tool for SOC analysts and incident responders.

Drop in a `.pcap` or `.pcapng` and WireCub reads it end to end: decodes
every layer, rebuilds the conversations, pulls out the files and
credentials that crossed the wire, and tells you what is worth your
attention — with the reasoning shown, not just a severity label.

Run it on your own machine and nothing about the capture leaves it. Or
deploy it to Vercel and use it from anywhere, behind an access key.

---

## Install and run

WireCub runs in two places from the same code: on your own machine, or as a
hosted instance on Vercel.

### On your machine

Requires Python 3.11+. Nothing else.

**Docker**

```bash
docker compose up -d --build
```

**Python**

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cd backend && python3 app.py
```

**uvicorn**

```bash
cd backend
uvicorn app:app --host 127.0.0.1 --port 8000
```

**Debian/Ubuntu/Kali installer**

```bash
./install.sh && wirecub
```

Then open <http://localhost:8000>. The site is at `/`, the analyser at
`/app/`. Change the port with `WIRECUB_PORT=8001`. The installer and
`python3 app.py` listen on this machine only; set `WIRECUB_HOST=0.0.0.0` to
expose WireCub on purpose.

### On Vercel

1. Push this folder to a GitHub repository and import it in Vercel. No
   framework preset or build command is needed: Vercel finds the FastAPI
   app through `index.py` and serves `public/` from its CDN.
2. In the project, open **Storage**, create a **Blob** store and connect it.
   That sets `BLOB_READ_WRITE_TOKEN`. Reports, carved files and history are
   kept there as private blobs.
3. Under **Settings → Environment Variables** add `WIRECUB_ACCESS_KEY`
   (anyone opening the analyser must enter it) and `CRON_SECRET` (any long
   random string; it protects the daily cleanup).
4. Redeploy.

Captures are uploaded in 4 MB pieces to stay under Vercel's request limit,
analysed within one request, and deleted as soon as the report is saved.

| Setting | Default on Vercel | Meaning |
|---|---|---|
| `WIRECUB_ACCESS_KEY` | unset | Key the analyser asks for. Without it the instance is open to anyone with the address. |
| `WIRECUB_MAX_UPLOAD` | 200 MB | Largest capture accepted, in bytes. |
| `WIRECUB_TIME_BUDGET` | 280 s | Analysis stops with an explanation before Vercel's 300 s limit. |
| `WIRECUB_RETENTION_DAYS` | 7 | Reports older than this are deleted by the daily cron. `0` keeps them. |
| `CRON_SECRET` | unset | Authorises `/api/maintenance/cleanup`, which Vercel Cron calls daily. |

On the Hobby plan a function gets 2 GB of memory and at most 300 seconds;
a 200 MB capture analyses in well under a minute at about 650 MB. On Pro you
can raise `maxDuration` in `vercel.json` to 800 and set
`WIRECUB_TIME_BUDGET` and `WIRECUB_MAX_UPLOAD` higher to match.

---

## What it finds

**Attacks** — port scans, C2 beaconing, DNS tunnelling and DGA domains,
SQL injection, XSS, path traversal, RCE and Log4Shell with the payload
shown as it appeared, exfiltration, lateral movement, web and reverse
shells.

**Credentials** — usernames and passwords from FTP, Telnet (line and
character mode), POP3, IMAP, SMTP, HTTP Basic and Digest, SMB and SIP.
Separates what is readable now from what has to be cracked first.

**Windows** — NTLMv1, password spraying, one account spreading across
hosts, Kerberoasting with the targeted service account named, SMB1,
unsigned sessions, null sessions.

**Files** — rebuilt from the packets and hashed (MD5, SHA-1, SHA-256,
imphash). Signatures for PowerShell staging, Office macros, ransom notes,
shadow copy deletion, packers, credential dumpers and leaked keys. Files
can be downloaded for further analysis.

**Ransomware** — high-rate writes across shares, ransom notes and known
extensions.

**Telephony** — SIP calls rebuilt: who called whom, answered or not,
duration, codec, packet loss. Unencrypted audio, registration attacks,
spoofed INVITEs.

**OT, IoT, wireless** — Modbus, S7comm, DNP3 and BACnet write commands,
controllers reachable from outside, anonymous MQTT, deauthentication
floods, evil twins, captured WPA handshakes.

**Context** — typosquatted domains, Tor and VPN egress, QUIC with the
server name recovered, and sandbox environments, so you know when the
"external" side of a capture was simulated.

---

## Working through a capture

**Findings** opens first: every detection, ranked, each explaining what
was seen, why it matters and what to do next.

**Attacks** shows attempts against a host with the payload in full and
whether the server accepted it.

**Timeline** merges findings, credentials, files, calls and first contact
with each external address into one sequence — what followed what.

**Network map** draws the hosts, coloured by role and risk. Downloads as
PNG or SVG.

**Reputation** scores every external address and shows the reason behind
each point, with links to VirusTotal, AbuseIPDB, Shodan and GreyNoise.

Export as HTML, JSON, STIX 2.1, MISP or CSV. Two captures from the same
network can be compared: new hosts, new destinations, findings that
appeared and findings that went away.

---

## Notes

**Memory does not grow with the capture.** Flow, host and stream tables
have ceilings; once reached, WireCub keeps counting in aggregate and says
so in the report rather than growing until the machine gives out. A 1 GB
file takes about 90 seconds at roughly 900 MB, and a 10 GB one about
fifteen minutes at the same footprint. The local upload ceiling is 10 GB,
adjustable with `WIRECUB_MAX_UPLOAD`.

**Only the reputation feeds reach the internet**, and never during an
analysis. On an isolated machine everything else works unchanged.

**Locally there is no access control** unless you set `WIRECUB_ACCESS_KEY`.
Keep it on localhost, or put it behind something that authenticates.

**Upgrading from 1.3** moves the SQLite history into the new file-based
index on first start. Nothing needs doing by hand.

## Layout

```
index.py            Vercel entrypoint (re-exports backend/app.py)
vercel.json         function duration, daily cleanup cron, headers
backend/app.py      HTTP API: chunked upload, streamed analysis, reports
backend/storage.py  local disk or private Vercel Blob
backend/engine/     the analyser: reader, decoders, reassembly, detections
public/             the site (/) and the analyser (/app/)
tests/              run_tests.py (engine), api_test.py (HTTP), *.js (UI)
```
