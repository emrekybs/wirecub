# Tests

Two suites. Both generate their own fixtures, so nothing needs to be
downloaded and no real capture is required to verify a change.

## Backend

```bash
python3 tests/run_tests.py
```

## HTTP API

```bash
python3 tests/api_test.py http://127.0.0.1:8000 [access-key]
```

Runs against a live server the way the interface does: announces each
fixture, uploads it in chunks, reads the streamed analysis, then exercises
every report, export, history, compare and delete endpoint, and checks that
identifiers containing `..` or other path tricks are refused. Works the
same against a local server and a Vercel deployment.

Generates synthetic captures covering every decoder and detection path,
runs them through the full pipeline, and asserts what each should produce.
Also checks the cryptographic primitives against published vectors
(FIPS-197 for AES, NIST for GCM, RFC 9001 for the QUIC key schedule) —
a silent failure there would produce plausible wrong answers rather than
an obvious crash.

## Frontend

```bash
cd tests && npm install jsdom && node frontend_tests.js
```

Needs report JSON in a directory named by `WIRECUB_FETEST` (default
`/tmp/fetest`), which the backend produces: start the server, analyse a few
captures, then save `/api/history` as `history.json` and each
`/api/reports/{id}` as `report_{id}.json`.

Loads the real page in a DOM, drives every tab, expands findings, opens
the stream viewer, and checks that tabs appear only when they have data
and that user-controlled strings are escaped.

## Panel visibility

```bash
cd tests && node panel_visibility_test.js
```

Applies the real stylesheet in a DOM and reads computed styles for every
panel after each tab switch. This exists because a CSS rule can override
the `hidden` attribute and leave one panel permanently visible — a bug the
markup-only suite cannot see, since it never applies the cascade.

## Contrast

```bash
python3 tests/contrast_test.py
cd tests && node rendered_contrast_test.js
```

Two levels, because two separate colour bugs shipped from the same blind
spot. The first resolves the custom properties in the stylesheet and
computes the WCAG ratio for every rule that sets both a text and a
background colour. The second renders the whole interface, walks all
fifteen tabs, and measures every text node against the nearest ancestor
that actually paints a background — which is the only way to catch text
inheriting a background it was never written against, or a colour set
inline from JavaScript.

Both are needed. A stylesheet check cannot follow inheritance, and jsdom
returns the literal `var(--ink)` unless the variables are expanded first,
so a naive rendered check silently passes on an unreadable page.

## Fixture generators

Each writes captures into `/tmp` and can be run on its own:

| Script | Covers |
|---|---|
| `fixtures_scenario.py` | Beaconing, DNS tunneling, port scan, web attacks, cleartext credentials, ICMP tunnel, ARP spoofing, IPv6 TLS |
| `fixtures_windows_ics.py` | HTTP file download, NTLMv1 spraying, Kerberoasting, ransomware-rate SMB writes, Modbus, MQTT, QUIC, SSDP |
| `fixtures_smb.py` | A file transferred across SMB write operations, with a known hash |
| `fixtures_fragments.py` | IPv4 and IPv6 fragmented datagrams hiding a payload |
| `fixtures_linktypes.py` | 15 link types and encapsulations, one capture each |
| `fixtures_credentials.py` | FTP, Telnet (line and character mode), POP3, APOP, IMAP with each SASL mechanism, SMTP AUTH, HTTP Basic/Digest/NTLM |
| `fixtures_voip.py` | A full SIP call with RTP media and digest auth, plus a spoofed INVITE |
| `fixtures_wifi.py` | Deauthentication flood, evil twin, WPA handshake |
| `fixtures_large.py` | Configurable-size capture for performance work: `python3 fixtures_large.py 250` |
