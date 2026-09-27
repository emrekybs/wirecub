"""
End-to-end check of the HTTP API against a running server.

    python3 tests/api_test.py http://127.0.0.1:8000 [access-key]

Uploads the generated fixtures the way the interface does (announce, send
chunks, stream the analysis), then reads every report endpoint, compares,
deletes, and probes the identifier checks. Needs the fixtures in /tmp
(run tests/run_tests.py once, or any fixtures_*.py script).
"""

import gzip
import http.client
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"
KEY = sys.argv[2] if len(sys.argv) > 2 else ""
FAILED = []


def check(name, ok, detail=""):
    print(f"  {'ok  ' if ok else 'FAIL'}  {name}" + (f"  — {detail}" if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def call(method, path, body=None, headers=None, raw=False, key=True):
    headers = dict(headers or {})
    if KEY and key:
        headers["X-WireCub-Key"] = KEY
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(BASE + path, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=600) as response:
            data = response.read()
            if response.headers.get("Content-Encoding") == "gzip":
                data = gzip.decompress(data)
            return response.status, (data if raw else _decode(data)), response.headers
    except urllib.error.HTTPError as exc:
        data = exc.read()
        return exc.code, _decode(data), exc.headers


def _decode(data):
    try:
        return json.loads(data)
    except ValueError:
        return data


def raw_path(method, path):
    """Send a path exactly as written, without client-side normalisation."""
    parsed = urllib.parse.urlparse(BASE)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=30)
    headers = {"X-WireCub-Key": KEY} if KEY else {}
    conn.request(method, path, headers=headers)
    status = conn.getresponse().status
    conn.close()
    return status


def analyse(path, name=None):
    data = open(path, "rb").read()
    name = name or path.rsplit("/", 1)[-1]
    status, plan, _ = call("POST", "/api/uploads", {"filename": name, "size": len(data)})
    if status != 200:
        return None, f"announce {status} {plan}"
    size = plan["chunk_bytes"]
    for index in range(plan["chunks"]):
        status, body, _ = call("PUT", f"/api/uploads/{plan['upload_id']}/{index}",
                               data[index * size:(index + 1) * size],
                               {"Content-Type": "application/octet-stream"})
        if status != 200:
            return None, f"chunk {index}: {status} {body}"

    request = urllib.request.Request(
        f"{BASE}/api/uploads/{plan['upload_id']}/analyze",
        data=json.dumps({"filename": name, "size": len(data), "chunks": plan["chunks"]}).encode(),
        headers={"Content-Type": "application/json", **({"X-WireCub-Key": KEY} if KEY else {})},
        method="POST",
    )
    last = None
    progress = 0
    with urllib.request.urlopen(request, timeout=900) as response:
        for line in response:
            if not line.strip():
                continue
            event = json.loads(line)
            if event["type"] == "progress":
                progress += 1
            if event["type"] in ("done", "failed", "cancelled"):
                last = event
    if not last or last["type"] != "done":
        return None, f"outcome {last}"
    return last["job_id"], f"{progress} progress events"


def main():
    print(f"\nAPI test against {BASE}")
    status, config, _ = call("GET", "/api/config")
    check("config answers", status == 200 and "chunk_bytes" in config, str(config))
    check("store is ready", config.get("store_ready") is True, str(config.get("store_error")))

    if KEY:
        status, _, _ = call("GET", "/api/history", key=False)
        check("history refused without key", status == 401)
        status, _, _ = call("POST", "/api/auth", {"key": "wrong"}, key=False)
        check("wrong key refused", status == 401)

    ids = {}
    for fixture in ("scenario.pcapng", "scenario2.pcapng", "smb.pcapng", "credentials.pcapng"):
        job_id, detail = analyse(f"/tmp/{fixture}")
        check(f"analyse {fixture}", job_id is not None, detail)
        if job_id:
            ids[fixture] = job_id

    job = ids.get("scenario.pcapng")
    status, report, headers = call("GET", f"/api/reports/{job}", headers={"Accept-Encoding": "gzip"})
    check("report loads", status == 200 and report.get("findings"), str(status))
    check("report is sent compressed", headers.get("Content-Encoding") == "gzip")

    for fmt in ("html", "stix", "misp"):
        status, body, headers = call("GET", f"/api/reports/{job}/export/{fmt}", raw=True)
        check(f"export {fmt}", status == 200 and len(body) > 200, str(status))
    status, body, headers = call("GET", f"/api/reports/{job}/export/html", raw=True)
    check("html export carries CSP", "default-src 'none'" in headers.get("Content-Security-Policy", ""))
    for table in ("findings", "credentials", "hosts", "flows", "files", "iocs"):
        status, body, _ = call("GET", f"/api/reports/{job}/export/csv?table={table}", raw=True)
        check(f"export csv {table}", status == 200, str(status))
    status, _, _ = call("GET", f"/api/reports/{job}/view", raw=True)
    check("html view", status == 200)
    status, _, _ = call("GET", f"/api/reports/{job}/download", raw=True)
    check("json download", status == 200)

    status, rep, _ = call("GET", f"/api/reports/{job}/reputation")
    check("reputation answers", status == 200 and "verdicts" in rep, str(status))

    smb = ids.get("smb.pcapng")
    if smb:
        _, smb_report, _ = call("GET", f"/api/reports/{smb}")
        files = smb_report.get("files", [])
        if files:
            sha = files[0]["sha256"]
            status, body, headers = call("GET", f"/api/reports/{smb}/files/{sha}", raw=True)
            check("carved file downloads", status == 200 and len(body) > 0, str(status))
            check("carved file is an attachment",
                  "attachment" in headers.get("Content-Disposition", ""))
        else:
            check("smb fixture produced a file", False)

    status, history, _ = call("GET", "/api/history")
    check("history lists analyses", status == 200 and len(history) >= len(ids), str(status))

    a, b = ids.get("scenario.pcapng"), ids.get("scenario2.pcapng")
    status, diff, _ = call("GET", f"/api/compare?baseline={a}&current={b}")
    check("compare", status == 200 and "new_findings" in diff, str(status))

    # Identifier checks: nothing outside the namespace is reachable.
    check("delete '..' refused", raw_path("DELETE", "/api/history/..") in (400, 404, 405))
    check("delete '%2E%2E' refused", raw_path("DELETE", "/api/history/%2E%2E") in (400, 404))
    check("report '..' refused", raw_path("GET", "/api/reports/..%2F..%2Fetc") in (400, 404))
    check("bad upload id refused", raw_path("PUT", "/api/uploads/..%2Fx/0") in (400, 404, 405))
    status, _, _ = call("POST", "/api/uploads", {"filename": "a.exe", "size": 10})
    check("wrong file type refused", status == 400)
    status, _, _ = call("POST", "/api/uploads", {"filename": "a.pcap", "size": 10**13})
    check("oversize refused", status == 413)

    # A non-capture file is rejected with an explanation.
    status, plan, _ = call("POST", "/api/uploads", {"filename": "junk.pcap", "size": 100})
    call("PUT", f"/api/uploads/{plan['upload_id']}/0", b"x" * 100,
         {"Content-Type": "application/octet-stream"})
    request = urllib.request.Request(
        f"{BASE}/api/uploads/{plan['upload_id']}/analyze",
        data=json.dumps({"filename": "junk.pcap", "size": 100, "chunks": 1}).encode(),
        headers={"Content-Type": "application/json", **({"X-WireCub-Key": KEY} if KEY else {})},
        method="POST")
    with urllib.request.urlopen(request, timeout=60) as response:
        events = [json.loads(l) for l in response if l.strip()]
    check("non-capture fails cleanly", events[-1]["type"] == "failed", str(events[-1]))

    status, _, _ = call("DELETE", f"/api/history/{b}")
    check("delete analysis", status == 200)
    status, _, _ = call("GET", f"/api/reports/{b}")
    check("deleted report is gone", status == 404, str(status))

    print(f"\n{'all passed' if not FAILED else f'{len(FAILED)} failed: ' + ', '.join(FAILED)}")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
