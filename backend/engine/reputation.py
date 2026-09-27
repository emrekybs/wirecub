"""
Indicator reputation, without API keys.

Every source here publishes a plain list over HTTP with no registration,
no key and no per-query quota. That constraint is deliberate: a tool that
needs an account before it can answer is a tool that stops working the
moment someone runs it on an isolated network or forgets to renew a key.

The design is cache-first. Feeds are downloaded once, written to disk, and
matched locally from then on. Analysis never blocks on the network: if a
feed is missing or stale it is simply reported as such, and the verdict
says so rather than pretending to certainty it does not have.

None of this is a substitute for a commercial intelligence platform. What
it gives you is the answer to "is this address already publicly known as
bad", which is the question most worth asking before spending an hour on
an alert.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

USER_AGENT = "WireCub/1.0 (+offline pcap analysis)"
FETCH_TIMEOUT = 20
DEFAULT_MAX_AGE = 24 * 3600


@dataclass
class Feed:
    """One public blocklist."""

    name: str
    url: str
    kind: str                 # ip | domain | url
    description: str
    severity: str             # what a hit implies
    parser: str = "lines"     # lines | csv | cidr
    column: int = 0


# Ordered roughly by how specific a hit is. A Feodo hit names a botnet
# controller; a blocklist.de hit means somebody's honeypot saw an attack.
FEEDS: list[Feed] = [
    Feed(
        "Feodo Tracker",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "ip",
        "Command and control servers for Dridex, Emotet, TrickBot and "
        "QakBot, tracked by abuse.ch.",
        "critical",
    ),
    Feed(
        "SSL Blacklist",
        "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "ip",
        "Addresses serving TLS certificates associated with botnet command "
        "and control.",
        "critical",
    ),
    Feed(
        "URLhaus",
        "https://urlhaus.abuse.ch/downloads/text_online/",
        "url",
        "URLs actively distributing malware, maintained by abuse.ch.",
        "critical",
    ),
    Feed(
        "Emerging Threats compromised",
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "ip",
        "Hosts observed compromised and used in attacks.",
        "high",
    ),
    Feed(
        "CINS Army",
        "https://cinsscore.com/list/ci-badguys.txt",
        "ip",
        "Addresses with a poor reputation across the CINS sensor network.",
        "high",
    ),
    Feed(
        "Blocklist.de",
        "https://lists.blocklist.de/lists/all.txt",
        "ip",
        "Addresses reported for attacking honeypots and public services in "
        "the last 48 hours.",
        "medium",
    ),
    Feed(
        "Spamhaus DROP",
        "https://www.spamhaus.org/drop/drop.txt",
        "ip",
        "Networks Spamhaus considers wholly controlled by criminal "
        "operations. Ranges, not single addresses.",
        "high",
        parser="cidr",
    ),
    Feed(
        "Tor exit nodes",
        "https://check.torproject.org/torbulkexitlist",
        "ip",
        "Current Tor exit relays.",
        "medium",
    ),
    Feed(
        "Phishing Army",
        "https://phishing.army/download/phishing_army_blocklist.txt",
        "domain",
        "Domains used in phishing campaigns.",
        "high",
    ),
    Feed(
        "OpenPhish",
        "https://openphish.com/feed.txt",
        "url",
        "Phishing URLs observed in the wild.",
        "high",
    ),
]

# DNS blocklists answer over plain DNS with no key. A hit is one signal
# among several, not a verdict on its own.
DNSBL_ZONES = [
    ("zen.spamhaus.org", "Spamhaus ZEN",
     "Listed by Spamhaus for spam, exploited hosts or policy reasons."),
    ("bl.spamcop.net", "SpamCop",
     "Reported to SpamCop for sending spam."),
    ("b.barracudacentral.org", "Barracuda",
     "Poor sending reputation according to Barracuda."),
    ("dnsbl.sorbs.net", "SORBS",
     "Listed by SORBS, often for open relays or compromised hosts."),
]


@dataclass
class Verdict:
    """What the local intelligence says about one indicator."""

    indicator: str
    kind: str
    listed: bool = False
    sources: list[dict] = field(default_factory=list)
    worst_severity: str = "info"
    checked_feeds: int = 0
    stale_feeds: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "indicator": self.indicator,
            "kind": self.kind,
            "listed": self.listed,
            "sources": self.sources,
            "worst_severity": self.worst_severity,
            "checked_feeds": self.checked_feeds,
            "stale_feeds": self.stale_feeds,
        }


# Largest public list is a few megabytes; anything far beyond is not a feed.
MAX_FEED_BYTES = 64 * 1024 * 1024

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class ReputationStore:
    """
    Holds downloaded feeds and answers lookups from memory.

    Feeds are loaded from disk at construction. Refreshing is an explicit
    action rather than something that happens during analysis, because an
    analysis that silently waits on ten HTTP requests is an analysis that
    appears to hang.
    """

    def __init__(self, cache_dir: str | os.PathLike):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ip_sets: dict[str, set[str]] = {}
        self.cidr_sets: dict[str, list] = {}
        self.domain_sets: dict[str, set[str]] = {}
        self.url_hosts: dict[str, set[str]] = {}
        self.meta: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._refresh_lock = threading.Lock()
        self.load()

    # -- persistence --------------------------------------------------------

    def _path(self, feed: Feed) -> Path:
        safe = re.sub(r"[^a-z0-9]+", "-", feed.name.lower()).strip("-")
        return self.cache_dir / f"{safe}.txt"

    def _meta_path(self) -> Path:
        return self.cache_dir / "feeds.json"

    def load(self) -> None:
        """Read whatever is already cached. Never touches the network."""
        try:
            if self._meta_path().exists():
                self.meta = json.loads(self._meta_path().read_text())
        except (OSError, ValueError):
            self.meta = {}

        for feed in FEEDS:
            path = self._path(feed)
            if not path.exists():
                continue
            try:
                self._ingest(feed, path.read_text(errors="replace"))
            except OSError:
                continue

    def _ingest(self, feed: Feed, text: str) -> int:
        """Parse one feed's contents into the matching lookup structure."""
        values: set[str] = set()
        networks = []

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";", "//")):
                continue

            if feed.parser == "cidr":
                # Spamhaus DROP lines are "1.2.3.0/24 ; SBL123"
                candidate = line.split(";")[0].strip()
                try:
                    networks.append(ipaddress.ip_network(candidate, strict=False))
                except ValueError:
                    continue
                continue

            if feed.kind == "url":
                # Store the host portion: matching whole URLs against
                # observed traffic almost never hits, but the host does.
                host = _host_from_url(line)
                if host:
                    values.add(host)
                continue

            value = line.split()[0].split(",")[0].strip().lower()
            if feed.kind == "ip":
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue
                values.add(value)
            else:
                if "." in value and " " not in value:
                    values.add(value.lstrip("*."))

        with self._lock:
            if feed.parser == "cidr":
                self.cidr_sets[feed.name] = networks
                return len(networks)
            if feed.kind == "ip":
                self.ip_sets[feed.name] = values
            elif feed.kind == "url":
                self.url_hosts[feed.name] = values
            else:
                self.domain_sets[feed.name] = values
        return len(values)

    # -- refresh ------------------------------------------------------------

    def refresh(self, max_age: int = DEFAULT_MAX_AGE,
                force: bool = False,
                progress=None) -> dict:
        """
        Download feeds that are missing or older than max_age.

        Returns a per-feed report. Failures are recorded rather than
        raised: one unreachable feed should not stop the other nine.
        """
        # Two refreshes at once (a double click, two tabs) would write the
        # same files and mutate meta while it is being serialised.
        with self._refresh_lock:
            return self._refresh(max_age, force, progress)

    def _refresh(self, max_age: int, force: bool, progress) -> dict:
        report = {}
        now = time.time()

        for index, feed in enumerate(FEEDS):
            entry = self.meta.get(feed.name, {})
            age = now - entry.get("fetched_at", 0)
            path = self._path(feed)

            if not force and path.exists() and age < max_age:
                report[feed.name] = {
                    "status": "current",
                    "entries": entry.get("entries", 0),
                    "age_hours": round(age / 3600, 1),
                }
                continue

            if progress:
                progress(index / len(FEEDS), f"Updating {feed.name}")

            try:
                request = urllib.request.Request(
                    feed.url, headers={"User-Agent": USER_AGENT}
                )
                with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:
                    raw = response.read(MAX_FEED_BYTES + 1)
                if len(raw) > MAX_FEED_BYTES:
                    raise ValueError("feed is larger than expected; not stored")
                text = raw.decode("utf-8", "replace")
                if len(text) < 32:
                    raise ValueError("feed returned no usable content")
                path.write_text(text)
                count = self._ingest(feed, text)
                self.meta[feed.name] = {
                    "fetched_at": now,
                    "entries": count,
                    "url": feed.url,
                }
                report[feed.name] = {"status": "updated", "entries": count}
            except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
                report[feed.name] = {
                    "status": "failed",
                    "error": str(exc)[:200],
                    "using_cache": path.exists(),
                    "entries": entry.get("entries", 0),
                }

        try:
            self._meta_path().write_text(json.dumps(self.meta, indent=2))
        except OSError:
            pass

        return report

    # -- lookup -------------------------------------------------------------

    @property
    def ready(self) -> bool:
        return bool(self.ip_sets or self.domain_sets or self.url_hosts
                    or self.cidr_sets)

    def feed_status(self) -> list[dict]:
        now = time.time()
        rows = []
        for feed in FEEDS:
            entry = self.meta.get(feed.name, {})
            fetched = entry.get("fetched_at")
            rows.append(
                {
                    "name": feed.name,
                    "description": feed.description,
                    "kind": feed.kind,
                    "severity": feed.severity,
                    "entries": entry.get("entries", 0),
                    "fetched_at": fetched,
                    "age_hours": round((now - fetched) / 3600, 1) if fetched else None,
                    "cached": self._path(feed).exists(),
                }
            )
        return rows

    def check_ip(self, ip: str) -> Verdict:
        verdict = Verdict(indicator=ip, kind="ip")
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return verdict
        if address.is_private or address.is_loopback or address.is_multicast:
            return verdict

        lowered = ip.lower()
        for feed in FEEDS:
            if feed.kind != "ip":
                continue
            if feed.parser == "cidr":
                networks = self.cidr_sets.get(feed.name)
                if networks is None:
                    continue
                verdict.checked_feeds += 1
                for network in networks:
                    if address.version == network.version and address in network:
                        self._record(verdict, feed, f"within {network}")
                        break
            else:
                values = self.ip_sets.get(feed.name)
                if values is None:
                    continue
                verdict.checked_feeds += 1
                if lowered in values:
                    self._record(verdict, feed, "listed")

        self._note_staleness(verdict)
        return verdict

    def check_domain(self, domain: str) -> Verdict:
        verdict = Verdict(indicator=domain, kind="domain")
        name = domain.lower().rstrip(".")
        if not name or "." not in name:
            return verdict

        # Check the name and its parents, so a hit on evil.example matches
        # sub.evil.example too.
        labels = name.split(".")
        candidates = {
            ".".join(labels[i:]) for i in range(len(labels) - 1)
        }

        for feed in FEEDS:
            if feed.kind == "domain":
                values = self.domain_sets.get(feed.name)
            elif feed.kind == "url":
                values = self.url_hosts.get(feed.name)
            else:
                continue
            if values is None:
                continue
            verdict.checked_feeds += 1
            hit = candidates & values
            if hit:
                self._record(verdict, feed, f"matched {sorted(hit)[0]}")

        self._note_staleness(verdict)
        return verdict

    def _record(self, verdict: Verdict, feed: Feed, detail: str) -> None:
        verdict.listed = True
        verdict.sources.append(
            {
                "feed": feed.name,
                "severity": feed.severity,
                "detail": detail,
                "description": feed.description,
                "fetched_at": self.meta.get(feed.name, {}).get("fetched_at"),
            }
        )
        if SEVERITY_ORDER[feed.severity] > SEVERITY_ORDER[verdict.worst_severity]:
            verdict.worst_severity = feed.severity

    def _note_staleness(self, verdict: Verdict) -> None:
        """Flag feeds old enough that a clean result means less."""
        now = time.time()
        for feed in FEEDS:
            entry = self.meta.get(feed.name, {})
            fetched = entry.get("fetched_at")
            if fetched and now - fetched > 7 * 24 * 3600:
                verdict.stale_feeds.append(feed.name)


# ---------------------------------------------------------------------------
# DNS blocklists
# ---------------------------------------------------------------------------

def check_dnsbl(ip: str, timeout: float = 2.0) -> list[dict]:
    """
    Query DNS blocklists.

    Needs no key and no account, just outbound DNS. Only IPv4 is supported
    because that is what these zones index.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return []
    if address.version != 4 or address.is_private:
        return []

    reversed_ip = ".".join(reversed(ip.split(".")))
    hits = []
    # gethostbyname ignores socket timeouts, and changing the process-wide
    # default from a worker thread races every other socket in the server.
    # Callers run this off the event loop instead.
    for zone, name, description in DNSBL_ZONES:
        try:
            socket.gethostbyname(f"{reversed_ip}.{zone}")
            hits.append(
                {
                    "feed": name,
                    "severity": "medium",
                    "detail": "DNS blocklist hit",
                    "description": description,
                }
            )
        except (socket.gaierror, socket.timeout, OSError):
            continue

    return hits


def _host_from_url(url: str) -> str | None:
    """Extract the host from a URL without importing a full parser."""
    text = url.strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].split("?", 1)[0]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    # Strip a port, but not an IPv6 literal's colons.
    if text.count(":") == 1:
        text = text.split(":", 1)[0]
    text = text.strip("[]").lower()
    return text or None


# ---------------------------------------------------------------------------
# Applying reputation to a completed analysis
# ---------------------------------------------------------------------------

def enrich_report(result, store: ReputationStore, use_dnsbl: bool = False,
                  limit: int = 400) -> dict:
    """
    Check every external address and observed domain against local feeds.

    Runs after analysis rather than during it, so a missing or slow feed
    never delays the result the user is waiting for.
    """
    if not store.ready:
        return {
            "available": False,
            "reason": "No reputation feeds cached. Update them from the "
                      "Reputation tab; it needs no account or API key.",
            "verdicts": [],
            "feeds": store.feed_status(),
        }

    verdicts: list[dict] = []
    checked = 0

    for ip, host in result.hosts.items():
        if host.is_private or checked >= limit:
            continue
        checked += 1
        verdict = store.check_ip(ip)
        if use_dnsbl and not verdict.listed:
            for hit in check_dnsbl(ip):
                verdict.listed = True
                verdict.sources.append(hit)
                if SEVERITY_ORDER[hit["severity"]] > SEVERITY_ORDER[verdict.worst_severity]:
                    verdict.worst_severity = hit["severity"]
        if verdict.listed:
            verdicts.append(verdict.to_dict())

    seen_domains = set()
    for record in result.dns_records:
        for query in record.get("queries", []):
            name = query.get("name", "").lower()
            if not name or name in seen_domains or len(seen_domains) >= limit:
                continue
            seen_domains.add(name)
            verdict = store.check_domain(name)
            if verdict.listed:
                verdicts.append(verdict.to_dict())

    for record in result.http_records:
        host_header = (record.get("host") or "").lower()
        if host_header and host_header not in seen_domains and len(seen_domains) < limit:
            seen_domains.add(host_header)
            verdict = store.check_domain(host_header)
            if verdict.listed:
                verdicts.append(verdict.to_dict())

    verdicts.sort(
        key=lambda v: -SEVERITY_ORDER.get(v["worst_severity"], 0)
    )

    return {
        "available": True,
        "verdicts": verdicts,
        "addresses_checked": checked,
        "domains_checked": len(seen_domains),
        "feeds": store.feed_status(),
        "dnsbl_used": use_dnsbl,
    }


# ---------------------------------------------------------------------------
# Live address lookup, still without a key
# ---------------------------------------------------------------------------

# Two services answer per-address questions with no account and no key.
#
# ip-api.com returns the operator, the autonomous system, the country, and
# three flags that matter here: whether the address belongs to a hosting
# provider, an anonymising proxy, or a mobile network. A workstation
# beaconing to a hosting address is a different proposition from one
# talking to a residential line.
#
# RDAP is the registries' own successor to whois. It gives the allocation
# name, the abuse contact, and the registration date. A destination whose
# network was registered last month deserves more attention than one
# registered in 1998.
IP_API_BATCH = "http://ip-api.com/batch"
IP_API_FIELDS = (
    "status,message,query,country,countryCode,regionName,city,isp,org,as,"
    "asname,reverse,mobile,proxy,hosting"
)
RDAP_BOOTSTRAP = "https://rdap.org/ip/"

# Where an analyst goes next. No key needed to open any of these, which is
# the point: the tool hands over a link rather than pretending it can do
# the whole judgement itself.
def pivot_links(indicator: str, kind: str = "ip") -> list[dict]:
    """Search links for manual follow-up, none requiring an account."""
    indicator = urllib.parse.quote(str(indicator), safe=".:-_")
    if kind == "ip":
        return [
            {"name": "VirusTotal", "url": f"https://www.virustotal.com/gui/ip-address/{indicator}"},
            {"name": "AbuseIPDB", "url": f"https://www.abuseipdb.com/check/{indicator}"},
            {"name": "Shodan", "url": f"https://www.shodan.io/host/{indicator}"},
            {"name": "GreyNoise", "url": f"https://viz.greynoise.io/ip/{indicator}"},
            {"name": "RDAP registry", "url": f"https://rdap.org/ip/{indicator}"},
            {"name": "ThreatFox", "url": f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{indicator}"},
        ]
    return [
        {"name": "VirusTotal", "url": f"https://www.virustotal.com/gui/domain/{indicator}"},
        {"name": "URLhaus", "url": f"https://urlhaus.abuse.ch/browse.php?search={indicator}"},
        {"name": "crt.sh certificates", "url": f"https://crt.sh/?q={indicator}"},
        {"name": "URLScan", "url": f"https://urlscan.io/search/#{indicator}"},
    ]


def lookup_addresses(addresses: list[str], timeout: int = 15) -> dict[str, dict]:
    """
    Ask ip-api.com about a batch of addresses.

    Batched because the service allows 100 per request and rate limits by
    request rather than by address. Returns whatever came back; a failure
    is reported as an empty result rather than raised, since this is
    enrichment and must never be the reason an analysis fails.
    """
    results: dict[str, dict] = {}
    public = []
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed.is_private or parsed.is_loopback or parsed.is_multicast:
            continue
        public.append(address)

    for start in range(0, len(public), 100):
        chunk = public[start:start + 100]
        payload = json.dumps(
            [{"query": ip, "fields": IP_API_FIELDS} for ip in chunk]
        ).encode()
        try:
            request = urllib.request.Request(
                IP_API_BATCH,
                data=payload,
                headers={
                    "User-Agent": USER_AGENT,
                    "Content-Type": "application/json",
                },
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                entries = json.loads(response.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            break

        for entry in entries:
            if not isinstance(entry, dict) or entry.get("status") != "success":
                continue
            address = entry.get("query")
            if not address:
                continue
            results[address] = {
                "country": entry.get("country"),
                "country_code": entry.get("countryCode"),
                "city": entry.get("city"),
                "region": entry.get("regionName"),
                "isp": entry.get("isp"),
                "organisation": entry.get("org"),
                "asn": entry.get("as"),
                "asn_name": entry.get("asname"),
                "reverse_dns": entry.get("reverse"),
                "hosting": bool(entry.get("hosting")),
                "proxy": bool(entry.get("proxy")),
                "mobile": bool(entry.get("mobile")),
            }

    return results


def lookup_rdap(address: str, timeout: int = 10) -> dict | None:
    """Fetch registry allocation details for one address."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if not parsed.is_global:
        return None
    try:
        request = urllib.request.Request(
            RDAP_BOOTSTRAP + str(parsed), headers={"User-Agent": USER_AGENT}
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None

    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    abuse = None
    for entity in data.get("entities", []):
        roles = entity.get("roles") or []
        if "abuse" in roles:
            for item in entity.get("vcardArray", [[], []])[1:]:
                for field in item:
                    if field and field[0] == "email":
                        abuse = field[3]
                        break
    return {
        "network_name": data.get("name"),
        "handle": data.get("handle"),
        "range": f"{data.get('startAddress')} – {data.get('endAddress')}"
                 if data.get("startAddress") else None,
        "country": data.get("country"),
        "type": data.get("type"),
        "registered": events.get("registration"),
        "last_changed": events.get("last changed"),
        "abuse_contact": abuse,
    }


def score_address(verdict: dict, context: dict | None) -> tuple[int, list[str]]:
    """
    Turn feed hits and network context into a 0-100 score with reasons.

    The reasons matter more than the number. A score with no explanation
    is a number an analyst has to take on trust, and this one is built
    from public lists and coarse network facts rather than anything that
    justifies that trust.
    """
    score = 0
    reasons: list[str] = []

    severity_points = {"critical": 55, "high": 35, "medium": 18, "low": 8}
    for source in verdict.get("sources", []):
        points = severity_points.get(source.get("severity"), 5)
        score += points
        reasons.append(f"Listed by {source['feed']} (+{points})")

    if context:
        if context.get("proxy"):
            score += 20
            reasons.append("Address is a known proxy, VPN or Tor node (+20)")
        if context.get("hosting"):
            score += 8
            reasons.append(
                "Belongs to a hosting provider rather than an access "
                "network (+8)"
            )
        if not context.get("reverse_dns"):
            score += 4
            reasons.append("No reverse DNS record (+4)")

    if not reasons:
        reasons.append("Nothing known against this address.")

    return min(100, score), reasons
