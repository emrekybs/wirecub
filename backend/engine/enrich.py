"""
Offline address enrichment.

Answers "whose network is this?" without contacting anything. WireCub runs
on isolated networks, so a lookup that needs the internet is a lookup that
will not happen when it matters.

This is deliberately coarser than a commercial GeoIP database. It resolves
the regional registry, the operator of well-known ranges, and whether an
address belongs to cloud, anonymity or bulletproof infrastructure. It does
not claim city-level accuracy, because a bundled table cannot honestly
provide it and a wrong city on a report is worse than no city at all.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

# Regional internet registries by IPv4 first octet. Coarse but reliable:
# these allocations change rarely.
RIR_V4 = {
    "ARIN": [
        (3, 3), (4, 4), (6, 9), (11, 24), (26, 26), (28, 30), (32, 35),
        (38, 38), (40, 40), (44, 45), (47, 48), (50, 50), (52, 56),
        (63, 76), (96, 100), (104, 108), (128, 129), (130, 132),
        (134, 137), (139, 140), (142, 144), (146, 148), (152, 152),
        (155, 162), (164, 174), (184, 184), (192, 192), (198, 199),
        (204, 209), (216, 216),
    ],
    "RIPE": [
        (2, 2), (5, 5), (25, 25), (31, 31), (37, 37), (46, 46), (51, 51),
        (57, 57), (62, 62), (77, 95), (109, 109), (141, 141), (145, 145),
        (149, 149), (151, 151), (176, 178), (185, 188), (193, 195),
        (212, 213), (217, 217),
    ],
    "APNIC": [
        (1, 1), (14, 14), (27, 27), (36, 36), (39, 39), (42, 43),
        (49, 49), (58, 61), (101, 103), (110, 126), (133, 133),
        (150, 150), (153, 153), (163, 163), (171, 171), (175, 175),
        (180, 183), (202, 203), (210, 211), (218, 223),
    ],
    "LACNIC": [(179, 179), (181, 181), (186, 191), (200, 201)],
    "AFRINIC": [(41, 41), (102, 102), (105, 105), (154, 154), (196, 197)],
}

# Well-known ranges worth naming precisely. Kept short on purpose: these
# are the operators that show up in almost every investigation.
KNOWN_NETWORKS: list[tuple[str, str, str, str]] = [
    # (CIDR, operator, category, note)
    ("8.8.8.0/24",       "Google Public DNS",  "dns",   "Public resolver"),
    ("8.8.4.0/24",       "Google Public DNS",  "dns",   "Public resolver"),
    ("1.1.1.0/24",       "Cloudflare DNS",     "dns",   "Public resolver"),
    ("1.0.0.0/24",       "Cloudflare DNS",     "dns",   "Public resolver"),
    ("9.9.9.0/24",       "Quad9 DNS",          "dns",   "Public resolver"),
    ("208.67.222.0/24",  "OpenDNS",            "dns",   "Public resolver"),
    ("208.67.220.0/24",  "OpenDNS",            "dns",   "Public resolver"),
    ("13.32.0.0/15",     "Amazon CloudFront",  "cdn",   "Content delivery"),
    ("13.64.0.0/11",     "Microsoft Azure",    "cloud", "Cloud hosting"),
    ("20.0.0.0/8",       "Microsoft Azure",    "cloud", "Cloud hosting"),
    ("40.64.0.0/10",     "Microsoft Azure",    "cloud", "Cloud hosting"),
    ("52.0.0.0/8",       "Amazon AWS",         "cloud", "Cloud hosting"),
    ("54.0.0.0/8",       "Amazon AWS",         "cloud", "Cloud hosting"),
    ("3.0.0.0/9",        "Amazon AWS",         "cloud", "Cloud hosting"),
    ("18.192.0.0/11",    "Amazon AWS",         "cloud", "Cloud hosting"),
    ("34.64.0.0/10",     "Google Cloud",       "cloud", "Cloud hosting"),
    ("35.184.0.0/13",    "Google Cloud",       "cloud", "Cloud hosting"),
    ("104.16.0.0/12",    "Cloudflare",         "cdn",   "Content delivery"),
    ("172.64.0.0/13",    "Cloudflare",         "cdn",   "Content delivery"),
    ("162.158.0.0/15",   "Cloudflare",         "cdn",   "Content delivery"),
    ("151.101.0.0/16",   "Fastly",             "cdn",   "Content delivery"),
    ("199.232.0.0/16",   "Fastly",             "cdn",   "Content delivery"),
    ("23.32.0.0/11",     "Akamai",             "cdn",   "Content delivery"),
    ("104.64.0.0/10",    "Akamai",             "cdn",   "Content delivery"),
    ("157.240.0.0/16",   "Meta",               "service", "Social platform"),
    ("31.13.24.0/21",    "Meta",               "service", "Social platform"),
    ("140.82.112.0/20",  "GitHub",             "service", "Code hosting"),
    ("185.199.108.0/22", "GitHub Pages",       "service", "Static hosting"),
    ("45.32.0.0/12",     "Vultr",              "vps",   "Low-cost VPS"),
    ("45.76.0.0/14",     "Vultr",              "vps",   "Low-cost VPS"),
    ("45.77.0.0/16",     "Vultr",              "vps",   "Low-cost VPS"),
    ("64.176.0.0/12",    "Vultr",              "vps",   "Low-cost VPS"),
    ("104.238.128.0/17", "Vultr",              "vps",   "Low-cost VPS"),
    ("159.65.0.0/16",    "DigitalOcean",       "vps",   "Low-cost VPS"),
    ("165.227.0.0/16",   "DigitalOcean",       "vps",   "Low-cost VPS"),
    ("167.71.0.0/16",    "DigitalOcean",       "vps",   "Low-cost VPS"),
    ("134.209.0.0/16",   "DigitalOcean",       "vps",   "Low-cost VPS"),
    ("128.199.0.0/16",   "DigitalOcean",       "vps",   "Low-cost VPS"),
    ("139.59.0.0/16",    "DigitalOcean",       "vps",   "Low-cost VPS"),
    ("172.104.0.0/15",   "Linode",             "vps",   "Low-cost VPS"),
    ("139.162.0.0/16",   "Linode",             "vps",   "Low-cost VPS"),
    ("45.79.0.0/16",     "Linode",             "vps",   "Low-cost VPS"),
    ("176.9.0.0/16",     "Hetzner",            "vps",   "Low-cost VPS"),
    ("116.202.0.0/15",   "Hetzner",            "vps",   "Low-cost VPS"),
    ("144.76.0.0/16",    "Hetzner",            "vps",   "Low-cost VPS"),
    ("51.15.0.0/16",     "Scaleway",           "vps",   "Low-cost VPS"),
    ("163.172.0.0/16",   "Scaleway",           "vps",   "Low-cost VPS"),
    ("51.75.0.0/16",     "OVH",                "vps",   "Low-cost VPS"),
    ("54.36.0.0/16",     "OVH",                "vps",   "Low-cost VPS"),
    ("91.121.0.0/16",    "OVH",                "vps",   "Low-cost VPS"),
    # Ranges with a persistent reputation for hosting attack infrastructure.
    ("185.220.100.0/22", "Tor exit relays",    "anonymity",
     "Range widely used by Tor exit nodes"),
    ("185.220.96.0/22",  "Tor relays",         "anonymity",
     "Range widely used by Tor relays"),
    ("199.249.230.0/24", "Quintex / Tor",      "anonymity", "Tor relay hosting"),
    ("171.25.193.0/24",  "DFRI / Tor",         "anonymity", "Tor exit hosting"),
    ("45.15.156.0/22",   "Bulletproof hosting","suspicious",
     "Provider known for ignoring abuse reports"),
    ("194.26.29.0/24",   "Bulletproof hosting","suspicious",
     "Provider known for ignoring abuse reports"),
    ("5.188.206.0/24",   "Bulletproof hosting","suspicious",
     "Provider known for ignoring abuse reports"),
]

KNOWN_NETWORKS_V6: list[tuple[str, str, str, str]] = [
    ("2606:4700::/32", "Cloudflare",     "cdn",   "Content delivery"),
    ("2001:4860::/32", "Google",         "cloud", "Cloud and services"),
    ("2600:1f00::/24", "Amazon AWS",     "cloud", "Cloud hosting"),
    ("2620:1ec::/36",  "Microsoft",      "cloud", "Cloud hosting"),
    ("2a03:2880::/32", "Meta",           "service", "Social platform"),
    ("2001:678::/29",  "RIPE allocation","registry", "European allocation"),
]

# Special-purpose ranges defined by RFC rather than allocated to operators.
SPECIAL_RANGES = [
    ("0.0.0.0/8",        "This network",       "reserved"),
    ("10.0.0.0/8",       "Private network",    "private"),
    ("100.64.0.0/10",    "Carrier-grade NAT",  "cgnat"),
    ("127.0.0.0/8",      "Loopback",           "loopback"),
    ("169.254.0.0/16",   "Link-local",         "link-local"),
    ("172.16.0.0/12",    "Private network",    "private"),
    ("192.0.2.0/24",     "Documentation",      "documentation"),
    ("192.168.0.0/16",   "Private network",    "private"),
    ("198.18.0.0/15",    "Benchmark testing",  "reserved"),
    ("198.51.100.0/24",  "Documentation",      "documentation"),
    ("203.0.113.0/24",   "Documentation",      "documentation"),
    ("224.0.0.0/4",      "Multicast",          "multicast"),
    ("240.0.0.0/4",      "Reserved",           "reserved"),
    ("fc00::/7",         "Unique local",       "private"),
    ("fe80::/10",        "Link-local",         "link-local"),
    ("ff00::/8",         "Multicast",          "multicast"),
    ("2001:db8::/32",    "Documentation",      "documentation"),
]

_COMPILED = [(ipaddress.ip_network(cidr), *rest) for cidr, *rest in KNOWN_NETWORKS]
_COMPILED_V6 = [(ipaddress.ip_network(cidr), *rest) for cidr, *rest in KNOWN_NETWORKS_V6]
_SPECIAL = [(ipaddress.ip_network(cidr), *rest) for cidr, *rest in SPECIAL_RANGES]

# Country hints for the largest allocations, used only where confident.
COUNTRY_HINTS = {
    "Hetzner": "DE", "OVH": "FR", "Scaleway": "FR", "Vultr": "US",
    "DigitalOcean": "US", "Linode": "US", "Amazon AWS": "US",
    "Google Cloud": "US", "Microsoft Azure": "US", "Cloudflare": "US",
    "GitHub": "US", "Meta": "US", "Akamai": "US", "Fastly": "US",
}


@lru_cache(maxsize=32768)
def enrich(ip: str) -> dict:
    """
    Describe an address using only bundled data.

    Returns operator, category, registry and a short note. Fields are None
    rather than guessed when the tables cannot support an answer.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "valid": False}

    result = {
        "ip": ip,
        "valid": True,
        "version": address.version,
        "operator": None,
        "category": None,
        "registry": None,
        "country_hint": None,
        "note": None,
        "scope": "public",
    }

    for network, label, scope in _SPECIAL:
        if address.version == network.version and address in network:
            result.update({"operator": label, "category": scope, "scope": scope})
            return result

    table = _COMPILED if address.version == 4 else _COMPILED_V6
    for network, operator, category, note in table:
        if address in network:
            result.update(
                {
                    "operator": operator,
                    "category": category,
                    "note": note,
                    "country_hint": COUNTRY_HINTS.get(operator),
                }
            )
            break

    if address.version == 4:
        first_octet = int(str(address).split(".")[0])
        for registry, ranges in RIR_V4.items():
            if any(low <= first_octet <= high for low, high in ranges):
                result["registry"] = registry
                break
    else:
        prefix = int(address.exploded[:4], 16)
        if 0x2001 <= prefix <= 0x2001:
            result["registry"] = "IANA allocation"
        elif prefix in (0x2a00, 0x2a01, 0x2a02, 0x2a03, 0x2a04, 0x2a05, 0x2a06):
            result["registry"] = "RIPE"
        elif prefix in (0x2400, 0x2401, 0x2402, 0x2403, 0x2404, 0x2405, 0x2406, 0x2407):
            result["registry"] = "APNIC"
        elif prefix in (0x2600, 0x2601, 0x2602, 0x2603, 0x2604, 0x2605, 0x2606, 0x2607):
            result["registry"] = "ARIN"
        elif prefix in (0x2800, 0x2801, 0x2802, 0x2803):
            result["registry"] = "LACNIC"
        elif prefix in (0x2c00, 0x2c01):
            result["registry"] = "AFRINIC"

    return result


def is_anonymity_infrastructure(ip: str) -> bool:
    """True for addresses in ranges associated with Tor and similar."""
    return enrich(ip).get("category") == "anonymity"


def is_suspicious_hosting(ip: str) -> bool:
    """True for providers with a persistent abuse reputation."""
    return enrich(ip).get("category") in ("suspicious", "anonymity")


def is_cheap_vps(ip: str) -> bool:
    """
    True for low-cost VPS ranges.

    Not incriminating by itself: these providers host an enormous amount of
    legitimate infrastructure. It matters as a supporting signal when the
    same address is already flagged by a behavioural detection.
    """
    return enrich(ip).get("category") == "vps"


# Tor directory authorities are a fixed, publicly documented list, so a
# connection to one is a reliable indicator that a Tor client is running.
TOR_DIRECTORY_AUTHORITIES = {
    "128.31.0.39", "86.59.21.38", "194.109.206.212", "131.188.40.189",
    "193.23.244.244", "171.25.193.9", "154.35.175.225", "199.58.81.140",
    "204.13.164.118", "66.111.2.131",
}

TOR_PORTS = {9001, 9030, 9050, 9051, 9150}

# Default ports for consumer and corporate VPN protocols.
VPN_PORTS = {
    1194: "OpenVPN", 1723: "PPTP", 500: "IKE/IPsec", 4500: "IPsec NAT-T",
    51820: "WireGuard", 1701: "L2TP",
}
