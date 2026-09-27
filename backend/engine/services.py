"""Port to service-name mapping, plus flags for protocols worth noticing."""

from __future__ import annotations

TCP_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    43: "WHOIS", 53: "DNS", 79: "Finger", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 111: "RPC", 113: "Ident", 119: "NNTP", 135: "MSRPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP",
    161: "SNMP", 179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "ISAKMP", 512: "rexec", 513: "rlogin", 514: "syslog",
    515: "LPD", 543: "klogin", 544: "kshell", 548: "AFP", 554: "RTSP",
    587: "SMTP-Sub", 593: "MSRPC-HTTP", 623: "IPMI", 636: "LDAPS",
    873: "rsync", 990: "FTPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 1883: "MQTT", 2049: "NFS", 2082: "cPanel",
    2375: "Docker", 2376: "Docker-TLS", 3128: "Squid", 3268: "LDAP-GC",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4444: "Metasploit",
    4789: "VXLAN", 5000: "UPnP", 5432: "PostgreSQL", 5555: "ADB",
    5601: "Kibana", 5900: "VNC", 5985: "WinRM", 5986: "WinRM-TLS",
    6379: "Redis", 6667: "IRC", 7001: "WebLogic", 8000: "HTTP-Alt",
    8008: "HTTP-Alt", 8080: "HTTP-Proxy", 8081: "HTTP-Alt",
    8088: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9000: "HTTP-Alt", 9001: "Tor-OR", 9030: "Tor-Dir", 9050: "Tor-SOCKS",
    9200: "Elasticsearch", 9300: "Elasticsearch", 10000: "Webmin",
    11211: "Memcached", 27017: "MongoDB", 3333: "Stratum",
    4445: "Stratum", 14444: "Stratum", 45560: "Stratum",
}

UDP_SERVICES = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 88: "Kerberos",
    123: "NTP", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 161: "SNMP",
    162: "SNMP-Trap", 389: "LDAP", 443: "QUIC", 500: "ISAKMP",
    514: "syslog", 520: "RIP", 623: "IPMI", 1194: "OpenVPN",
    1900: "SSDP", 3478: "STUN", 4500: "IPsec-NAT", 4789: "VXLAN",
    5060: "SIP", 5353: "mDNS", 5355: "LLMNR", 6081: "Geneve",
    51820: "WireGuard",
}

# Protocols that carry credentials or content with no transport encryption
CLEARTEXT_SERVICES = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP", 110: "POP3",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 512: "rexec", 513: "rlogin",
    514: "syslog", 69: "TFTP",
}

# Ports commonly used by remote-access and lateral-movement tooling
LATERAL_SERVICES = {
    135: "MSRPC", 139: "NetBIOS-SSN", 445: "SMB", 3389: "RDP",
    5985: "WinRM", 5986: "WinRM-TLS", 22: "SSH", 5900: "VNC",
}

# Ports strongly associated with cryptocurrency mining pools
MINING_PORTS = {3333, 4444, 4445, 5555, 7777, 8888, 14444, 45560, 45700}


def service_name(port: int, proto: str) -> str:
    """Best-effort service label for a port."""
    if not port:
        return proto
    table = UDP_SERVICES if proto == "UDP" else TCP_SERVICES
    name = table.get(port)
    if name:
        return name
    if port >= 49152:
        return "Ephemeral"
    return f"{proto}/{port}"


def is_cleartext(port: int) -> str | None:
    return CLEARTEXT_SERVICES.get(port)


def is_lateral(port: int) -> str | None:
    return LATERAL_SERVICES.get(port)
