"""
MAC address vendor lookup.

Ships with a compact built-in prefix table covering the vendors that
matter for asset identification. Fully offline: no lookup service, no
downloaded database.
"""

from __future__ import annotations

OUI_TABLE = {
    "000c29": "VMware", "005056": "VMware", "000569": "VMware",
    "001c14": "VMware", "0050c2": "IEEE Registration",
    "080027": "VirtualBox", "0a0027": "VirtualBox",
    "525400": "QEMU/KVM", "001a4a": "Red Hat/Qumranet",
    "00155d": "Microsoft Hyper-V", "0003ff": "Microsoft",
    "00163e": "Xen", "001dd8": "Microsoft",
    "0017fa": "Microsoft", "7c1e52": "Microsoft",
    "001b21": "Intel", "00a0c9": "Intel", "001517": "Intel",
    "00e04c": "Realtek", "525400": "QEMU", "001e67": "Intel",
    "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi",
    "e45f01": "Raspberry Pi", "28cdc1": "Raspberry Pi",
    "001a11": "Google", "3c5ab4": "Google", "f4f5d8": "Google",
    "d83134": "Roku", "b0a737": "Roku",
    "0025bc": "Apple", "3c0754": "Apple", "a45e60": "Apple",
    "f0189e": "Apple", "8c8590": "Apple", "9803d8": "Apple",
    "acbc32": "Apple", "d0817a": "Apple", "f81edf": "Apple",
    "001132": "Synology", "0011d8": "ASUSTek", "1c872c": "ASUSTek",
    "00248c": "ASUSTek", "2c56dc": "ASUSTek",
    "000e8f": "Cisco", "00000c": "Cisco", "001b54": "Cisco",
    "0026cb": "Cisco", "6400f1": "Cisco", "88908d": "Cisco",
    "000b86": "Aruba/HPE", "6cf37f": "Aruba/HPE",
    "001560": "HP", "3822d6": "HP", "0017a4": "HP",
    "001aa0": "Dell", "b8ca3a": "Dell", "f8bc12": "Dell",
    "d067e5": "Dell", "00219b": "Dell",
    "00248d": "Fortinet", "0009f5": "Fortinet", "085b0e": "Fortinet",
    "001c7f": "Check Point", "00e02b": "Extreme Networks",
    "000420": "Palo Alto", "b40c25": "Palo Alto",
    "001c23": "Dell", "0050f2": "Microsoft",
    "d8cb8a": "Micro-Star", "4ccc6a": "Micro-Star",
    "001fc6": "ASUSTek", "bcae c5": "ASUSTek",
    "e0d55e": "Giga-Byte", "1c6f65": "Giga-Byte",
    "70854d": "TP-Link", "5c899a": "TP-Link", "a42bb0": "TP-Link",
    "c46e1f": "TP-Link", "989096": "D-Link", "1cbdb9": "D-Link",
    "b0487a": "TP-Link", "001e58": "D-Link",
    "0018f3": "ASUSTek", "20cf30": "ASUSTek",
    "747548": "Amazon", "fc65de": "Amazon", "4c17eb": "Amazon",
    "68544b": "Samsung", "5001bb": "Samsung", "8425db": "Samsung",
    "002454": "Samsung", "e8508b": "Samsung",
    "0c8bfd": "Intel", "94659c": "Intel", "a0a8cd": "Intel",
    "001966": "Huawei", "48ad08": "Huawei", "781dba": "Huawei",
    "0c37dc": "Huawei", "e0247f": "Huawei",
    "3c286d": "Google", "94eb2c": "Google",
    "0004f2": "Polycom", "64167f": "Polycom",
    "00907f": "WatchGuard", "0090a9": "Western Digital",
    "0011d9": "TiVo", "00095b": "Netgear", "204e7f": "Netgear",
    "a04dc3": "Netgear", "9c3dcf": "Netgear",
    "0026f2": "Netgear", "e0469a": "Netgear",
    "001cc0": "Intel", "3417eb": "Dell", "144fd7": "Dell",
    "ffffff": "Broadcast",
}


def lookup_vendor(mac: str | None) -> str | None:
    """Return a vendor name for a MAC address, or None if unknown."""
    if not mac:
        return None
    clean = mac.replace(":", "").replace("-", "").replace(".", "").lower()
    if len(clean) < 6:
        return None
    if clean.startswith("ffffff"):
        return "Broadcast"
    if clean.startswith("01005e") or clean.startswith("3333"):
        return "Multicast"

    vendor = OUI_TABLE.get(clean[:6])
    if vendor:
        return vendor

    # Locally administered addresses are randomised or virtual.
    try:
        first_octet = int(clean[:2], 16)
        if first_octet & 0x02:
            return "Locally administered"
    except ValueError:
        return None
    return None


def is_randomised(mac: str | None) -> bool:
    """True for locally administered MACs, which modern clients randomise."""
    if not mac:
        return False
    clean = mac.replace(":", "").lower()
    try:
        return bool(int(clean[:2], 16) & 0x02)
    except (ValueError, IndexError):
        return False
