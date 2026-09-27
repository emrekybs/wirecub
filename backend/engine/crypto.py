"""
Minimal cryptographic primitives, in pure Python.

Exists for one job: decrypting QUIC Initial packets. Those are encrypted
with a key derived from a published salt and the connection ID that is
sitting in the packet header, so anyone can decrypt them — the encryption
protects against middlebox interference, not observation.

Doing that needs AES and GHASH, which the standard library does not
provide. Rather than take a compiled dependency for it, both are
implemented here. This is slow by cryptographic standards and entirely
unsuitable for bulk work, which is fine: it runs over a few hundred
handshake packets, never over traffic.

Not for protecting anything. No constant-time guarantees, no side-channel
resistance. Reading published handshakes only.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

# ---------------------------------------------------------------------------
# AES
# ---------------------------------------------------------------------------

_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
]

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D]


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


# Precomputed multiplication tables for MixColumns.
_MUL2 = [_xtime(i) for i in range(256)]
_MUL3 = [_xtime(i) ^ i for i in range(256)]


class AES:
    """AES block cipher. Encryption only: GCM and CTR never decrypt blocks."""

    __slots__ = ("_round_keys", "_rounds")

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        self._rounds = {16: 10, 24: 12, 32: 14}[len(key)]
        self._round_keys = self._expand(key)

    def _expand(self, key: bytes) -> list[list[int]]:
        key_words = len(key) // 4
        total_words = 4 * (self._rounds + 1)
        words = [list(key[i * 4:i * 4 + 4]) for i in range(key_words)]

        for i in range(key_words, total_words):
            temp = list(words[i - 1])
            if i % key_words == 0:
                temp = temp[1:] + temp[:1]
                temp = [_SBOX[b] for b in temp]
                temp[0] ^= _RCON[i // key_words - 1]
            elif key_words > 6 and i % key_words == 4:
                temp = [_SBOX[b] for b in temp]
            words.append([words[i - key_words][j] ^ temp[j] for j in range(4)])

        return [
            [byte for word in words[r * 4:r * 4 + 4] for byte in word]
            for r in range(self._rounds + 1)
        ]

    def encrypt_block(self, block: bytes) -> bytes:
        state = list(block)

        # Initial round key addition
        key = self._round_keys[0]
        for i in range(16):
            state[i] ^= key[i]

        for round_index in range(1, self._rounds + 1):
            state = [_SBOX[b] for b in state]

            # ShiftRows, operating on the column-major state layout
            state = [
                state[0], state[5], state[10], state[15],
                state[4], state[9], state[14], state[3],
                state[8], state[13], state[2], state[7],
                state[12], state[1], state[6], state[11],
            ]

            if round_index != self._rounds:
                mixed = []
                for c in range(4):
                    a0, a1, a2, a3 = state[c * 4:c * 4 + 4]
                    mixed.extend(
                        [
                            _MUL2[a0] ^ _MUL3[a1] ^ a2 ^ a3,
                            a0 ^ _MUL2[a1] ^ _MUL3[a2] ^ a3,
                            a0 ^ a1 ^ _MUL2[a2] ^ _MUL3[a3],
                            _MUL3[a0] ^ a1 ^ a2 ^ _MUL2[a3],
                        ]
                    )
                state = mixed

            key = self._round_keys[round_index]
            for i in range(16):
                state[i] ^= key[i]

        return bytes(state)


# ---------------------------------------------------------------------------
# CTR and GCM
# ---------------------------------------------------------------------------

def aes_ctr(key: bytes, nonce_counter: bytes, data: bytes) -> bytes:
    """AES in counter mode. Encryption and decryption are the same operation."""
    cipher = AES(key)
    out = bytearray()
    counter = int.from_bytes(nonce_counter, "big")

    for offset in range(0, len(data), 16):
        block = cipher.encrypt_block(
            counter.to_bytes(16, "big")
        )
        chunk = data[offset:offset + 16]
        out.extend(a ^ b for a, b in zip(chunk, block))
        counter = (counter + 1) & ((1 << 128) - 1)

    return bytes(out)


def _ghash(h: int, data: bytes) -> int:
    """GHASH over GF(2^128), used for the GCM authentication tag."""
    y = 0
    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16].ljust(16, b"\x00")
        y ^= int.from_bytes(block, "big")

        # Carry-less multiply by H, reduced by the GCM polynomial.
        z = 0
        v = h
        for i in range(127, -1, -1):
            if (y >> i) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ 0xE1000000000000000000000000000000
            else:
                v >>= 1
        y = z
    return y


def aes_gcm_decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes,
    verify: bool = True,
) -> bytes | None:
    """
    AES-GCM decryption.

    Returns the plaintext, or None when the tag does not verify. The last
    16 bytes of the ciphertext are taken as the tag.
    """
    if len(ciphertext) < 16:
        return None

    tag = ciphertext[-16:]
    body = ciphertext[:-16]

    cipher = AES(key)
    h = int.from_bytes(cipher.encrypt_block(b"\x00" * 16), "big")

    if len(nonce) == 12:
        j0 = nonce + b"\x00\x00\x00\x01"
    else:
        padded = nonce + b"\x00" * ((-len(nonce)) % 16)
        padded += b"\x00" * 8 + struct.pack(">Q", len(nonce) * 8)
        j0 = _ghash(h, padded).to_bytes(16, "big")

    if verify:
        padded_aad = aad + b"\x00" * ((-len(aad)) % 16)
        padded_body = body + b"\x00" * ((-len(body)) % 16)
        lengths = struct.pack(">QQ", len(aad) * 8, len(body) * 8)
        s = _ghash(h, padded_aad + padded_body + lengths)
        expected = bytes(
            a ^ b
            for a, b in zip(
                s.to_bytes(16, "big"), cipher.encrypt_block(j0)
            )
        )
        if not hmac.compare_digest(expected, tag):
            return None

    # Counter starts at J0 + 1 for the payload.
    counter = (int.from_bytes(j0, "big") + 1) & ((1 << 128) - 1)
    return aes_ctr(key, counter.to_bytes(16, "big"), body)


def aes_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Single-block ECB, used only for QUIC header protection masks."""
    return AES(key).encrypt_block(block)


# ---------------------------------------------------------------------------
# HKDF
# ---------------------------------------------------------------------------

def hkdf_extract(salt: bytes, key_material: bytes,
                 algorithm: str = "sha256") -> bytes:
    return hmac.new(salt, key_material, algorithm).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int,
                algorithm: str = "sha256") -> bytes:
    hash_len = hashlib.new(algorithm).digest_size
    blocks = b""
    previous = b""
    counter = 1
    while len(blocks) < length:
        previous = hmac.new(
            prk, previous + info + bytes([counter]), algorithm
        ).digest()
        blocks += previous
        counter += 1
        if counter > 255:
            break
    return blocks[:length]


def hkdf_expand_label(secret: bytes, label: str, context: bytes,
                      length: int, algorithm: str = "sha256") -> bytes:
    """
    TLS 1.3 HKDF-Expand-Label, which QUIC uses for its key schedule.

    The label is prefixed with "tls13 " and the whole structure is length
    prefixed, exactly as RFC 8446 defines it.
    """
    full_label = b"tls13 " + label.encode("ascii")
    info = (
        struct.pack(">H", length)
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )
    return hkdf_expand(secret, info, length, algorithm)
