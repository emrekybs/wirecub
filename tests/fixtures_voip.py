"""
SIP call with RTP media, plus a call with forged routing headers.

Covers the shape a VoIP investigation actually needs: who called whom,
whether it was answered, what codec carried the audio, and whether the
signalling was authenticated.
"""
import socket, struct, hashlib

pkts = []
t = 1700800000
A, B = '001122334455', '66778899aabb'


def eth(d, s, et, p): return bytes.fromhex(d) + bytes.fromhex(s) + struct.pack('!H', et) + p
def ip4(s, d, proto, p):
    return (struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(p), 1, 0x4000, 64, proto, 0)
            + socket.inet_aton(s) + socket.inet_aton(d) + p)
def udp(sp, dp, p): return struct.pack('!HHHH', sp, dp, 8 + len(p), 0) + p
def send(src, dst, sp, dp, payload, ts):
    pkts.append((ts, eth(A, B, 0x0800, ip4(src, dst, 17, udp(sp, dp, payload)))))


CALL = 'a84b4c76e66710@pbx.corp.local'
SDP = ("v=0\r\no=alice 2890844526 2890844526 IN IP4 10.20.0.10\r\ns=Call\r\n"
       "c=IN IP4 10.20.0.10\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0 8\r\n"
       "a=rtpmap:0 PCMU/8000\r\n")

send('10.20.0.10', '10.20.0.1', 5060, 5060,
     (f"INVITE sip:bob@corp.local SIP/2.0\r\nVia: SIP/2.0/UDP 10.20.0.10:5060\r\n"
      f"From: <sip:alice@corp.local>;tag=1\r\nTo: <sip:bob@corp.local>\r\n"
      f"Call-ID: {CALL}\r\nCSeq: 1 INVITE\r\nUser-Agent: SoftPhone 3.2\r\n"
      f"Content-Type: application/sdp\r\nContent-Length: {len(SDP)}\r\n\r\n{SDP}").encode(), t)

send('10.20.0.1', '10.20.0.10', 5060, 5060,
     (f"SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 10.20.0.10:5060\r\n"
      f"From: <sip:alice@corp.local>;tag=1\r\nTo: <sip:bob@corp.local>\r\n"
      f"Call-ID: {CALL}\r\nCSeq: 1 INVITE\r\n"
      f'WWW-Authenticate: Digest realm="corp.local", nonce="9c8e88df"\r\n'
      f"Content-Length: 0\r\n\r\n").encode(), t + 0.1)

send('10.20.0.10', '10.20.0.1', 5060, 5060,
     (f"INVITE sip:bob@corp.local SIP/2.0\r\nVia: SIP/2.0/UDP 10.20.0.10:5060\r\n"
      f"From: <sip:alice@corp.local>;tag=1\r\nTo: <sip:bob@corp.local>\r\n"
      f"Call-ID: {CALL}\r\nCSeq: 2 INVITE\r\nUser-Agent: SoftPhone 3.2\r\n"
      f'Authorization: Digest username="alice", realm="corp.local", '
      f'nonce="9c8e88df", uri="sip:bob@corp.local", '
      f'response="6629fae49393a05397450978507c4ef1"\r\n'
      f"Content-Type: application/sdp\r\nContent-Length: {len(SDP)}\r\n\r\n{SDP}").encode(), t + 0.2)

for status, reason, offset in ((180, "Ringing", 0.3), (200, "OK", 1.4)):
    send('10.20.0.1', '10.20.0.10', 5060, 5060,
         (f"SIP/2.0 {status} {reason}\r\nVia: SIP/2.0/UDP 10.20.0.10:5060\r\n"
          f"From: <sip:alice@corp.local>;tag=1\r\nTo: <sip:bob@corp.local>;tag=9\r\n"
          f"Call-ID: {CALL}\r\nCSeq: 2 INVITE\r\nUser-Agent: Asterisk PBX 18\r\n"
          f"Content-Length: 0\r\n\r\n").encode(), t + offset)

# 300 RTP packets each way: G.711 u-law, 20 ms frames
for i in range(300):
    for src, dst, sp, dp, ssrc in (('10.20.0.10', '10.20.0.20', 40000, 40002, 0x1111AAAA),
                                   ('10.20.0.20', '10.20.0.10', 40002, 40000, 0x2222BBBB)):
        hdr = struct.pack('!BBHII', 0x80, 0, i & 0xFFFF, i * 160, ssrc)
        send(src, dst, sp, dp, hdr + b'\xff' * 160, t + 1.5 + i * 0.02)

send('10.20.0.10', '10.20.0.1', 5060, 5060,
     (f"BYE sip:bob@corp.local SIP/2.0\r\nVia: SIP/2.0/UDP 10.20.0.10:5060\r\n"
      f"From: <sip:alice@corp.local>;tag=1\r\nTo: <sip:bob@corp.local>;tag=9\r\n"
      f"Call-ID: {CALL}\r\nCSeq: 3 BYE\r\nContent-Length: 0\r\n\r\n").encode(), t + 8.0)

# A spoofed INVITE: Via names a host the packet did not come from.
send('10.20.0.99', '10.20.0.1', 5060, 5060,
     ("INVITE sip:@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 10.20.0.45\r\n"
      "From: \"spoof\"<sip:10.20.0.45>\r\nTo: <sip:victim@corp.local>\r\n"
      "Call-ID: spoofed-999\r\nCSeq: 1 INVITE\r\nContact: <sip:127.0.0.1>\r\n"
      "Content-Length: 0\r\n\r\n").encode(), t + 9.0)

pkts.sort(key=lambda x: x[0])
with open('/tmp/voip.pcapng', 'wb') as f:
    f.write(struct.pack('<IIIHHq', 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1) + struct.pack('<I', 28))
    f.write(struct.pack('<III', 0x00000001, 20, 1) + struct.pack('<I', 65535) + struct.pack('<I', 20))
    for ts, data in pkts:
        pad = (-len(data)) % 4; us = int(ts * 1_000_000); blen = 32 + len(data) + pad
        f.write(struct.pack('<IIIIIII', 0x00000006, blen, 0, us >> 32, us & 0xffffffff, len(data), len(data)))
        f.write(data + b'\x00' * pad); f.write(struct.pack('<I', blen))
print(f'voip fixture: {len(pkts)} packets -> /tmp/voip.pcapng')
