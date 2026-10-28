#!/usr/bin/env python3
"""Craft a real ESP AES-GCM frame exactly per gcm_kat: outer IPv4(20) +
SPI(4)+SEQ(4) + IV(8) + AES-GCM(ct||ICV), where ct = inner(28)+ESPtrailer(4),
AAD = SPI||SEQ (8 B, RFC 4106), nonce = salt(4)||wire-IV(8).  Send on the
VDUSE outer netdev so the forwarder decrypts + delivers inner to the tap."""
import socket, struct, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENCKEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f10111213")
KEY16, SALT = ENCKEY[:16], ENCKEY[16:20]
SPI = 0xBABE0001
SEQ = 1
iface = sys.argv[1] if len(sys.argv) > 1 else "eth1"

inner = bytearray()
inner += struct.pack(">BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, 1, 0,
                     socket.inet_aton("10.0.1.1"), socket.inet_aton("10.0.2.1"))
inner += b"\x08\x00\x00\x00" + struct.pack(">HH", 0x1234, 0x5678)
def cks(b):
    if len(b) % 2: b += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(b)//2), b))
    s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff
inner[10:12] = struct.pack(">H", cks(bytes(inner)))

trailer = b"\x00\x00\x00\x01"          # padlen=0, next_hdr=1 (ICMP)
plain = bytes(inner) + trailer
iv8 = b"\x01\x02\x03\x04\x05\x06\x07\x08"
nonce = SALT + iv8
aad = struct.pack(">II", SPI, SEQ)
aes = AESGCM(KEY16)
ct_icv = aes.encrypt(nonce, plain, aad)

total = 20 + 8 + 8 + len(ct_icv)
outer = bytearray(struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0x1111, 0, 64, 50, 0,
                     socket.inet_aton("192.0.2.2"), socket.inet_aton("192.0.2.1")))
outer[10:12] = struct.pack(">H", cks(bytes(outer)))
esp = struct.pack(">II", SPI, SEQ) + iv8 + ct_icv
eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + struct.pack(">H", 0x0800)
frame = eth + bytes(outer) + esp
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind((iface, 0))
n = s.send(frame)
print(f"sent {n}B ESP frame SPI={SPI:#x} seq={SEQ} on {iface}: ct+icv={len(ct_icv)}B")
