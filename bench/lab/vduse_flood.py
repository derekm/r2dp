#!/usr/bin/env python3
"""Flood unique-seq ESP AES-GCM frames on the VDUSE outer netdev.  Each frame
seq increments so anti-replay accepts them; the forwarder decrypts each and
delivers inner to the tap.  Count what we send."""
import socket, struct, sys, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENCKEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f10111213")
KEY16, SALT = ENCKEY[:16], ENCKEY[16:20]
SPI = 0xBABE0001
iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
DUR = float(sys.argv[2]) if len(sys.argv) > 2 else 6
RATE = int(sys.argv[3]) if len(sys.argv) > 3 else 40000

def cks(b):
    if len(b) % 2: b += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(b)//2), b))
    s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff

def make(seq):
    inner = bytearray()
    inner += struct.pack(">BBHHHBBH4s4s", 0x45, 0, 28, 0, seq % 1000, 64, 1, 0,
                         socket.inet_aton("10.0.1.1"), socket.inet_aton("10.0.2.1"))
    inner += b"\x08\x00\x00\x00" + struct.pack(">HH", 0x1234, seq & 0xffff)
    inner[10:12] = struct.pack(">H", cks(bytes(inner)))
    trailer = b"\x00\x00\x00\x01"
    iv8 = struct.pack(">Q", (seq << 16) | 0x01020304)[-8:]
    nonce = SALT + iv8
    aad = struct.pack(">II", SPI, seq & 0xffffffff)
    ct_icv = AESGCM(KEY16).encrypt(nonce, bytes(inner) + trailer, aad)
    total = 20 + 8 + 8 + len(ct_icv)
    outer = bytearray(struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 50, 0,
                         socket.inet_aton("192.0.2.2"), socket.inet_aton("192.0.2.1")))
    outer[10:12] = struct.pack(">H", cks(bytes(outer)))
    esp = struct.pack(">II", SPI, seq & 0xffffffff) + iv8 + ct_icv
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + struct.pack(">H", 0x0800)
    return eth + bytes(outer) + esp

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind((iface, 0))
end = time.time() + DUR
n = 0
while time.time() < end:
    for _ in range(RATE):
        s.sendall(make(n)); n += 1
print(f"sent {n} frames in {DUR}s on {iface}")
