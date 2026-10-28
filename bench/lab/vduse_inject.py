#!/usr/bin/env python3
"""Deterministically encrypt a valid inner packet into an outer ESP datagram
using an AES-GCM ESP key (16B AES + 4B salt), and send it out the VDUSE outer
netdev so the forwarder decrypts it.  DPDK ESP AES-GCM: enckey = 16B key +
4B salt; the crypto IV = salt(4) + transmitted-iv(8)."""
import socket, struct, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENCKEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f10111213")  # 16+4
KEY16 = ENCKEY[:16]
SALT = ENCKEY[16:20]
SPI = 0xBABE0001
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

iv8 = b"IVIVIVIV"
iv = SALT + iv8
aes = AESGCM(KEY16)
enc = aes.encrypt(iv, bytes(inner), b"")

outer = bytearray(struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + 8 + 8 + len(inner) + 16,
                     0x1111, 0, 64, 50, 0,
                     socket.inet_aton("192.0.2.2"), socket.inet_aton("192.0.2.1")))
outer[10:12] = struct.pack(">H", cks(bytes(outer)))

esp = struct.pack(">II", SPI, 1) + iv8 + enc
eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + struct.pack(">H", 0x0800)
frame = eth + bytes(outer) + esp
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind((iface, 0))
n = s.send(frame)
print(f"sent {n}B ESP frame SPI={SPI:#x} on {iface}, inner={len(inner)}B")
