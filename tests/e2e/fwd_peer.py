#!/usr/bin/env python3
"""Independent ESP peer (scapy + cryptography) for the r2dp-fwd interop test.

Adapted from the upstream prototype's harness for this forwarder.
Plays the remote IPsec gateway on the outer (ESP) tap.  Every positive check is a
full round trip: scapy encrypts an ICMP echo -> forwarder decrypts and routes it
-> a real kernel host answers -> forwarder encrypts the reply -> scapy decrypts
it and compares payloads.  Negative checks print the packet they sent; the
shell harness asserts on the forwarder's drop counters afterwards.

usage: fwd_peer.py <iface> <my_mac> <fwd_mac> <key1hex> <key2hex> <phase> <reply_ttl>
  reply_ttl: the TTL the inner echo reply must carry when it reaches us
  (the host's default TTL minus the hops the forwarder takes off), so the
  check is relative to the environment (64 on a host, 127 in some userns).
"""
import sys, time, threading
from scapy.all import (Ether, IP, ICMP, Raw, AsyncSniffer, sendp, conf)
from scapy.layers.ipsec import SecurityAssociation, ESP

conf.verb = 0
iface, my_mac, fwd_mac, k1, k2, phase, reply_ttl = sys.argv[1:8]
reply_ttl = int(reply_ttl)
P, F = "192.0.2.2", "192.0.2.1"          # peer / forwarder tunnel endpoints
SPI1, SPI2 = 0x1000, 0x2000              # peer->fwd, fwd->peer
IN_SRC, IN_DST = "10.1.0.1", "10.2.0.2"  # protected subnets behind each side

def mk_sa(spi, key, src, dst):
    return SecurityAssociation(ESP, spi=spi, crypt_algo="AES-GCM", crypt_key=bytes.fromhex(key),
                               auth_algo="NULL", auth_key=None, tunnel_header=IP(src=src, dst=dst))

sa_out = mk_sa(SPI1, k1, P, F)           # we encrypt with this; forwarder decrypts
sa_in = mk_sa(SPI2, k2, F, P)            # forwarder encrypts with this; we decrypt

# Each phase is its own process, but the forwarder's anti-replay window persists
# across them, so every phase starts its ESP sequence numbers well above the last.
# (scapy stamps a packet with seq_num *before* incrementing it, and RFC 4303 forbids
# sequence 0, so the first packet of a fresh SA must be sent with seq_num == 1.)
SEQ_BASE = {"positive": 1, "window": 1000, "negative": 5000}
sa_out.seq_num = SEQ_BASE[phase]

fails = 0
def check(cond, msg):
    global fails
    print(("ok   " if cond else "FAIL ") + msg, flush=True)
    if not cond: fails += 1

def payload(n, tag=0):
    return bytes(((i * 7 + tag) & 0xff) for i in range(n))

def send_and_wait(frame, want_reply, timeout=2.0):
    """Send one frame; return the decrypted inner packet of the first ESP reply (or None)."""
    got = []
    ev = threading.Event()
    def cb(p):
        if p.haslayer(ESP) and p[IP].src == F and p[IP].dst == P:
            got.append(p); ev.set()
    # lfilter, not a BPF filter: no libpcap/tcpdump needed in the venv
    sn = AsyncSniffer(iface=iface, prn=cb, store=False,
                      lfilter=lambda p: p.haslayer(IP) and p[IP].proto == 50)
    sn.start(); time.sleep(0.6)     # let the AF_PACKET socket attach before we send
    sendp(frame, iface=iface)
    ev.wait(timeout if want_reply else 0.6)
    sn.stop()
    if not got: return None
    return sa_in.decrypt(got[0][IP])

def esp_frame(inner, sa=None):
    sa = sa or sa_out
    return Ether(src=my_mac, dst=fwd_mac) / sa.encrypt(inner)

def echo(seq, n, src=IN_SRC, ident=0x4242):
    return IP(src=src, dst=IN_DST, ttl=64) / ICMP(id=ident, seq=seq) / Raw(payload(n, seq))

def roundtrip(seq, n):
    rep = send_and_wait(esp_frame(echo(seq, n)), True)
    ok = (rep is not None and rep.haslayer(ICMP) and rep[ICMP].type == 0 and rep[ICMP].id == 0x4242 and
          rep[ICMP].seq == seq and (bytes(rep[Raw].load) if rep.haslayer(Raw) else b"") == payload(n, seq) and
          rep[IP].src == IN_DST and rep[IP].dst == IN_SRC)
    return ok, rep

if phase == "positive":
    # payload sizes 0..9 hit every ESP pad length (0-3); then larger ones up to near-MTU
    for i, n in enumerate(list(range(0, 10)) + [64, 512, 1000, 1400]):
        ok, rep = roundtrip(i + 1, n)
        check(ok, f"round trip payload={n} (next esp seq {sa_out.seq_num})")
    ok, rep = roundtrip(50, 100)
    check(ok and rep[IP].ttl == reply_ttl,
          f"inner reply ttl {reply_ttl} (got {rep[IP].ttl if rep else None})")
elif phase == "window":
    B = SEQ_BASE["window"]
    def at(seq):                       # make the NEXT packet carry exactly this ESP sequence number
        sa_out.seq_num = seq
    at(B + 200); ok, _ = roundtrip(101, 40); check(ok, f"seq {B+200} accepted (window top)")
    at(B + 198); ok, _ = roundtrip(102, 40); check(ok, f"seq {B+198} (out of order, inside window) accepted")
    at(B + 198); check(send_and_wait(esp_frame(echo(103, 40)), False) is None, f"seq {B+198} replayed -> no reply")
    at(B + 19);  check(send_and_wait(esp_frame(echo(104, 40)), False) is None, f"seq {B+19} (far older than the window) -> no reply")
    at(B + 400); ok, _ = roundtrip(105, 40); check(ok, f"seq {B+400}: window slides forward")
    at(B + 337); ok, _ = roundtrip(106, 40); check(ok, f"seq {B+337} (distance 63: oldest slot of the 64-window) accepted")
    at(B + 336); check(send_and_wait(esp_frame(echo(107, 40)), False) is None, f"seq {B+336} (distance 64: just outside) -> no reply")
elif phase == "negative":
    # tampered ciphertext
    f = esp_frame(echo(201, 64)); raw = bytearray(bytes(f)); raw[-20] ^= 0x01
    check(send_and_wait(Ether(bytes(raw)), False) is None, "bit-flipped ciphertext -> no reply")
    # tampered ESP header (SPI bytes are authenticated as AAD only via SA lookup; seq is in AAD)
    f = esp_frame(echo(202, 64)); raw = bytearray(bytes(f)); raw[14 + 20 + 7] ^= 0x01   # seq low byte
    check(send_and_wait(Ether(bytes(raw)), False) is None, "tampered sequence number (AAD) -> no reply")
    # unknown SPI
    other = mk_sa(0x7777, k1, P, F)
    check(send_and_wait(esp_frame(echo(203, 64), other), False) is None, "unknown SPI -> no reply")
    # inner packet outside the policy selector
    check(send_and_wait(esp_frame(echo(204, 64, src="10.9.9.9")), False) is None, "inner src outside selector -> no reply")
    # clear text where policy demands ESP
    clear = Ether(src=my_mac, dst=fwd_mac) / IP(src=IN_SRC, dst=IN_DST, ttl=64) / ICMP(id=0x4242, seq=205) / Raw(b"clear" * 8)
    check(send_and_wait(clear, False) is None, "cleartext on the protected flow -> no reply")
    # truncated ESP
    f = esp_frame(echo(206, 64)); raw = bytes(f)[:14 + 20 + 12]
    pkt = Ether(raw); pkt[IP].len = 20 + 12; del pkt[IP].chksum
    check(send_and_wait(Ether(bytes(pkt)), False) is None, "truncated ESP -> no reply")
    # control: a valid packet right after the garbage still works
    ok, _ = roundtrip(207, 32); check(ok, "forwarder still healthy after the garbage")
sys.exit(1 if fails else 0)
