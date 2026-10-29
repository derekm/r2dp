#!/usr/bin/env python3
"""Independent ESP peer (scapy + cryptography) for the r2dp-fwd interop test.

Plays the remote IPsec gateway on the black side.  Every positive check is a
full round trip: scapy encrypts an ICMP echo -> forwarder decrypts and routes it
-> a real kernel host answers -> forwarder encrypts the reply -> scapy decrypts
it and compares payloads.  Negative checks print the packet they sent; the
shell harness asserts on the forwarder's drop counters afterwards.

usage: fwd_peer.py <iface> <my_mac> <fwd_black_mac> <key1hex> <key2hex> <phase>
"""
import sys, time, threading
from scapy.all import (Ether, IP, UDP, ICMP, Raw, AsyncSniffer, sendp, conf)
from scapy.layers.ipsec import SecurityAssociation, ESP

conf.verb = 0
iface, my_mac, fwd_mac, k1, k2, phase = sys.argv[1:7]
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
SEQ_BASE = {"positive": 1, "window": 1000, "negative": 5000, "esn": 1, "natt": 1}
K3 = "3031323334353637383940414243444546474849"      # esn: peer->fwd (SPI 0x3000)  -- keep in sync with fwd_e2e.sh
K4 = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3"      # esn: fwd->peer (SPI 0x4000)
sa_out.seq_num = SEQ_BASE.get(phase, 1)       # cbcN phases use their own fresh SAs

fails = 0
def check(cond, msg):
    global fails
    print(("ok   " if cond else "FAIL ") + msg, flush=True)
    if not cond: fails += 1

def payload(n, tag=0):
    return bytes(((i * 7 + tag) & 0xff) for i in range(n))

def send_and_wait(frame, want_reply, timeout=2.0, dec=None, flt="esp"):
    """Send one frame; return the decrypted inner packet of the first ESP reply (or None)."""
    got = []
    ev = threading.Event()
    def cb(p):
        if p.haslayer(ESP) and p[IP].src == F and p[IP].dst == P:
            got.append(p); ev.set()
    sn = AsyncSniffer(iface=iface, prn=cb, store=False, filter=flt)
    sn.start(); time.sleep(0.6)     # let the AF_PACKET socket attach before we send
    sendp(frame, iface=iface)
    ev.wait(timeout if want_reply else 0.6)
    sn.stop()
    if not got: return None
    return (dec or sa_in).decrypt(got[0][IP])

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
    # request ttl 64 -> 63 at the host; reply ttl 64 (host) -> 63 after the forwarder
    check(ok and rep[IP].ttl == 63, f"ttl decremented on the way back (got {rep[IP].ttl if rep else None})")
    # forwarder-originated ESP sequence numbers are strictly increasing
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
elif phase == "esn":
    # A second SA pair with extended sequence numbers.  The forwarder only sees the low 32 bits on the
    # wire and must infer the high 32 from its window (RFC 4303 A2.2); the AAD it authenticates then
    # contains those inferred bits, so a wrong inference can only ever show up as an auth failure.
    e_out = SecurityAssociation(ESP, spi=0x3000, crypt_algo="AES-GCM", crypt_key=bytes.fromhex(K3),
                                auth_algo="NULL", auth_key=None, tunnel_header=IP(src=P, dst=F), esn_en=True, esn=0)
    e_in = SecurityAssociation(ESP, spi=0x4000, crypt_algo="AES-GCM", crypt_key=bytes.fromhex(K4),
                               auth_algo="NULL", auth_key=None, tunnel_header=IP(src=F, dst=P), esn_en=True, esn=0)
    def esn_frame(lo, hi, seq):
        return Ether(src=my_mac, dst=fwd_mac) / e_out.encrypt(echo(seq, 48), seq_num=lo, esn_en=True, esn=hi)
    def esn_trip(lo, hi, seq, label, want=True):
        got = []
        ev = threading.Event()
        def cb(p):
            if p.haslayer(ESP) and p[IP].src == F and p[IP].dst == P:
                got.append(p); ev.set()
        sn = AsyncSniffer(iface=iface, prn=cb, store=False, filter="esp"); sn.start(); time.sleep(0.6)
        sendp(esn_frame(lo, hi, seq), iface=iface)
        ev.wait(2.0 if want else 0.6); sn.stop()
        rep = e_in.decrypt(got[0][IP], esn_en=True, esn=0) if got else None
        ok = (rep is not None and rep.haslayer(ICMP) and rep[ICMP].type == 0 and rep[ICMP].seq == seq) if want else (rep is None)
        check(ok, label)
    esn_trip(1, 0, 1, "ESN AAD (spi|seq_hi|seq_lo) interoperates: seq 1")
    esn_trip(2, 0, 2, "ESN seq 2")
    esn_trip(0xFFFFFF00, 0, 3, "forward jump to 0xFFFFFF00 stays in subspace 0")
    esn_trip(0xFFFFFFF0, 0, 4, "0xFFFFFFF0, just below the 2^32 boundary")
    esn_trip(5, 1, 5, "crosses 2^32: low=5 -> forwarder infers high=1 (seq 0x1_00000005)")
    esn_trip(0xFFFFFFF8, 0, 6, "late packet from subspace 0, 13 behind the top, still inside the window")
    esn_trip(0xFFFFFFF8, 0, 7, "...and replaying it is refused", want=False)
    esn_trip(6, 7, 8, "right low bits, wrong high bits (7 not 1) -> auth failure, no reply", want=False)
    esn_trip(0xFFFFFF00, 0, 9, "low 0xFFFFFF00 after the wrap is read as a far-future subspace -> auth failure", want=False)
    esn_trip(7, 1, 10, "legitimate seq 0x1_00000007 still accepted: the failed packets did not move the window")
elif phase == "natt":
    # ESP-in-UDP (RFC 3948).  UDP/4500 carries three things the forwarder must tell apart by the
    # first bytes: ESP (non-zero SPI), IKE (4 zero bytes, the "non-ESP marker"), and a lone 0xFF keepalive.
    K5 = "5051525354555657585960616263646566676869"; K6 = "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3"
    def nat_sa(spi, key, src, dst, natt=True):
        return SecurityAssociation(ESP, spi=spi, crypt_algo="AES-GCM", crypt_key=bytes.fromhex(key), auth_algo="NULL",
                                   auth_key=None, tunnel_header=IP(src=src, dst=dst),
                                   nat_t_header=UDP(sport=4500, dport=4500) if natt else None)
    n_out, n_in = nat_sa(0x5000, K5, P, F), nat_sa(0x6000, K6, F, P)
    FLT = "esp or udp port 4500"
    def ntrip(seq, n, label, want=True):
        rep = send_and_wait(Ether(src=my_mac, dst=fwd_mac) / n_out.encrypt(echo(seq, n)), want, dec=n_in, flt=FLT)
        ok = (rep is not None and rep.haslayer(ICMP) and rep[ICMP].type == 0 and rep[ICMP].seq == seq and
              (bytes(rep[Raw].load) if rep.haslayer(Raw) else b"") == payload(n, seq)) if want else (rep is None)
        check(ok, label)
    ntrip(1, 64, "ESP-in-UDP round trip (UDP 4500 both ways)")
    ntrip(2, 1400, "1400-byte payload still fits with the extra 8-byte UDP header")
    # Request and reply have the same size, so one SA cannot show this.  Send the request over the plain-ESP SA
    # (1440-byte inner packet -> 1496 on the wire, fits); the host's reply is then encrypted by the *newest*
    # outbound SA, the NAT-T one, whose extra 8 bytes make it 1504: dropped and counted, never truncated.
    sa_out.seq_num = 9000
    check(send_and_wait(esp_frame(echo(3, 1412)), False, flt=FLT) is None,
          "1412-byte payload: request fits as plain ESP, reply would not fit as ESP-in-UDP -> dropped as too big")
    def raw_udp(payload_bytes):
        return Ether(src=my_mac, dst=fwd_mac) / IP(src=P, dst=F) / UDP(sport=4500, dport=4500) / Raw(payload_bytes)
    check(send_and_wait(raw_udp(b"\xff"), False, flt=FLT) is None, "NAT keepalive (single 0xFF) is swallowed")
    check(send_and_wait(raw_udp(b"\x00\x00\x00\x00" + b"IKE-ish" * 4), False, flt=FLT) is None,
          "non-ESP-marker datagram is IKE, not ESP: not decrypted")
    plain = nat_sa(0x5000, K5, P, F, natt=False); plain.seq_num = 50
    check(send_and_wait(Ether(src=my_mac, dst=fwd_mac) / plain.encrypt(echo(4, 32)), False, flt=FLT) is None,
          "plain ESP for an SA that expects UDP encapsulation is refused")
    wrapped = nat_sa(0x1000, k1, P, F); wrapped.seq_num = 7000
    check(send_and_wait(Ether(src=my_mac, dst=fwd_mac) / wrapped.encrypt(echo(5, 32)), False, flt=FLT) is None,
          "UDP-wrapped ESP for a plain-ESP SA is refused")
elif phase.startswith("cbc"):
    # AES-CBC + HMAC.  Combos are numbered; keys are derived from the index so the shell harness can install the
    # same SAs without passing key material around (keep keyset()/COMBOS in sync with fwd_e2e.sh).
    COMBOS = [("HMAC-SHA1-96", 20, 16), ("SHA2-256-128", 32, 16), ("SHA2-384-192", 48, 16), ("SHA2-512-256", 64, 16),
              ("SHA2-256-128", 32, 24), ("SHA2-256-128", 32, 32)]
    def keyset(idx, n, base, step): return bytes(((idx * 13 + base + i * step) & 255) for i in range(n))
    idx = int(phase[3:]); aname, akl, ekl = COMBOS[idx]
    spi_in, spi_out = 0x7000 + 2 * idx, 0x7001 + 2 * idx
    def mk(spi, ek, ak, src, dst):
        return SecurityAssociation(ESP, spi=spi, crypt_algo="AES-CBC", crypt_key=ek, auth_algo=aname, auth_key=ak,
                                   tunnel_header=IP(src=src, dst=dst))
    c_out = mk(spi_in, keyset(idx, ekl, 1, 7), keyset(idx, akl, 5, 11), P, F)
    c_in = mk(spi_out, keyset(idx, ekl, 3, 7), keyset(idx, akl, 9, 11), F, P)
    def ctrip(seq, n, label, want=True, sa=None, tamper=None):
        fr = Ether(src=my_mac, dst=fwd_mac) / (sa or c_out).encrypt(echo(seq, n))
        if tamper: fr = tamper(fr)
        rep = send_and_wait(fr, want, dec=c_in)
        ok = (rep is not None and rep.haslayer(ICMP) and rep[ICMP].type == 0 and rep[ICMP].seq == seq and
              (bytes(rep[Raw].load) if rep.haslayer(Raw) else b"") == payload(n, seq)) if want else (rep is None)
        check(ok, label)
    # inner = 28 + payload; +2 trailer bytes; every residue mod 16 is a different pad length
    sizes = [0, 1, 14, 15, 16, 17, 100, 1000] if idx < 4 else [16, 100]
    for j, n in enumerate(sizes):
        ctrip(j + 1, n, f"AES-{ekl*8}-CBC + {aname}: payload {n}")
    if idx == 1:   # hostile input, on one representative combo
        def flip(off):
            def f(fr):
                raw = bytearray(bytes(fr)); raw[off] ^= 0x01; return Ether(bytes(raw))
            return f
        ctrip(50, 64, "flipped ciphertext bit -> HMAC fails, no reply", want=False, tamper=flip(-30))
        ctrip(51, 64, "flipped ICV bit -> HMAC fails, no reply", want=False, tamper=flip(-1))
        ctrip(52, 64, "flipped IV bit (covered by the HMAC) -> no reply", want=False, tamper=flip(14 + 20 + 8 + 3))
        def trunc(fr):                                    # ciphertext no longer a multiple of the block size
            pkt = Ether(bytes(fr)); raw = bytes(pkt)[:-5]; q = Ether(raw)
            q[IP].len = len(raw) - 14; del q[IP].chksum; return Ether(bytes(q))
        ctrip(53, 64, "ciphertext not a multiple of 16 -> refused before any crypto", want=False, tamper=trunc)
sys.exit(1 if fails else 0)
