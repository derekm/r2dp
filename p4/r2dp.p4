// SPDX-FileCopyrightText: 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//
// r2dp P4 backend — first behavior (PNA arch, compiled by p4c-dpdk --arch pna).
//
// Structure modeled on p4c's backends/dpdk/examples/ipsec.p4 (Copyright 2023
// Intel Corporation, Apache-2.0).
//
// It targets the same SPD/SAD contract as the r2dp DPDK backend
// (fwd/dp_dpdk.c) behind the same r2dp socket.
//
// Behavior (2026-11-07, §8): inbound/outbound NON-ESP frames (IKE UDP/500,
// ARP, plaintext) are NOT dropped — they forward clear (IPv4 routes by dst,
// non-IP ARP is forced inner/outer via next_hop_preserve ids 2/3).  UDP/4500
// is demuxed on the RFC 3948 zero marker (non-ESP keepalive/IKE forwarded
// clear; a non-zero SPI is ESP-in-UDP).  SAD is exact (ipv4.dst_addr, spi);
// SPD is exact (src_addr, dst_addr, protocol) — SAD's exact key is correct;
// the SPD exact-only (no prefix/ANY/ports) and the inbound miss action `drop`,
// which is NOT the DPDK backend's DR_NO_SA_IN counter, are the known scoped
// limits, not full parity.  Do not reintroduce the pre-§8 IKE/ARP drops or
// the blanket "every UDP/4500 is ESP" parse.
//
// The tables below are populated from the r2dp control plane (SA_ADD/SP_ADD ->
// rte_swx_ctl_* table entries + rte_swx_ipsec_sa_add), mapping fwd_dp_ops:
// sa_add/sp_add/sa_del/sp_del/start/stop (see fwd/dp.h).
//
// Compile:  p4c-dpdk --arch pna r2dp.p4 -o r2dp.out   (NOT `p4c --target dpdk`:
// the p4c driver only registers dpdk-psa; use the standalone build/backends/
// dpdk/p4c-dpdk binary, p4c-dpdk itself picks arch pna|psa).
#include <core.p4>
#include <dpdk/pna.p4>

// Direction: the NIC reports whether a frame arrived from the wire (NET_TO_HOST
// == inbound / decrypt) or is being transmitted (HOST_TO_NET == outbound /
// encrypt).  Both legs live in the one control block, split on this.
#define inbound(meta)  (istd.direction == PNA_Direction_t.NET_TO_HOST)
#define outbound(meta) (istd.direction == PNA_Direction_t.HOST_TO_NET)

// ------------------------------------------------------------------ headers
header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

#define ETHERNET_ETHERTYPE_IPV4 0x0800
#define ETHERNET_ETHERTYPE_ARP  0x0806

// ARP (RFC 826): two 4-byte addresses + two 2-byte codes, so the whole
// grouped header is 28 bytes.  Parsed only so an ARP frame is NOT dropped:
// it is forwarded clear (non-ESP inbound), never offered to the SAD.
header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    bit<48> sha;
    bit<32> spa;
    bit<48> tha;
    bit<32> tpa;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> total_length;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragment_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> header_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

#define IP_PROTOCOL_ESP 0x32
#define IP_PROTOCOL_UDP 0x11

// ESP-in-UDP (NAT-T, RFC 3948): the outer UDP header carries ESP on UDP/4500.
// A UDP/4500 datagram that is NOT ESP-in-UDP (an IKE message or a NAT-T
// keepalive) begins with a 32-bit zero "non-ESP marker" where the ESP SPI
// would be.  We parse the candidate SPI via lookahead and treat a zero
// marker as non-ESP (forwarded clear); a non-zero SPI is ESP-in-UDP.
header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

#define UDP_DST_ESP 4500
#define UDP_DST_IKE 500

header esp_t {
    bit<32> spi;
    bit<32> seq;
}

struct headers_t {
    ethernet_t ethernet;
    arp_t      arp;
    ipv4_t     ipv4;
    udp_t      udp;
    esp_t      esp;
}

// ----------------------------------------------------------------- metadata
struct metadata_t {
    bit<32> next_hop_id;
    bit<32> bypass;    /* 1 = forward clear (IKE/plaintext), not IPSEC */
    bit<32> nat_marker;/* UDP/4500 first-4: 0 = non-ESP, else ESP SPI */
    bit<32> is_esp;    /* 1 = this frame carries ESP (direct or UDP/4500) */
}

// ------------------------------------------------------------------ extern
ipsec_accelerator() ipsec;

// ------------------------------------------------------------------ parser
parser MainParserImpl(packet_in pkt, out headers_t hdrs, inout metadata_t meta,
                      in pna_main_parser_input_metadata_t istd) {
    bool from_ipsec;
    ipsec_status status;

    state start {
        from_ipsec = ipsec.from_ipsec(status);
        transition select(from_ipsec) {
            true   : parse_ipv4;       /* post-decrypt inner packet */
            default: parse_ethernet;   /* wire frame */
        }
    }

    state parse_ethernet {
        pkt.extract(hdrs.ethernet);
        transition select(hdrs.ethernet.ether_type) {
            ETHERNET_ETHERTYPE_IPV4 : parse_ipv4;
            ETHERNET_ETHERTYPE_ARP  : parse_arp;
            default                 : accept;
        }
    }

    state parse_arp {
        pkt.extract(hdrs.arp);
        transition accept;   /* forwarded clear; never offered to the SAD */
    }

    state parse_ipv4 {
        pkt.extract(hdrs.ipv4);
        transition select(hdrs.ipv4.protocol) {
            IP_PROTOCOL_ESP : set_esp;
            IP_PROTOCOL_UDP : parse_udp;
            default         : accept;    /* e.g. ICMP / IKE on 500 */
        }
    }

    state parse_udp {
        pkt.extract(hdrs.udp);
        transition select(hdrs.udp.dst_port) {
            UDP_DST_ESP : nat_demux;   /* ESP-in-UDP vs non-ESP marker */
            default     : accept;      /* IKE (500) / plaintext UDP */
        }
    }

    /* RFC 3948 demux: a UDP/4500 datagram with a zero first-32-bits is the
     * non-ESP marker (NAT-T keepalive / IKE behind NAT), forwarded clear.
     * A non-zero first-32-bits is the ESP SPI of an ESP-in-UDP packet. */
    state nat_demux {
        meta.nat_marker = pkt.lookahead<bit<32>>();
        transition select(meta.nat_marker) {
            0       : accept;           /* non-ESP marker -> clear */
            default : set_esp;          /* ESP SPI -> parse ESP */
        }
    }

    state set_esp {
        meta.is_esp = 1;
        transition parse_esp;
    }

    state parse_esp {
        pkt.extract(hdrs.esp);
        transition accept;
    }
}

// ---------------------------------------------------------------- precontrol
control PreControlImpl(in headers_t hdr, inout metadata_t meta,
                       in pna_pre_input_metadata_t istd,
                       inout pna_pre_output_metadata_t ostd) {
    apply { }
}

// ------------------------------------------------------------ main control
control MainControlImpl(inout headers_t hdrs, inout metadata_t meta,
                        in pna_main_input_metadata_t istd,
                        inout pna_main_output_metadata_t ostd) {

    action ipsec_enable(bit<32> sa_index) {
        ipsec.enable();
        ipsec.set_sa_index<bit<32>>(sa_index);
        hdrs.ethernet.setInvalid();
    }
    action ipsec_bypass() {
        meta.bypass = 1;
        ipsec.disable();
    }
    action drop() {
        drop_packet();
    }

    /* Inbound SAD: (outer dst, esp spi) -> the SA the ipsec extern decrypts
     * with.  A miss runs the const default `drop`; note this is NOT the DPDK
     * backend's DR_NO_SA_IN drop-counter (see header/PLAN §8). */
    table inbound_table {
        key = {
            hdrs.ipv4.dst_addr : exact;
            hdrs.esp.spi       : exact;
        }
        actions = { ipsec_enable; ipsec_bypass; drop; }
        const default_action = drop;
    }

    /* SPD (outbound): bind the OUT PROTECT policy (selector -> egress SA) or
     * bypass/discard.  Mirrors SP_ADD/SP_DEL -> policy_table in ipsec.spec. */
    action ipsec_protect(bit<32> sa_index) {
        ipsec.enable();
        ipsec.set_sa_index<bit<32>>(sa_index);
        hdrs.ethernet.setInvalid();
    }
    action spd_bypass() {
        meta.bypass = 1;
        ipsec.disable();
    }
    action spd_discard() {
        drop_packet();
    }
    table outbound_table {
        key = {
            hdrs.ipv4.src_addr : exact;
            hdrs.ipv4.dst_addr : exact;
            hdrs.ipv4.protocol : exact;
        }
        actions = { ipsec_protect; spd_bypass; spd_discard; drop; }
        const default_action = spd_bypass;
    }

    /* Routing / next hop: send the (possibly IPSEC-processed) frame out the
     * right port with the outer L2 header.  port 0 = outer (encrypted) net,
     * port 1 = inner (plaintext) net; the runtime maps this to a ring/port. */
    action next_hop_set(bit<48> dst_addr, bit<48> src_addr,
                        bit<16> ether_type, bit<32> port_id) {
        hdrs.ethernet.setValid();
        hdrs.ethernet.dst_addr   = dst_addr;
        hdrs.ethernet.src_addr   = src_addr;
        hdrs.ethernet.ether_type = ether_type;
        send_to_port((PortId_t)port_id);
    }
    action next_hop_id_set(bit<32> next_hop_id) {
        meta.next_hop_id = next_hop_id;
    }
    /* Clear-forward that preserves the incoming frame unchanged (non-IP /
     * ARP / control-plane traffic): only the target port is set, ethernet
     * kept intact so ARP keeps ethertype 0x0806. */
    action next_hop_preserve(bit<32> port_id) {
        send_to_port((PortId_t)port_id);
    }
    table routing_table {
        key = { hdrs.ipv4.dst_addr : lpm; }
        actions = { next_hop_id_set; drop; }
        const default_action = next_hop_id_set(0);
    }
    table next_hop_table {
        key = { meta.next_hop_id : exact; }
        actions = { next_hop_set; next_hop_preserve; drop; }
        const default_action = drop;
    }

    apply {
        if (inbound(meta)) {
            ipsec_status status;

            if (!ipsec.from_ipsec(status)) {
                // Pre-decrypt: an inbound ESP frame -> SAD -> ipsec extern.
                // Non-ESP inbound (IKE/ARP/plaintext) forwards clear, never
                // dropped: IPv4 routes by destination IP (the routing LPM,
                // not 10/8 in general, decides the leg); non-IP (ARP) is
                // forced inner via next_hop id 2.
                if (hdrs.ipv4.isValid() && hdrs.esp.isValid()) {
                    inbound_table.apply();
                    if (meta.bypass == 1) {
                        routing_table.apply();
                        next_hop_table.apply();
                    }
                    // else: ipsec extern consumes the frame (decrypt).
                } else {
                    /* Non-ESP inbound (IKE/plaintext/UDP/ARP): forward clear,
                     * never drop.  IPv4 (IKE etc.) routes by destination IP
                     * (10/8 -> inner in this lab; the routing LPM decides the
                     * leg, so an IKE dst outside 10/8 egresses outer) -- this
                     * is "route, don't drop", NOT a forced-inner guarantee.
                     * non-IP (ARP) -> next_hop id 2 = next_hop_preserve(inner),
                     * which keeps the original L2. */
                    if (hdrs.ipv4.isValid())
                        routing_table.apply();
                    else
                        meta.next_hop_id = 2;
                    next_hop_table.apply();
                }
            } else {
                // Post-decrypt: the plaintext inner exits on the inner net.
                if (status == ipsec_status.IPSEC_SUCCESS) {
                    routing_table.apply();
                    next_hop_table.apply();
                } else {
                    drop_packet();       /* crypto / replay failure */
                }
            }
        } else {
            // Outbound (egress): SPD -> encrypt if PROTECT, else clear.
            ipsec_status status;

            if (!ipsec.from_ipsec(status)) {
                if (hdrs.ipv4.isValid()) {
                    outbound_table.apply();
                    if (meta.bypass == 1) {
                        routing_table.apply();
                        next_hop_table.apply();
                    }
                } else {
                    /* non-IP (ARP): clear-forward to outer leg, frame
                     * preserved via next_hop id 3 (next_hop_preserve->outer). */
                    meta.next_hop_id = 3;
                    next_hop_table.apply();
                }
            } else {
                // Post-encrypt: give the outer frame its L2 + port.
                if (status == ipsec_status.IPSEC_SUCCESS) {
                    routing_table.apply();
                    next_hop_table.apply();
                } else {
                    drop_packet();
                }
            }
        }
    }
}

// -------------------------------------------------------------- deparser
control MainDeparserImpl(packet_out pkt, in headers_t hdrs, in metadata_t meta,
                         in pna_main_output_metadata_t ostd) {
    apply {
        pkt.emit(hdrs.ethernet);
        pkt.emit(hdrs.arp);
        pkt.emit(hdrs.ipv4);
        pkt.emit(hdrs.udp);
        pkt.emit(hdrs.esp);
    }
}

// ------------------------------------------------------------------ package
PNA_NIC(MainParserImpl(), PreControlImpl(), MainControlImpl(), MainDeparserImpl()) main;
