/* r2dp P4 backend — first behavior (PNA arch on p4c '--target dpdk').
 *
 * Modeled on p4c's own backends/dpdk/examples/ipsec.p4, which is the canonical
 * PNA IPsec program for the DPDK soft-switch (rte_swx_pipeline + the
 * rte_swx_ipsec extern).  It expresses the same SPD/SAD behaviour as the r2dp
 * DPDK backend (fwd/dp_dpdk.c) behind the same r2dp socket: inbound ESP ->
 * SAD (dst, spi) -> ipsec extern decap; outbound -> SPD -> ipsec extern encap;
 * bypass/discard otherwise.  The same source can later target a switch ASIC
 * once the P4 abstraction is kept (see p4/PLAN.md).
 *
 * The tables below are populated from the r2dp control plane (SA_ADD/SP_ADD ->
 * rte_swx_ctl_* table entries + rte_swx_ipsec_sa_add), exactly mapping
 * fwd_dp_ops: sa_add/sp_add/sa_del/sp_del/start/stop (see fwd/dp.h).
 */
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

// ESP-in-UDP (NAT-T): the outer UDP header carries ESP on UDP/4500.
header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

#define UDP_DST_ESP 4500

header esp_t {
    bit<32> spi;
    bit<32> seq;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    udp_t      udp;
    esp_t      esp;
}

// ----------------------------------------------------------------- metadata
struct metadata_t {
    bit<32> next_hop_id;
    bit<32> bypass;    /* 1 = forward clear (IKE/plaintext), not IPSEC */
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
            default                 : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdrs.ipv4);
        transition select(hdrs.ipv4.protocol) {
            IP_PROTOCOL_ESP : parse_esp;
            IP_PROTOCOL_UDP : parse_udp;
            default         : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdrs.udp);
        transition select(hdrs.udp.dst_port) {
            UDP_DST_ESP : parse_esp;   /* NAT-T ESP on 4500 */
            default     : accept;      /* IKE / plaintext UDP */
        }
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
     * with.  A miss drops (DR_NO_SA_IN). */
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
    table routing_table {
        key = { hdrs.ipv4.dst_addr : lpm; }
        actions = { next_hop_id_set; drop; }
        const default_action = next_hop_id_set(0);
    }
    table next_hop_table {
        key = { meta.next_hop_id : exact; }
        actions = { next_hop_set; drop; }
        const default_action = drop;
    }

    apply {
        if (inbound(meta)) {
            ipsec_status status;

            if (!ipsec.from_ipsec(status)) {
                // Pre-decrypt: an inbound ESP frame -> SAD -> ipsec extern.
                if (hdrs.ipv4.isValid() && hdrs.esp.isValid()) {
                    inbound_table.apply();
                    if (meta.bypass) {
                        routing_table.apply();
                        next_hop_table.apply();
                    }
                    // else: ipsec extern consumes the frame (decrypt).
                } else {
                    drop_packet();
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
                    if (meta.bypass) {
                        routing_table.apply();
                        next_hop_table.apply();
                    }
                } else {
                    drop_packet();
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
        pkt.emit(hdrs.ipv4);
        pkt.emit(hdrs.udp);
        pkt.emit(hdrs.esp);
    }
}

// ------------------------------------------------------------------ package
PNA_NIC(MainParserImpl(), PreControlImpl(), MainControlImpl(), MainDeparserImpl()) main;
