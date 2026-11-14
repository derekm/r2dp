/* r2dp P4 backend — first behavior (PNA arch, p4c --target dpdk --arch pna).
 *
 * This models the SWX pipeline engine that DPDK already builds (examples/
 * pipeline/examples/ipsec.spec + rte_swx_ipsec), expressed as a portable PNA
 * program so the same source can compile to the DPDK soft-switch now and, once
 * the P4 abstraction is kept, to a switch ASIC later.
 *
 * The SWX ipsec block (rte_swx_ipsec) does the actual ESP crypto + replay and
 * is driven solely by an sa_id written into the ipsec_internal header; the
 * tables below classify and select that sa_id / policy, exactly mirroring the
 * vtable contract (fwd_dp_ops) the DPDK backend already satisfies.
 *
 * NOTE: this is the source-of-truth .p4; compiling it needs p4c (not installed
 * on .179 — see p4/PLAN.md §3).  The loadable artifact for today is emitted
 * from the hand-written .spec path, which this program documents/derives from.
 */
#include <core.p4>
#include <pna.p4>

/* -------------------------------------------------------------------- */
/* Let the outer parse accept either raw IPv4 or IPv4-in-UDP carrying ESP */
/* -------------------------------------------------------------------- */
header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ethertype;
}

header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

header esp_h {
    bit<32> spi;
    bit<32> seq;
}

/* The SWX ipsec extern's side-band: written by the ingress table to name the
 * SA the block must run against; consumed off the data plane. */
header ipsec_internal_h {
    bit<32> sa_id;
}

struct headers_t {
    ethernet_h        ethernet;
    ipv4_h            ipv4;
    udp_h             udp;
    esp_h             esp;
    ipsec_internal_h  ipsec_internal;
}

struct metadata_t {
    bit<32> port_in;
    bit<32> port_out;

    bit<32> src_addr;
    bit<32> dst_addr;
    bit<8>  protocol;
    bit<16> src_port;
    bit<16> dst_port;
}

parser r2dp_parser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
                   in pna_main_parser_input_metadata_t istd) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethertype) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.src_addr = hdr.ipv4.src_addr;
        meta.dst_addr = hdr.ipv4.dst_addr;
        meta.protocol = hdr.ipv4.protocol;
        transition select(hdr.ipv4.protocol) {
            50:  parse_esp;        /* ESP over IPv4 */
            17:  parse_udp;        /* ESP-in-UDP (NAT-T) */
            default: accept;       /* IKE / ARP / cleartext -> exception */
        }
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        meta.src_port = hdr.udp.src_port;
        meta.dst_port = hdr.udp.dst_port;
        transition select(hdr.udp.dst_port) {
            4500: parse_esp;       /* IKE/ESP floats to 4500 under NAT-T */
            default: accept;
        }
    }
    state parse_esp {
        pkt.extract(hdr.esp);
        accept;
    }
}

control r2dp_ingress(inout headers_t hdr, inout metadata_t meta,
                     in pna_main_parser_input_metadata_t istd,
                     inout pna_main_input_metadata_t imeta,
                     inout pna_main_output_metadata_t ometa) {

    /* Inbound SAD: (spi, outer dst) -> the inbound SA, whose sa_id the ipsec
     * extern runs.  A miss is NoAction (drop), matching DR_NO_SA_IN. */
    action SAD_HIT(bit<32> sa_id) {
        hdr.ipsec_internal.setValid();
        hdr.ipsec_internal.sa_id = sa_id;
        meta.port_out = 1;           /* decrypted inner exits the inner net */
    }
    table sad {
        key = {
            hdr.esp.spi      : exact;
            hdr.ipv4.dst_addr: exact;
        }
        actions = { SAD_HIT; NoAction; }
        const default_action = NoAction();
    }

    /* SPD (egress / exception): bind the OUT PROTECT policy to its egress SA,
     * or bypass (IKE/clear), or discard.  Mirrors SP_ADD/SP_DEL -> the
     * policy_table in DPDK's ipsec.spec. */
    action SPD_PROTECT(bit<32> sa_id) {
        hdr.ipsec_internal.setValid();
        hdr.ipsec_internal.sa_id = sa_id;
        meta.port_out = 0;           /* encrypted egress on the outer net */
    }
    action SPD_BYPASS() {
        meta.port_out = 1;           /* forward clear on the inner net */
    }
    action SPD_DISCARD() {
        mark_to_drop(istd, imeta);
    }
    table spd {
        key = {
            meta.src_addr : exact;
            meta.dst_addr : exact;
            meta.protocol : exact;
            meta.src_port : ternary;
            meta.dst_port : ternary;
        }
        actions = { SPD_PROTECT; SPD_BYPASS; SPD_DISCARD; }
        const default_action = SPD_BYPASS();
    }

    apply {
        if (hdr.esp.isValid())
            sad.apply();             /* inbound: SAD -> ipsec extern */
        else
            spd.apply();             /* egress/exception: SPD decision  */
    }
}

control r2dp_deparser(packet_out pkt, inout headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.esp);
        pkt.emit(hdr.ipsec_internal);
    }
}

PNA_Main(r2dp_parser(), r2dp_ingress(), r2dp_deparser(), pna_main_imem_t(), pna_main_emem_t());
