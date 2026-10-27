#!/usr/bin/env python3
"""Generate a complete N-initiator lab: racoon2 configs + a manifest.

Higher-level abstraction: the manifest (lab.manifest) is the single source of
truth.  All harness scripts (lab_up.sh, lab_bench.sh, lab_teardown.sh) parse
it and derive names/addresses; no script hardcodes nsI<n> / racoonA<n>.

Derived per-initiator index i (0-based):
  netns      = "nsI" + i
  veth pair  = "vi" + i + "a/b"
  dummy      = "dummyI" + i
  outer ip   = OUTER_BASE + i     (e.g. 10.77.0.2+i)
  inner src  = INNER_BASE + i     (e.g. 192.0.2.2+i)
  spmd sock  = /tmp/spmif-A<i>
  ike admin  = /tmp/ikedA.sock-<i>
  iked log   = /tmp/ikedA<i>.log
  lab id     = "lab.a" + i ; peer id "lab.b"
Addresses are passed as the LAST octet (a dotted-quad prefix).  The responder
holds outer=RESP_OUTER, inner=RESP_INNER (no per-initiator suffix).
"""
import os, sys

CFG = os.environ.get("LAB_CFG", "/home/yescorp/bench/configs")
PSK = os.environ.get("LAB_PSK", "/home/yescorp/bench/psk/lab.psk")

def octet(prefix, i):
    base, _, last = prefix.rpartition(".")
    return f"{base}.{int(last)+i}"

def initiator_conf(i, ouc, inc, resp_outer, resp_inner):
    return f"""interface {{
\tike {{ "{ouc}"; }};
\tspmd {{ unix "/tmp/spmif-A{i}"; }};
\tspmd_password "{CFG}/spmd.pwd.A";
}};
resolver {{ resolver off; }};

remote labA{i}_init {{
\tacceptable_kmp {{ ikev2; }};
\tikev2 {{
\t\tmy_id fqdn "lab.a{i}";
\t\tpeers_id fqdn "lab.b";
\t\tpeers_ipaddr "{resp_outer}" port 500;
\t\tkmp_enc_alg {{ aes256_cbc; aes128_cbc; }};
\t\tkmp_prf_alg {{ hmac_sha2_256; }};
\t\tkmp_hash_alg {{ hmac_sha2_256; }};
\t\tkmp_dh_group {{ ecp256; modp2048; modp3072; }};
\t\tkmp_auth_method {{ psk; }};
\t\tpre_shared_key "{PSK}";
\t}};
\tselector_index sel_in;
}};

selector sel_out {{
\tdirection outbound;
\tsrc "{inc}";
\tdst "{resp_inner}";
\tpolicy_index pol;
}};
selector sel_in {{
\tdirection inbound;
\tdst "{inc}";
\tsrc "{resp_inner}";
\tpolicy_index pol;
}};

policy pol {{
\taction auto_ipsec;
\tremote_index labA{i}_init;
\tipsec_mode tunnel;
\tipsec_index {{ ipsec_e; }};
\tipsec_level require;
\tpeers_sa_ipaddr "{resp_outer}";
\tmy_sa_ipaddr "{ouc}";
}};

ipsec ipsec_e {{
\tipsec_sa_lifetime_time 3600 sec;
\tsa_index esp_e;
}};

sa esp_e {{
\tsa_protocol esp;
\tesp_enc_alg {{ aes_gcm; }};
\tesp_auth_alg {{ non_auth; }};
}};
"""

def responder_conf(N, ouc_list, inc_list, resp_outer, resp_inner):
    parts = [f"""interface {{
\tike {{ "{resp_outer}"; }};
\tspmd {{ unix "/tmp/spmif-B"; }};
\tspmd_password "{CFG}/spmd.pwd.B";
}};
resolver {{ resolver off; }};
"""]
    for i in range(N):
        ouc, inc = ouc_list[i], inc_list[i]
        parts.append(f"""
remote labB_resp{i} {{
\tacceptable_kmp {{ ikev2; }};
\tikev2 {{
\t\tpassive on;
\t\tmy_id fqdn "lab.b";
\t\tpeers_id fqdn "lab.a{i}";
\t\tpeers_ipaddr "{ouc}";
\t\tkmp_enc_alg {{ aes256_cbc; aes128_cbc; }};
\t\tkmp_prf_alg {{ hmac_sha2_256; }};
\t\tkmp_hash_alg {{ hmac_sha2_256; }};
\t\tkmp_dh_group {{ ecp256; modp2048; modp3072; }};
\t\tkmp_auth_method {{ psk; }};
\t\tpre_shared_key "{PSK}";
\t\tdpd_delay 60 sec;
\t}};
\tselector_index sel_in{i};
}};

selector sel_out{i} {{
\tdirection outbound;
\tsrc "{resp_inner}";
\tdst "{inc}";
\tpolicy_index pol{i};
}};
selector sel_in{i} {{
\tdirection inbound;
\tdst "{resp_inner}";
\tsrc "{inc}";
\tpolicy_index pol{i};
}};

policy pol{i} {{
\taction auto_ipsec;
\tremote_index labB_resp{i};
\tipsec_mode tunnel;
\tipsec_index {{ ipsec_e; }};
\tipsec_level require;
\tpeers_sa_ipaddr "{ouc}";
\tmy_sa_ipaddr "{resp_outer}";
}};
""")
    parts.append("""
ipsec ipsec_e {
\tipsec_sa_lifetime_time 3600 sec;
\tsa_index esp_e;
};

sa esp_e {
\tsa_protocol esp;
\tesp_enc_alg { aes_gcm; };
\tesp_auth_alg { non_auth; };
};
""")
    return "\n".join(parts)

def main():
    N = int(os.environ.get("NINIT", "4"))
    outer_base = octet(os.environ.get("OUTER_BASE", "10.77.0.2"), 0)  # 10.77.0.2
    inner_base = octet(os.environ.get("INNER_BASE", "192.0.2.2"), 0)  # 192.0.2.2
    resp_outer = os.environ.get("RESP_OUTER", "10.77.0.1")
    resp_inner = os.environ.get("RESP_INNER", "192.0.2.1")
    # outer/inner_base hold the FIRST initiator's addr; derive base as prefix minus index 0
    oub = outer_base
    inb = inner_base
    ouc_list = [octet(oub, i) for i in range(N)]
    inc_list = [octet(inb, i) for i in range(N)]

    # responder config
    with open(f"{CFG}/racoonBmulti.conf", "w") as f:
        f.write(responder_conf(N, ouc_list, inc_list, resp_outer, resp_inner))
    # initiator configs
    for i in range(N):
        with open(f"{CFG}/racoonA{i}.conf", "w") as f:
            f.write(initiator_conf(i, ouc_list[i], inc_list[i], resp_outer, resp_inner))

    # ---- manifest (single source of truth for all harness scripts) ----
    lines = [
        f"NINIT={N}",
        f"OUTER_BASE={oub}",
        f"INNER_BASE={inb}",
        f"RESP_OUTER={resp_outer}",
        f"RESP_INNER={resp_inner}",
        f"CFG={CFG}",
        f"PSK={PSK}",
        "",
        "# i:NETNS:OUTER:INNER:DUMMY:SPMD_SOCK:IKED_SOCK:IKED_LOG:LABID",
    ]
    for i in range(N):
        lines.append(
            f"I{i}={i}:nsI{i}:{ouc_list[i]}:{inc_list[i]}:dummyI{i}:"
            f"/tmp/spmif-A{i}:/tmp/ikedA.sock-{i}:/tmp/ikedA{i}.log:lab.a{i}"
        )
    with open(f"{CFG}/lab.manifest", "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"generated N={N}: {CFG}/racoonA0..{N-1}.conf, racoonBmulti.conf, lab.manifest")

if __name__ == "__main__":
    main()
