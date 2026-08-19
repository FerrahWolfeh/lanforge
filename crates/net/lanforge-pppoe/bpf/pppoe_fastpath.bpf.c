// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Lanforge PPPoE High-Performance Data Plane eBPF Program
 *
 * Provides:
 *  1. Ingress Decapsulation (Generic / Native XDP):
 *     - Intercepts incoming PPPoE session frames (EtherType 0x8864).
 *     - Strips PPPoE Header (6B) + PPP Protocol (2B) = 8B via bpf_xdp_adjust_head.
 *     - Rewrites Ethernet Header to standard IPv4 (0x0800) or IPv6 (0x86DD).
 *     - Passes decapsulated IP packet directly to the Linux routing stack.
 *
 *  2. Egress Encapsulation & TCP MSS Clamping (TC BPF Classifier):
 *     - Intercepts outgoing IP packets on WAN interface.
 *     - Clamps TCP MSS on SYN packets down to 1452 (for 1492 MTU) with checksum update.
 *     - Prepends 8 bytes (Ethernet 0x8864 + PPPoE Header + PPP Protocol).
 *     - Transmits directly to the Access Concentrator.
 */

/* vmlinux.h provides all kernel struct definitions (ethhdr, iphdr, tcphdr,
 * pppoe_hdr, xdp_md, __sk_buff, etc.) compiled from the running kernel's BTF.
 * It must be included before bpf_helpers.h. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* EtherTypes — not exported by vmlinux.h */
#define ETH_P_IP      0x0800
#define ETH_P_IPV6    0x86DD
#define ETH_P_PPP_SES 0x8864

/* PPP Protocol numbers */
#define PPP_IP   0x0021
#define PPP_IPV6 0x0057

/* TC action codes — not exported by vmlinux.h */
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

/* Shared session config stored in BPF Map */
struct pppoe_session_val {
    __u16 session_id;
    __u16 mss_clamp;
    __u8  ac_mac[6];
    __u8  local_mac[6];
    __u32 local_ip;
    __u32 peer_ip;
    __u8  active;
    __u8  pad[3];
};

/* BPF Map: key is ifindex (u32), value is session info.
 * Uses the modern BTF-defined map style required by aya >= 0.13. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, struct pppoe_session_val);
} pppoe_sessions SEC(".maps");

#ifndef BPF_F_ADJ_ROOM_ENCAP_L2_ETH
#define BPF_F_ADJ_ROOM_ENCAP_L2_ETH (1ULL << 6)
#endif

/* ========================================================================= */
/* 1. INGRESS: XDP PPPoE Decapsulation                                       */
/* ========================================================================= */

SEC("xdp")
int pppoe_ingress_decap(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Bounds check: Ethernet (14B) + PPPoE (6B) + PPP proto (2B) = 22 bytes */
    if (data + sizeof(struct ethhdr) + sizeof(struct pppoe_hdr) + sizeof(__u16) > data_end) {
        return XDP_PASS;
    }

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_PPP_SES)) {
        return XDP_PASS;
    }

    struct pppoe_hdr *pppoe = (void *)(eth + 1);
    __u32 ifindex = ctx->ingress_ifindex;
    struct pppoe_session_val *sess = bpf_map_lookup_elem(&pppoe_sessions, &ifindex);
    if (!sess) {
        __u32 zero = 0;
        sess = bpf_map_lookup_elem(&pppoe_sessions, &zero);
    }
    if (!sess || !sess->active) {
        return XDP_PASS;
    }

    if (bpf_ntohs(pppoe->sid) != sess->session_id) {
        return XDP_PASS;
    }

    __u16 *ppp_proto = (void *)(pppoe + 1);
    __u16 new_proto = 0;
    if (*ppp_proto == bpf_htons(PPP_IP)) {
        new_proto = bpf_htons(ETH_P_IP);
    } else if (*ppp_proto == bpf_htons(PPP_IPV6)) {
        new_proto = bpf_htons(ETH_P_IPV6);
    } else {
        /* Control protocols (LCP, IPCP, Auth, CCP) pass directly to the socket */
        return XDP_PASS;
    }

    /* Save original Ethernet MAC addresses before moving head */
    __u8 dst_mac[6];
    __u8 src_mac[6];
    dst_mac[0] = eth->h_dest[0];
    dst_mac[1] = eth->h_dest[1];
    dst_mac[2] = eth->h_dest[2];
    dst_mac[3] = eth->h_dest[3];
    dst_mac[4] = eth->h_dest[4];
    dst_mac[5] = eth->h_dest[5];

    src_mac[0] = eth->h_source[0];
    src_mac[1] = eth->h_source[1];
    src_mac[2] = eth->h_source[2];
    src_mac[3] = eth->h_source[3];
    src_mac[4] = eth->h_source[4];
    src_mac[5] = eth->h_source[5];

    /* Move packet head forward by 8 bytes (stripping 6B PPPoE + 2B PPP proto) */
    if (bpf_xdp_adjust_head(ctx, 8) < 0) {
        return XDP_PASS;
    }

    /* Re-evaluate pointers after adjusting head */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }

    /* Write updated Ethernet header at the new head using fixed offsets */
    struct ethhdr *out_eth = data;
    out_eth->h_dest[0] = dst_mac[0];
    out_eth->h_dest[1] = dst_mac[1];
    out_eth->h_dest[2] = dst_mac[2];
    out_eth->h_dest[3] = dst_mac[3];
    out_eth->h_dest[4] = dst_mac[4];
    out_eth->h_dest[5] = dst_mac[5];

    out_eth->h_source[0] = src_mac[0];
    out_eth->h_source[1] = src_mac[1];
    out_eth->h_source[2] = src_mac[2];
    out_eth->h_source[3] = src_mac[3];
    out_eth->h_source[4] = src_mac[4];
    out_eth->h_source[5] = src_mac[5];

    out_eth->h_proto = new_proto;

    return XDP_PASS;
}

/* ========================================================================= */
/* 2. EGRESS: TC PPPoE Encapsulation                                         */
/* ========================================================================= */

SEC("classifier")
int pppoe_egress_encap(struct __sk_buff *skb) {
    __u32 ifindex = skb->ifindex;
    struct pppoe_session_val *sess = bpf_map_lookup_elem(&pppoe_sessions, &ifindex);
    if (!sess) {
        __u32 zero = 0;
        sess = bpf_map_lookup_elem(&pppoe_sessions, &zero);
    }
    if (!sess || !sess->active) {
        return TC_ACT_OK;
    }

    /* Load Ethernet header (at TC egress, skb->data points to MAC header offset 0) */
    struct ethhdr eth;
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) {
        return TC_ACT_OK;
    }

    __u16 ppp_proto = 0;
    if (eth.h_proto == bpf_htons(ETH_P_IP)) {
        ppp_proto = bpf_htons(PPP_IP);
    } else if (eth.h_proto == bpf_htons(ETH_P_IPV6)) {
        ppp_proto = bpf_htons(PPP_IPV6);
    } else {
        /* Already PPPoE or non-IP frame, don't re-encapsulate */
        return TC_ACT_OK;
    }

#ifndef BPF_F_ADJ_ROOM_NO_CSUM_RESET
#define BPF_F_ADJ_ROOM_NO_CSUM_RESET (1ULL << 5)
#endif

    /* Expand room at MAC layer by 8 bytes for the PPPoE header + PPP proto.
     * Use BPF_F_ADJ_ROOM_NO_CSUM_RESET to preserve valid software-calculated checksums (CHECKSUM_NONE). */
    int ret = bpf_skb_adjust_room(skb, 8, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_NO_CSUM_RESET);
    if (ret < 0) {
        return TC_ACT_OK;
    }

    /* PPPoE payload length = skb length minus Ethernet (14B) minus PPPoE header (6B) */
    __u16 payload_len = (__u16)(skb->len - 14 - 6);

    /* Construct PPPoE header with designated initializer to avoid uninitialized bitfield read */
    struct pppoe_hdr phdr = {
        .ver      = 1,
        .type     = 1,
        .code     = 0x00,
        .sid      = bpf_htons(sess->session_id),
        .length   = bpf_htons(payload_len),
    };

    /* Construct new Ethernet header with direct byte assignments */
    struct ethhdr new_eth;
    new_eth.h_dest[0] = sess->ac_mac[0];
    new_eth.h_dest[1] = sess->ac_mac[1];
    new_eth.h_dest[2] = sess->ac_mac[2];
    new_eth.h_dest[3] = sess->ac_mac[3];
    new_eth.h_dest[4] = sess->ac_mac[4];
    new_eth.h_dest[5] = sess->ac_mac[5];

    new_eth.h_source[0] = sess->local_mac[0];
    new_eth.h_source[1] = sess->local_mac[1];
    new_eth.h_source[2] = sess->local_mac[2];
    new_eth.h_source[3] = sess->local_mac[3];
    new_eth.h_source[4] = sess->local_mac[4];
    new_eth.h_source[5] = sess->local_mac[5];

    new_eth.h_proto = bpf_htons(ETH_P_PPP_SES);

    /* Write updated Ethernet header */
    bpf_skb_store_bytes(skb, 0, &new_eth, sizeof(new_eth), 0);
    /* Write PPPoE header at offset 14 */
    bpf_skb_store_bytes(skb, 14, &phdr, sizeof(phdr), 0);
    /* Write PPP protocol field at offset 20 */
    bpf_skb_store_bytes(skb, 20, &ppp_proto, sizeof(ppp_proto), 0);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
