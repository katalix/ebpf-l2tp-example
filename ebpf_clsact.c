/*****************************************************************************
 * Copyright (C) 2024 Katalix Systems Ltd
 *****************************************************************************/
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <sys/socket.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "maps.h"

#ifndef IPPROTO_L2TP
#define IPPROTO_L2TP 115
#endif

#define MAX_SESSIONS 256

/* Mapping encapsulated packets to session context */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SESSIONS);
    __type(key, struct encap_session_key);
    __type(value, struct l2tp_session_ctx);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} l2tp_session_map SEC(".maps");

/* Mapping decapsulated packets to session context.
 * The key here is just the ifindex of the interface
 * receiving the frame.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SESSIONS);
    __type(key, uint32_t);
    __type(value, struct l2tp_session_ctx);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} eth_session_map SEC(".maps");

struct l2tpv3udp_hdr {
    uint16_t flagver;
    uint16_t reserved;
    uint32_t session_id;
    /* TODO: This is optional, and should be managed by the control plane */
    uint32_t l2specific_sublayer;
};

struct l2tpv3ip_hdr {
    uint32_t session_id;
    /* TODO: This is optional, and should be managed by the control plane */
    uint32_t l2specific_sublayer;
};

//#define VERBOSE_LOGGING

#ifdef VERBOSE_LOGGING
#define _verbose(_fmt, ...) do { \
    const char fstr[] = _fmt; \
    bpf_trace_printk(fstr, sizeof(fstr), ##__VA_ARGS__); \
} while(0)
#else
#define _verbose(_fmt, ...)
#endif

#define _err(_fmt, ...) do { \
    const char fstr[] = _fmt; \
    bpf_trace_printk(fstr, sizeof(fstr), ##__VA_ARGS__); \
} while(0)

#define skb_ptr(_p) \
    ((char *)(long)(_p))

#define mac_addr_is_unset(_addr) \
     ((_addr)[0] == 0x00 && \
    (_addr)[1] == 0x00 && \
    (_addr)[2] == 0x00 && \
    (_addr)[3] == 0x00 && \
    (_addr)[4] == 0x00 && \
    (_addr)[5] == 0x00)

static void *skb_pullb(struct __sk_buff *skb, char **dptr, size_t nbytes)
{
    char *end = skb_ptr(skb->data_end);
    void *out = NULL;
    if (*dptr + nbytes <= end) {
        out = *dptr;
        *dptr += nbytes;
    }
    return out;
}

static void *skb_pullb_at(struct __sk_buff *skb, char **dptr, size_t nbytes, size_t offset)
{
    return skb_pullb(skb, dptr, offset) ? skb_pullb(skb, dptr, nbytes) : NULL;
}

static bool skb_wrapb(struct __sk_buff *skb, void *hdr, size_t hdrlen)
{
    long ret;

    ret = bpf_skb_change_head(skb, hdrlen, 0);
    if (ret) {
        _err("encap: bpf_skb_change_head: %d", ret);
        return false;
    }

    ret = bpf_skb_store_bytes(skb, 0, hdr, hdrlen, BPF_F_INVALIDATE_HASH);
    if (ret) {
        _err("encap: bpf_skb_store_bytes: %d", ret);
        return false;
    }

    return true;
}

static bool parse_key(struct __sk_buff *skb, struct encap_session_key *key, long *encap_len)
{
    char *data = skb_ptr(skb->data);
    struct ethhdr *eth;

    /* Ethernet */
    if (!(eth = skb_pullb(skb, &data, sizeof(*eth))))
        return false;

    __builtin_memset(key, 0, sizeof(*key));

    /* Ethernet pseudowires are L2TPv3-only */
    key->l2tp_version = 3;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip;

        if (!(ip = skb_pullb(skb, &data, sizeof(*ip))))
            return false;

        key->family = AF_INET;
        key->local.ip.v4 = ip->addrs.daddr;
        key->peer.ip.v4 = ip->addrs.saddr;
        key->protocol = ip->protocol;

    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip;

        if (!(ip = skb_pullb(skb, &data, sizeof(*ip))))
            return false;

        key->family = AF_INET6;
        memcpy(&key->local.ip.v6, &ip->daddr.in6_u, 4*sizeof(uint32_t));
        memcpy(&key->peer.ip.v6, &ip->saddr.in6_u, 4*sizeof(uint32_t));
        /* TODO: handle extension headers */
        key->protocol = ip->nexthdr;
    } else {
        return false;
    }

    /* UDP encap and IP encap have different L2TP headers */
    if (key->protocol == IPPROTO_UDP) {
        struct l2tpv3udp_hdr *l2tp;
        struct udphdr *udp;

        if (!(udp = skb_pullb(skb, &data, sizeof(*udp))))
            return false;

        if (!(l2tp = skb_pullb(skb, &data, sizeof(*l2tp))))
            return false;

        key->local.port = udp->dest;
        key->peer.port = udp->source;
        key->l2tp_id = bpf_ntohl(l2tp->session_id);

        *encap_len = data - skb_ptr(skb->data);

    } else if (key->protocol == IPPROTO_L2TP) {
        struct l2tpv3ip_hdr *l2tp;

        if (!(l2tp = skb_pullb(skb, &data, sizeof(*l2tp))))
            return false;

        key->l2tp_id = bpf_ntohl(l2tp->session_id);

        *encap_len = data - skb_ptr(skb->data);

    } else {
        _err("decap: unhandled encap protocol %u", key->protocol);
        return false;
    }

    return true;
}

SEC("cls_act/decap")
int decap(struct __sk_buff *skb)
{
    uint64_t adj_room_flags = BPF_F_ADJ_ROOM_FIXED_GSO;
    struct l2tp_session_ctx *sctx;
    struct encap_session_key key;
    long encap_len;
    int ret;

    if (!parse_key(skb, &key, &encap_len))
        return TC_ACT_OK;

    _verbose("decap: l2tp version %u id %u: %d bytes encap", key.l2tp_version, key.l2tp_id, encap_len);
    _verbose("decap: family %u, protocol %u", key.family, key.protocol);
    _verbose("decap: local addr %u %u", key.local.ip.v4, key.local.port);
    _verbose("decap: peer addr %u %u", key.peer.ip.v4, key.peer.port);

    /* Figure out where we're sending the de-encapsulated packet */
    sctx = bpf_map_lookup_elem(&l2tp_session_map, &key);
    if (!sctx) {
        _verbose("decap: no map entry");
        return TC_ACT_OK;
    }
    _verbose("decap: %u bytes: ifndex %u to ifindex %u", encap_len, skb->ifindex, sctx->decap_path.ifindex);

    /* Copy inner eth header and rewrite outer eth header */
    {
        struct ethhdr *eth_inner, *eth_outer;

        {
            char *data = skb_ptr(skb->data);
            eth_inner = skb_pullb_at(skb, &data, sizeof(*eth_inner), 0xfff & encap_len);
        }

        {
            char *data = skb_ptr(skb->data);
            eth_outer = skb_pullb_at(skb, &data, sizeof(*eth_outer), 0);
        }

        if (eth_outer && eth_inner) {
            *eth_outer = *eth_inner;
        } else {
            _err("decap: eth rewrite failed");
            return TC_ACT_SHOT;
        }
    }

    /* Remove outer IP/UDP/L2TP and inner eth headers*/
#ifdef HAVE_BPF_F_ADJ_ROOM_DECAP_L3_IPV4
    adj_room_flags |= BPF_F_ADJ_ROOM_DECAP_L3_IPV4;
#endif
    ret = bpf_skb_adjust_room(skb, -encap_len, BPF_ADJ_ROOM_MAC, adj_room_flags);
    if (ret) {
        _err("decap: bpf_skb_adjust_room %d %d", encap_len, ret);
        return TC_ACT_SHOT;
    }

    return bpf_redirect(sctx->decap_path.ifindex, 0);
}

/* from Linux tools/testing/selftests/bpf/progs/test_tc_tunnel.c */
static __always_inline void set_ipv4_csum(struct iphdr *iph)
{
    uint16_t *iph16 = (uint16_t *)iph;
    uint32_t csum = 0;
    int i;

    iph->check = 0;

    for (i = 0; i < sizeof(*iph) >> 1; i++)
        csum += *iph16++;

    iph->check = ~((csum & 0xffff) + (csum >> 16));
}

static bool sctx_mac_resolve(struct __sk_buff *skb, struct l2tp_session_ctx *sctx)
{
    if (mac_addr_is_unset(sctx->encap_path.mac) || mac_addr_is_unset(sctx->decap_path.mac)) {
        struct bpf_fib_lookup fib_params = {};
        long fib_ret;

        fib_params.family = sctx->encap_path.meta.family;
        fib_params.l4_protocol = sctx->encap_path.meta.protocol;
        fib_params.sport = sctx->encap_path.meta.local.port;
        fib_params.dport = sctx->encap_path.meta.peer.port;
        fib_params.ifindex = sctx->encap_path.ifindex;
        if (sctx->encap_path.meta.family == AF_INET) {
            fib_params.ipv4_src = sctx->encap_path.meta.local.ip.v4;
            fib_params.ipv4_dst = sctx->encap_path.meta.peer.ip.v4;
        } else if (sctx->encap_path.meta.family == AF_INET6) {
            memcpy(fib_params.ipv6_src, sctx->encap_path.meta.local.ip.v6, 4*sizeof(uint32_t));
            memcpy(fib_params.ipv6_dst, sctx->encap_path.meta.peer.ip.v6, 4*sizeof(uint32_t));
        } else {
            _err("encap: unsupported address family");
        }
        fib_ret = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_OUTPUT);
        if (fib_ret == BPF_FIB_LKUP_RET_SUCCESS) {
            memcpy(sctx->encap_path.mac, fib_params.dmac, ETH_ALEN);
            memcpy(sctx->decap_path.mac, fib_params.smac, ETH_ALEN);
        } else {
            _err("encap: bpf_fib_lookup(): %u", fib_ret);
            return false;
        }
    }
    return true;
}

#ifdef HAVE_BPF_LOOP_HELPER
static uint16_t csum_final(unsigned long csum)
{
    while (csum >> 16)
        csum = (csum & 0xffff) + (csum >> 16);
    return ~csum;
}

static unsigned long csum_add(const uint16_t *dptr, size_t count, unsigned long csum)
{
    size_t i;
    for (i = 0; i < count; i++)
        csum += bpf_ntohs(dptr[i]);
    return csum;
}

static unsigned long build_udp_v6_pseudo_csum(const struct ipv6hdr *ip6h)
{
    unsigned long pseudo_sum = 0;

    pseudo_sum = csum_add(ip6h->saddr.in6_u.u6_addr16, 8, pseudo_sum);
    pseudo_sum = csum_add(ip6h->daddr.in6_u.u6_addr16, 8, pseudo_sum);
    pseudo_sum += bpf_ntohs(ip6h->payload_len);
    pseudo_sum += ip6h->nexthdr;

    return pseudo_sum;
}

struct ipv6_udp_csum_ctx {
    struct __sk_buff *skb;
    char *dptr;
    unsigned long csum;
};

static int ipv6_udp_csum_cb(uint32_t idx, void *dptr)
{
    struct ipv6_udp_csum_ctx *ctx = dptr;
    uint16_t *pword;
    uint8_t *pchar;

    pword = skb_pullb(ctx->skb, &ctx->dptr, sizeof(*pword));
    if (pword) {
        ctx->csum += bpf_ntohs(*pword);
        return 0;
    }

    pchar = skb_pullb(ctx->skb, &ctx->dptr, sizeof(*pchar));
    if (pchar) {
        ctx->csum += *pchar;
        return 0;
    }

    return 1;
}
#endif

static uint16_t calc_iphdr_len(struct l2tp_session_ctx *sctx, struct __sk_buff *skb)
{
    uint16_t len = skb->len;

    if (sctx->encap_path.meta.family == AF_INET)
        len += sizeof(struct iphdr);

    if (sctx->encap_path.meta.protocol == IPPROTO_UDP) {
        len += sizeof(struct udphdr);
        len += sizeof(struct l2tpv3udp_hdr);
    } else {
        len += sizeof(struct l2tpv3ip_hdr);
    }

    return bpf_htons(len);
}

SEC("cls_act/encap")
int encap(struct __sk_buff *skb)
{
    size_t idx = 0, udp_off = 0, ip6_off = 0, l2tp_off = 0;
    struct l2tp_session_ctx *sctx;
    uint32_t key = skb->ifindex;
    uint8_t encap_header[128];

    sctx = bpf_map_lookup_elem(&eth_session_map, &key);
    if (!sctx) {
        _verbose("encap: no map entry");
        return TC_ACT_OK;
    }

#define buf_append(_buf, _idx, _dptr) do { \
    if (sizeof(*(_dptr)) > sizeof(_buf)-_idx) { \
        return TC_ACT_OK; \
    } else { \
        memcpy(&((_buf)[_idx]), _dptr, sizeof(*(_dptr))); \
        _idx += sizeof(*(_dptr)); \
    } \
} while(0)

    /* Wrap with eth header */
    {
        struct ethhdr eth = {
            .h_proto = bpf_htons(sctx->encap_path.meta.family == AF_INET ? ETH_P_IP : ETH_P_IPV6),
        };

        if (!sctx_mac_resolve(skb, sctx))
            return TC_ACT_SHOT;

        memcpy(eth.h_dest, sctx->encap_path.mac, ETH_ALEN);
        memcpy(eth.h_source, sctx->decap_path.mac, ETH_ALEN);

        buf_append(encap_header, idx, &eth);
    }

    /* Wrap with IP header */
    if (sctx->encap_path.meta.family == AF_INET) {
        /* TODO: meaningful values for tos, id, and frag_off fields */
        struct iphdr ip = {
            .version = IPVERSION,
            .ihl = 5,
            .tos = 0,
            .tot_len = calc_iphdr_len(sctx, skb),
            .id = 0,
            .frag_off = 0,
            .ttl = 0xff,
            .protocol = sctx->encap_path.meta.protocol,
            .saddr = sctx->encap_path.meta.local.ip.v4,
            .daddr = sctx->encap_path.meta.peer.ip.v4,
        };

        set_ipv4_csum(&ip);

        buf_append(encap_header, idx, &ip);

    } else if (sctx->encap_path.meta.family == AF_INET6) {
        /* TODO: meaningful values for priority, flow_lbl and hop_limit fields */
        struct ipv6hdr ip = {
            .version = 6,
            .priority = 0,
            .flow_lbl = {0, 0, 0},
            .payload_len = calc_iphdr_len(sctx, skb),
            .nexthdr = sctx->encap_path.meta.protocol == IPPROTO_UDP ? IPPROTO_UDP : IPPROTO_L2TP,
            .hop_limit = 0xff,
        };

        memcpy(ip.saddr.in6_u.u6_addr32, sctx->encap_path.meta.local.ip.v6, 4*sizeof(uint32_t));
        memcpy(ip.daddr.in6_u.u6_addr32, sctx->encap_path.meta.peer.ip.v6, 4*sizeof(uint32_t));

        ip6_off = idx;
        buf_append(encap_header, idx, &ip);
    }

    /* Wrap with UDP header */
    if (sctx->encap_path.meta.protocol == IPPROTO_UDP) {
        struct udphdr udp = {
            .source = sctx->encap_path.meta.local.port,
            .dest = sctx->encap_path.meta.peer.port,
            .check = 0,
            .len = bpf_htons(skb->len + sizeof(struct udphdr) + sizeof(struct l2tpv3udp_hdr)),
        };
        udp_off = idx;
        buf_append(encap_header, idx, &udp);
    }

    /* Wrap with L2TPv3 header */
    if (sctx->encap_path.meta.protocol == IPPROTO_UDP) {
        struct l2tpv3udp_hdr l2tp = {
            .flagver = 0x0300,
            .reserved = 0,
            .session_id = bpf_htonl(sctx->peer_l2tp_id),
        };
        l2tp_off = idx;
        buf_append(encap_header, idx, &l2tp);
    } else if (sctx->encap_path.meta.protocol == IPPROTO_L2TP) {
        struct l2tpv3ip_hdr l2tp = {
            .session_id = bpf_htonl(sctx->peer_l2tp_id),
        };
        buf_append(encap_header, idx, &l2tp);
    }

    /* For IPv6/UDP, the UDP checksum must be calculated */
    if (sctx->encap_path.meta.family == AF_INET6 && ip6_off && udp_off && l2tp_off) {
#ifdef HAVE_BPF_LOOP_HELPER
        struct l2tpv3udp_hdr *l2tp = (struct l2tpv3udp_hdr *)&encap_header[l2tp_off];
        struct ipv6hdr *ip = (struct ipv6hdr *)&encap_header[ip6_off];
        struct udphdr *udp = (struct udphdr *)&encap_header[udp_off];
        struct ipv6_udp_csum_ctx csum_ctx = {
            .skb = skb,
            .dptr = skb_ptr(skb->data),
            .csum = build_udp_v6_pseudo_csum(ip),
        };
        csum_ctx.csum = csum_add((void*)udp, sizeof(*udp)/2, csum_ctx.csum);
        csum_ctx.csum = csum_add((void*)l2tp, sizeof(*l2tp)/2, csum_ctx.csum);
        bpf_loop(UINT16_MAX/2, ipv6_udp_csum_cb, &csum_ctx, 0);
        udp->check = bpf_ntohs(csum_final(csum_ctx.csum));
#endif
    }

    if (!skb_wrapb(skb, encap_header, idx))
        return TC_ACT_SHOT;

    _verbose("encap: l2tp session %u", sctx->peer_l2tp_id);
    _verbose("encap: ifindex %u to ifindex %u: %d bytes encap", skb->ifindex, sctx->encap_path.ifindex, idx);
    return bpf_redirect(sctx->encap_path.ifindex, 0);
}

char __license[] SEC("license") = "GPL";
