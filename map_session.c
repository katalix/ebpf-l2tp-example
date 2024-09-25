/*****************************************************************************
 * Copyright (C) 2024 Katalix Systems Ltd
 *****************************************************************************/
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/in.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <sys/syscall.h>

#include <regex.h>

#include "maps.h"

#ifndef IPPROTO_L2TP
#define IPPROTO_L2TP 115
#endif

#define die(fmt, ...) do { \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
    exit(EXIT_FAILURE); \
} while(0)

/* Syscall wrapper missing in glibc */
static inline int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

static void usage(const char *myname)
{
    printf("Name:   %s\n", myname);
    printf("Desc:   create ebpf L2TP datapath mapping\n");
    printf("Usage:  %s [options]\n", myname);
    printf(
           "        -h      print this usage information\n"
           "        -l      local address\n"
           "        -p      peer address\n"
           "        -x      encap (udp or ip, udp default)\n"
           "        -i      l2tp id\n"
           "        -I      peer l2tp id\n"
           "        -E      encap ifindex (interface to send/receive L2TP-encap frames)\n"
           "        -D      decap ifindex (interface to send/receive decapsulated frames)\n"
           );
}

static bool re_match(const char *str, const char *regex)
{
    assert(str);
    assert(regex);

    regex_t re;
    int ret;

    if (regcomp(&re, regex, REG_EXTENDED|REG_NOSUB)) return false;
    ret = regexec(&re, str, 0,  NULL, 0);
    regfree(&re);
    return ret == 0;
}

static bool is_ipv4_address(const char *str)
{
    assert(str);
    const char *ipv4_addr = "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}";
    return re_match(str, ipv4_addr);
}

static bool is_ipv6_address(const char *str)
{
    assert(str);
    const char *ipv6_addr = "[0-9a-fA-F:\\.]+";
    return re_match(str, ipv6_addr);
}

#define do_parse_base10_value_x_after_delimiter(_s, _delim, _x, _out, _min, _max, _dflt) do { \
    if ((_s) && (_out)) { \
        char *p = strchr((_s), _delim); \
        errno = 0; \
        if (p) { \
            char *end = NULL; \
            long val = strtol(p+_x, &end, 10); \
            if (!errno && end != NULL && end[0] == '\0' && val >= (_min) && val <= (_max)) { \
                *(_out) = val; \
                *p = '\0'; \
                return true; \
            } \
        } else { \
            *(_out) = _dflt; \
            return true; \
        } \
    } \
    return false; \
} while(0)

static bool parse_v4_port_suffix(char *str, uint16_t dflt, uint16_t *port)
{
    do_parse_base10_value_x_after_delimiter(str, ':', 1, port, 0, 65535, dflt);
}

static bool ipv4_parse(char *str, struct sockaddr_in *addr)
{
    if (str) {
        uint16_t port = 0;
        if (parse_v4_port_suffix(str, port, &port)) {
            if (inet_pton(AF_INET, str, &addr->sin_addr)) {
                addr->sin_family = AF_INET;
                addr->sin_port = htons(port);
                return true;
            }
        }
    }
    return false;
}

static bool parse_v6_port_suffix(char *str, uint16_t dflt, uint16_t *port)
{
    do_parse_base10_value_x_after_delimiter(str, ']', 2, port, 0, 65535, dflt);
}

static bool ipv6_parse(char *str, struct sockaddr_in6 *addr)
{
    if (str) {
        uint16_t port = 0;
        if (str[0] == '[') str++;
        if (parse_v6_port_suffix(str, port, &port)) {
            if (1 == inet_pton(AF_INET6, str, &addr->sin6_addr)) {
                addr->sin6_family = AF_INET6;
                addr->sin6_port = htons(port);
                addr->sin6_flowinfo = 0;
                addr->sin6_scope_id = 0;
                return true;
            }
        }
    }
    return false;
}

static bool str_to_ss(char *str, struct sockaddr_storage *out)
{
    assert(str);
    assert(out);

    if (is_ipv4_address(str)) {
        struct sockaddr_in *addr = (struct sockaddr_in*)out;
        return ipv4_parse(str, addr);
    } else if (is_ipv6_address(str)) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6*)out;
        return ipv6_parse(str, addr);
    }

    return false;
}

static bool parse_address(char *str, struct ipaddr *out, uint16_t *family)
{
    assert(str);
    assert(out);

    struct sockaddr_storage ss = {};

    if (!str_to_ss(str, &ss)) return false;

    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)&ss;
        out->port = addr->sin_port;
        out->ip.v4 = addr->sin_addr.s_addr;
    } else if (ss.ss_family == AF_INET6) {
#ifndef HAVE_BPF_F_ADJ_ROOM_DECAP_L3_IPV4
        die("built without HAVE_BPF_F_ADJ_ROOM_DECAP_L3_IPV4, IPv6 encap support not available\n");
#endif
#ifndef HAVE_BPF_LOOP_HELPER
        die("built without HAVE_BPF_LOOP_HELPER, IPv6 encap support not available\n");
#endif
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&ss;
        out->port = addr->sin6_port;
        memcpy(out->ip.v6, &addr->sin6_addr, sizeof(out->ip.v6));
    } else return false;

    if (*family && *family != ss.ss_family)
        return false;

    *family = ss.ss_family;

    return true;
}

int main(int argc, char **argv)
{
    struct l2tp_session_ctx sctx = {};
    int opt;

    while ((opt = getopt(argc, argv, "hl:p:i:x:I:E:D:")) != -1) {
        switch (opt) {
            case 'h':
                usage(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            case 'l':
                if (!parse_address(optarg, &sctx.encap_path.meta.local, &sctx.encap_path.meta.family))
                    die("failed to parse local address\n");
                break;
            case 'p':
                if (!parse_address(optarg, &sctx.encap_path.meta.peer, &sctx.encap_path.meta.family))
                    die("failed to parse peer address\n");
                break;
            case 'i':
                sctx.encap_path.meta.l2tp_id = atoi(optarg);
                break;
            case 'x':
                if (0 == strcmp(optarg, "udp")) {
                    sctx.encap_path.meta.protocol = IPPROTO_UDP;
                } else if (0 == strcmp(optarg, "ip")) {
                    sctx.encap_path.meta.protocol = IPPROTO_L2TP;
                } else {
                    die("invalid encap type '%s'\n", optarg);
                }
                break;
            case 'I':
                sctx.peer_l2tp_id = atoi(optarg);
                break;
            case 'E':
                sctx.encap_path.ifindex = atoi(optarg);
                break;
            case 'D':
                sctx.decap_path.ifindex = atoi(optarg);
                break;
            default:
                die("failed to parse commandline args\n");
        }
    }

    if (!sctx.decap_path.ifindex) {
        die("no decap ifindex specified\n");
    } else if (!sctx.encap_path.ifindex) {
        die("no encap ifindex specified\n");
    } else if (!sctx.encap_path.meta.l2tp_id) {
        die("no l2tp id specified\n");
    }

    /* Ethernet pseudowires are L2TPv3 only */
    sctx.encap_path.meta.l2tp_version = 3;

    /* Update encap-path map */
#define L2TP_SESSION_MAP "/sys/fs/bpf/tc/globals/l2tp_session_map"
    {
        union bpf_attr attr = {
            .map_fd = bpf_obj_get(L2TP_SESSION_MAP),
            .key = (uint64_t)&sctx.encap_path.meta,
            .value = (uint64_t)&sctx,
            .flags = BPF_ANY
        };
        if (attr.map_fd < 0) die("failed to open map " L2TP_SESSION_MAP);
        if (bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr))) {
            perror("bpf(BPF_MAP_UPDATE_ELEM, " L2TP_SESSION_MAP ")");
            exit(EXIT_FAILURE);
        }
        printf("map_session: add entry for sid %u to map " L2TP_SESSION_MAP "\n",
                sctx.encap_path.meta.l2tp_id);
        close(attr.map_fd);
    }

    /* Update decap-path map */
#define ETH_SESSION_MAP "/sys/fs/bpf/tc/globals/eth_session_map"
    {
        union bpf_attr attr = {
            .map_fd = bpf_obj_get(ETH_SESSION_MAP),
            .key = (uint64_t)&sctx.decap_path.ifindex,
            .value = (uint64_t)&sctx,
            .flags = BPF_ANY
        };
        if (attr.map_fd < 0) die("failed to open map " ETH_SESSION_MAP);
        if (bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr))) {
            perror("bpf(BPF_MAP_UPDATE_ELEM, " ETH_SESSION_MAP ")");
            exit(EXIT_FAILURE);
        }
        close(attr.map_fd);
    }

    return EXIT_SUCCESS;
}
