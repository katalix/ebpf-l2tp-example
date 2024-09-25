/*****************************************************************************
 * Copyright (C) 2024 Katalix Systems Ltd
 *****************************************************************************/
#ifndef MAPS_H
#define MAPS_H

#include <stdint.h>

/**
 * Mapping structures for defining an L2TP datapath.
 */

/**
 * L2TP-encapsulated lookup key.
 */
struct encap_session_key {
    /* Source and destination address/port */
    struct ipaddr {
        union {
            uint32_t v6[4];
            uint32_t v4;
        } ip;
        uint16_t port;
    } local, peer;
    /* Address family (AF_INET/6) */
    uint16_t family;
    /* IP protocol (IPPROTO_UDP) */
    uint8_t protocol;
    /* L2TP version per the L2TP header: 2 for L2TPv2, 3 for L2TPv3 */
    uint8_t l2tp_version;
    /* L2TP ID (16 bit tunnel id + 16 bit session ID for L2TPv2, 32 bit session ID for L2TPv3 */
    uint32_t l2tp_id;
};

/**
 * L2TP datapath session context.
 */
struct l2tp_session_ctx {
    struct {
        /* index of eth interface for decapsulated packets */
        uint32_t ifindex;
        uint8_t mac[6];
    } decap_path;
    struct {
        /* index of eth interface for encapsualted packets */
        uint32_t ifindex;
        uint8_t mac[6];
        /* encapsulation metadata */
        struct encap_session_key meta;
    } encap_path;
    uint32_t peer_l2tp_id;
};
#endif
