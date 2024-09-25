# l2tp-test.sh ns1/ns2 configuration helpers ebpf
#
# Note that "ip netns exec" creates a new mountpoint for
# /sys/fs/bpf each time it is executed.  Hence we must do
# all the ebpf setup in the context of one exec call as the
# pinned maps won't be visible in the filesystem across
# exec calls.

readonly _NS1_SETUP_SCRIPT="$(mktemp)"
readonly _NS2_SETUP_SCRIPT="$(mktemp)"

addr_is_ipv6() { [[ $1 == *:* ]]; }

# $1 -- ip address
# $2 -- port
# $3 -- encap
build_addr_string()
{
    local addr="$1"
    local port="$2"

    # Set port to zero if we're not using UDP encap
    if test "$3" != "udp"
    then
        port=0
    fi

    # If address is IPv6, wrap in braces to allow port spec
    if addr_is_ipv6 $addr
    then
        addr="[$addr]"
    fi

    echo "$addr:$port"
}

# $1 -- ifname for encapsualted traffic
# $2 -- ifname for decapsulated traffic
# $3 -- encap type
# $4 -- local ip address
# $5 -- local udp port
# $6 -- local session ID
# $7 -- peer ip address
# $8 -- peer udp port
# $9 -- peer session ID
gen_overlay_script()
{
    local laddr=$(build_addr_string $4 $5 $3)
    local paddr=$(build_addr_string $7 $8 $3)

    cat << __EOF__
#!/bin/bash -e

# \$1 -- interface
# \$2 -- flavour [encap|decap]
setup_clsact()
{
    (
        flock 9
        tc qdisc show dev \$1 | grep clsact || {
            tc qdisc add dev \$1 clsact
            tc filter add dev \$1 \\
                ingress bpf da obj ./ebpf_clsact.o sec cls_act/\$2
        }
        ip link set dev \$1 up
        ip link set dev \$1 promisc on
    ) 9> /tmp/prol2tp-tclock
}

setup_clsact $1 decap
setup_clsact $2 encap

./map_session \
    -x $3 \
    -l "$laddr" \
    -p "$paddr" \
    -i $6 \
    -I $9 \
    -E "\$(cat /sys/class/net/$1/ifindex)" \
    -D "\$(cat /sys/class/net/$2/ifindex)"

sysctl net.ipv6.conf.all.forwarding=1
sysctl net.ipv4.ip_forward=1
__EOF__
}

setup_ebpf_overlay_ns1()
{
    local LOCAL_IP_ADDR="$1"
    local LOCAL_UDP_PORT="$L2TP_UDP_PORT_1"
    local LOCAL_SID="$L2TP_SID_1"
    local PEER_IP_ADDR="$2"
    local PEER_UDP_PORT="$L2TP_UDP_PORT_2"
    local PEER_SID="$L2TP_SID_2"
    local ENCAP="$3"

    gen_overlay_script \
        veth12 \
        veth10 \
        $ENCAP \
        $LOCAL_IP_ADDR \
        $LOCAL_UDP_PORT \
        $LOCAL_SID \
        $PEER_IP_ADDR \
        $PEER_UDP_PORT \
        $PEER_SID > $_NS1_SETUP_SCRIPT

    chmod +x $_NS1_SETUP_SCRIPT
    ip netns exec "${NS1}" $_NS1_SETUP_SCRIPT
}

setup_ebpf_overlay_ns2()
{
    local LOCAL_IP_ADDR="$1"
    local LOCAL_UDP_PORT="$L2TP_UDP_PORT_2"
    local LOCAL_SID="$L2TP_SID_2"
    local PEER_IP_ADDR="$2"
    local PEER_UDP_PORT="$L2TP_UDP_PORT_1"
    local PEER_SID="$L2TP_SID_1"
    local ENCAP="$3"

    gen_overlay_script \
        veth21 \
        veth23 \
        $ENCAP \
        $LOCAL_IP_ADDR \
        $LOCAL_UDP_PORT \
        $LOCAL_SID \
        $PEER_IP_ADDR \
        $PEER_UDP_PORT \
        $PEER_SID > $_NS2_SETUP_SCRIPT

    chmod +x $_NS2_SETUP_SCRIPT
    ip netns exec "${NS2}" $_NS2_SETUP_SCRIPT
}

cleanup_ebpf_overlay()
{
    rm -f $_NS1_SETUP_SCRIPT
    rm -f $_NS2_SETUP_SCRIPT
}

cleanup_ebpf_overlay_ns1() { cleanup_ebpf_overlay; }
cleanup_ebpf_overlay_ns2() { cleanup_ebpf_overlay; }
