#!/bin/bash -e

# Test l2tpv3 tunnel configurations.
#
# Network topology:
#
#   * A chain of 4 network namespaces, connected with veth pairs.
#
#   * NS0 and NS3 are at the extremities of the chain. They have one external
#     interface, which is assigned IP addresses to reach their peer.
#
#   * NS1 and NS2 are the intermediate namespaces. They use l2tp to
#     encapsulate the traffic, bridging traffic over the l2tp tunnel.
#
# +-----------------------------------------------------------------------+
# |                  NS0                                                  |
# |                                                                       |
# |   veth01:                                                             |
# |   ^  * IPv4 address: 192.0.1.100/32 peer 192.0.1.103/32               |
# |   |  * IPv6 address: 2001:db8::100/128 peer 2001:db8::103/128         |
# |   |                                                                   |
# +---+-------------------------------------------------------------------+
#     |
#     | Traffic type: ethernet
#     |
# +---+-------------------------------------------------------------------+
# |   |                  NS1                                              |
# |   |                                                                   |
# |   v                                                                   |
# |   veth10:                                                             |
# |                                                                       |
# |   l2tpeth12:                                                          |
# |                                                                       |
# |   l2tp:                                                               |
# |  * tunnel from 192.0.2.21 to 192.0.2.22                               |
# |  * tunnel from 2001:db8::21/128 to 2001:db8::22/128                   |
# |  * session interface l2tpeth12                                        |
# |  * bridge veth10 and l2tpeth12                                        |
# |                                                                       |
# |   veth12:                                                             |
# |   ^  * IPv4 address: 192.0.2.21/32, peer 192.0.2.22/32                |
# |   |  * IPv6 address: 2001:db8::21/128, peer 2001:db8::22/128          |
# |   |                                                                   |
# +---+-------------------------------------------------------------------+
#     |
#     | Traffic type: ethernet over L2TP
#     |
# +---+-------------------------------------------------------------------+
# |   |                  NS2                                              |
# |   |                                                                   |
# |   v                                                                   |
# |   veth21:                                                             |
# |  * IPv4 address: 192.0.2.22/32, peer 192.0.2.21/32                    |
# |  * IPv6 address: 2001:db8::22/128, peer 2001:db8::21/128              |
# |                                                                       |
# |   l2tpeth21:                                                          |
# |                                                                       |
# |   l2tp:                                                               |
# |  * tunnel from 192.0.2.22 to 192.0.2.21                               |
# |  * session interface l2tpeth21                                        |
# |  * bridge veth23 and l2tpeth21                                        |
# |                                                                       |
# |   veth23:                                                             |
# |   ^                                                                   |
# |   |                                                                   |
# |   |                                                                   |
# +---+-------------------------------------------------------------------+
#     |
#     | Traffic type: ethernet
#     |
# +---+-------------------------------------------------------------------+
# |   |                  NS3                                              |
# |   v                                                                   |
# |   veth32:                                                             |
# |  * IPv4 address: 192.0.1.103 peer 192.0.1.100                         |
# |  * IPv6 address: 2001:db8::103/128 peer 2001:db8::100/128             |
# |                                                                       |
# +-----------------------------------------------------------------------+

ERR=4 # Return 4 by default, which is the SKIP code for kselftest
PING6="ping"
PAUSE_ON_FAIL="no"
OPT_INTERACTIVE_DEBUG="no"
OPT_PCAPS="no"
OPT_TUNNEL_IPVER="ipv4"
OPT_ENCAP="udp"
OPT_L2TP_SESSION_SEQ=""
OPT_SETUP_OVERLAY_SCRIPT="l2tp-test_default.sh"

TCPDUMP_PID0=
TCPDUMP_PID1=
TCPDUMP_PID2=
TCPDUMP_PID3=

readonly NS0=$(mktemp -u ns0-XXXXXXXX)
readonly NS1=$(mktemp -u ns1-XXXXXXXX)
readonly NS2=$(mktemp -u ns2-XXXXXXXX)
readonly NS3=$(mktemp -u ns3-XXXXXXXX)
readonly INTERACTIVE_SHELL_RC=$(mktemp -u l2tp-test-XXXXXXXX.rc)

# L2TP tunnel addresses
readonly L2TP_IP4_1=192.0.2.21
readonly L2TP_IP4_2=192.0.2.22
readonly L2TP_IP6_1=2001:db8::21
readonly L2TP_IP6_2=2001:db8::22

# L2TP UDP ports
readonly L2TP_UDP_PORT_1=1701
readonly L2TP_UDP_PORT_2=1701

# L2TP tunnel/session ids
readonly L2TP_TID_1=12
readonly L2TP_TID_2=21
readonly L2TP_SID_1=1012
readonly L2TP_SID_2=1021

# Exit the script after having removed the network namespaces it created
#
# Parameters:
#
#   * The list of network namespaces to delete before exiting.
#
exit_cleanup()
{
    for ns in "$@"; do
        ip netns delete "${ns}" 2>/dev/null || true
    done

    if [ "${ERR}" -eq 4 ]; then
        echo "Error: Setting up the testing environment failed." >&2
    fi

    exit "${ERR}"
}

# Create the four network namespaces used by the script (NS0, NS1, NS2 and NS3)
#
# New namespaces are cleaned up manually in case of error, to ensure that only
# namespaces created by this script are deleted.
create_namespaces()
{
    ip netns add "${NS0}" || exit_cleanup
    ip netns add "${NS1}" || exit_cleanup "${NS0}"
    ip netns add "${NS2}" || exit_cleanup "${NS0}" "${NS1}"
    ip netns add "${NS3}" || exit_cleanup "${NS0}" "${NS1}" "${NS2}"
}

# The trap function handler
#
exit_cleanup_all()
{
    test -z "${TCPDUMP_PID0}" || ip netns exec "${NS0}" kill ${TCPDUMP_PID0}
    test -z "${TCPDUMP_PID1}" || ip netns exec "${NS1}" kill ${TCPDUMP_PID1}
    test -z "${TCPDUMP_PID2}" || ip netns exec "${NS2}" kill ${TCPDUMP_PID2}
    test -z "${TCPDUMP_PID3}" || ip netns exec "${NS3}" kill ${TCPDUMP_PID3}
    rm -f "${INTERACTIVE_SHELL_RC}"
    exit_cleanup "${NS0}" "${NS1}" "${NS2}" "${NS3}"
}

# Configure a network interface using a host route
#
# Parameters
#
#   * $1: the netns the network interface resides in,
#   * $2: the network interface name,
#   * $3: the local IPv4 address to assign to this interface,
#   * $4: the IPv4 address of the remote network interface,
#   * $5: the local IPv6 address to assign to this interface,
#   * $6: the IPv6 address of the remote network interface.
#
iface_config()
{
    local NS="${1}"; readonly NS
    local DEV="${2}"; readonly DEV
    local LOCAL_IP4="${3}"; readonly LOCAL_IP4
    local PEER_IP4="${4}"; readonly PEER_IP4
    local LOCAL_IP6="${5}"; readonly LOCAL_IP6
    local PEER_IP6="${6}"; readonly PEER_IP6

    ip -netns "${NS}" link set dev "${DEV}" up
    ip -netns "${NS}" address add dev "${DEV}" "${LOCAL_IP4}" peer "${PEER_IP4}"
    ip -netns "${NS}" address add dev "${DEV}" "${LOCAL_IP6}" peer "${PEER_IP6}" nodad
}

# Configure a bridge, adding a veth interface to that bridge
#
# Parameters
#
#   * $1: the netns the network interface resides in,
#   * $2: the network interface name,
#
iface_bridge_config()
{
    local NS="${1}"; readonly NS
    local DEV="${2}"; readonly DEV

    ip -netns "${NS}" link set dev "${DEV}" up promisc on
    ip -netns "${NS}" link add name "br_${NS}" type bridge
    ip -netns "${NS}" link set dev "br_${NS}" up
    ip -netns "${NS}" link set dev "${DEV}" master "br_${NS}"
}

# Create base networking topology:
#
#   * set up a veth pair to connect each netns in sequence (NS0 with NS1,
#     NS1 with NS2, etc.),
#   * add and IPv4 and an IPv6 address on each veth interface,
#   * add a bridge on intermediate notes, with one veth attached to it.
#     set in promiscuous mode
#
# The l2tp encapsulation isn't configured in setup_underlay(). That will be
# done just before running the reachability tests.
#
setup_underlay()
{
    ip link add name veth01 netns "${NS0}" type veth peer name veth10 netns "${NS1}"
    ip link add name veth12 netns "${NS1}" type veth peer name veth21 netns "${NS2}"
    ip link add name veth23 netns "${NS2}" type veth peer name veth32 netns "${NS3}"
    iface_config "${NS0}" veth01 192.0.1.100 192.0.1.103/32 2001:db8::100 2001:db8::103/128
    iface_bridge_config "${NS1}" veth10
    iface_config "${NS1}" veth12 ${L2TP_IP4_1} ${L2TP_IP4_2}/32 ${L2TP_IP6_1} ${L2TP_IP6_2}/128
    iface_config "${NS2}" veth21 ${L2TP_IP4_2} ${L2TP_IP4_1}/32 ${L2TP_IP6_2} ${L2TP_IP6_1}/128
    iface_bridge_config "${NS2}" veth23
    iface_config "${NS3}" veth32 192.0.1.103 192.0.1.100/32 2001:db8::103 2001:db8::100/128
}

setup_to_iproute2_tunnel_args()
{
    local NS="$1"
    local ENCAP="$2"
    local TUNNEL_ARGS1=""
    local TUNNEL_ARGS2=""

    case "${ENCAP}" in
        udp)
            TUNNEL_ARGS1="encap udp udp_sport ${L2TP_UDP_PORT_1} udp_dport ${L2TP_UDP_PORT_2}"
            TUNNEL_ARGS2="encap udp udp_sport ${L2TP_UDP_PORT_2} udp_dport ${L2TP_UDP_PORT_1}"
            ;;
        ip)
            TUNNEL_ARGS1="encap ip"
            TUNNEL_ARGS2="encap ip"
            ;;
        *)
            exit 1;
            ;;
    esac

    case "${NS}" in
        "${NS1}") echo "${TUNNEL_ARGS1}";;
        "${NS2}") echo "${TUNNEL_ARGS2}";;
        *) exit 1;;
    esac
}

setup_to_iproute2_session_args()
{
    local NS="$1"
    local SEQ1=""
    local SEQ2=""
    local SESSION_ARGS1=""
    local SESSION_ARGS2=""

    case "${NS}" in
        "${NS1}") echo "${SESSION_ARGS1}";;
        "${NS2}") echo "${SESSION_ARGS2}";;
        *) exit 1;;
    esac
}

setup_overlay_iproute2()
{
    local NS="$1"
    local ENCAP="$2"
    local LOCAL_IP="$3"
    local PEER_IP="$4"
    local LOCAL_TID="$5"
    local PEER_TID="$6"
    local LOCAL_SID="$7"
    local PEER_SID="$8"
    local TUNNEL_ARGS=""
    local SESSION_ARGS=""
    
    TUNNEL_ARGS=$(setup_to_iproute2_tunnel_args "${NS}" "${ENCAP}")
    SESSION_ARGS=$(setup_to_iproute2_session_args "${NS}")
    ip -netns "${NS}" l2tp add tunnel tunnel_id ${LOCAL_TID} peer_tunnel_id ${PEER_TID} \
       local "${LOCAL_IP}" remote "${PEER_IP}" ${TUNNEL_ARGS}
    ip -netns "${NS}" l2tp add session name l2tpeth12 tunnel_id ${LOCAL_TID} \
       session_id ${LOCAL_SID} peer_session_id ${PEER_SID} ${SESSION_ARGS}
    ip -netns "${NS}" link set dev l2tpeth12 up promisc on
    ip -netns "${NS}" link set dev l2tpeth12 master "br_${NS}"
}

setup_overlay_ipv4()
{
    local ENCAP="$1"
    setup_overlay_ns1 ${L2TP_IP4_1} ${L2TP_IP4_2} "${ENCAP}"
    setup_overlay_ns2 ${L2TP_IP4_2} ${L2TP_IP4_1} "${ENCAP}"
}

setup_overlay_ipv6()
{
    local ENCAP="$1"
    setup_overlay_ns1 ${L2TP_IP6_1} ${L2TP_IP6_2} "${ENCAP}"
    setup_overlay_ns2 ${L2TP_IP6_2} ${L2TP_IP6_1} "${ENCAP}"
}

cleanup_overlay_ns_iproute2()
{
    local NS="$1"
    local L2TP_TID="$2"
    local L2TP_SID="$3"

    ip -netns "${NS}" l2tp del session tunnel_id ${L2TP_TID} \
             session_id ${L2TP_SID}
    ip -netns "${NS}" l2tp del tunnel tunnel_id ${L2TP_TID}
}

cleanup_overlay()
{
    cleanup_overlay_ns1
    cleanup_overlay_ns2
}

start_pcap()
{
    local NS="$1"
    local DEV="$2"
    local PIDVAR="$3"
    
    ip netns exec "${NS}" tcpdump --immediate-mode -ni "${DEV}" \
       -s 0 -w "${NS}-${DEV}.pcap" 2> /dev/null &
    eval ${PIDVAR}=$!
    sleep 0.1
}

fn_exists()
{
    declare -F "$1" > /dev/null
}

# Run "ping" from NS0 and print the result
#
# Parameters:
#
#   * $1: the variant of ping to use (normally either "ping" or "ping6"),
#   * $2: the IP address to ping,
#   * $3: a human readable description of the purpose of the test.
#
# If the test fails and PAUSE_ON_FAIL is active, the user is given the
# possibility to continue with the next test or to quit immediately.
#
ping_test_one()
{
    local PING="$1"; readonly PING
    local IP="$2"; readonly IP
    local MSG="$3"; readonly MSG
    local RET

    printf "TEST: %-60s  " "${MSG}"

    set +e
    for n in `seq 1 5`; do
        ip netns exec "${NS0}" "${PING}" -w 1 -c 1 "${IP}" > /dev/null 2>&1
        RET=$?
        test $RET -eq 0 && break
    done
    set -e

    if [ "${RET}" -eq 0 ]; then
        local do_complete_test=no
        fn_exists complete_test && do_complete_test=yes || do_complete_test=no
        if [ $do_complete_test = yes ]; then
            set +e
            complete_test "${IP}"
            RET=$?
            set -e
        fi
    fi

    if [ "${RET}" -eq 0 ]; then
        printf "[ OK ]\n"
    else
        ERR=1
        printf "[FAIL]\n"
        if [ "${PAUSE_ON_FAIL}" = "yes" ]; then
            printf "\nHit enter to continue, 'q' to quit\n"
            read a
            if [ "$a" = "q" ]; then
                exit 1
            fi
        fi
    fi
}

# Run reachability tests
#
# Parameters:
#
#   * $1: ipv4 or ipv6 (test traffic)
#   * $2: l2tp tunnel endpoints (ipv4 or ipv6)
#   * $3: l2tp encap (udp or ip)
#
ping_test()
{
    local TRAFFIC="$1"; readonly TRAFFIC
    local IPVER="$2"; readonly IPVER
    local ENCAP="$3"; readonly ENCAP

    if [ "${TRAFFIC}" = "ipv4" ]; then
        ping_test_one "ping" "192.0.1.103" "IPv4 packets over L2TPv3 ${IPVER}/${ENCAP}"
    fi
    if [ "${TRAFFIC}" = "ipv6" ]; then
        ping_test_one "${PING6}" "2001:db8::103" "IPv6 packets over L2TPv3 ${IPVER}/${ENCAP}"
    fi
}

# Set up l2tp and run reachability tests over IPv4 and IPv6
#
# Parameters:
#
#   * $1: the packet type (protocol)
#
test_overlay()
{
    local IPVER="$1"
    readonly IPVER
    local ENCAP="$2"
    readonly ENCAP

    # Create the l2tp tunnel in the intermediate namespaces
    case "${IPVER}" in
        ipv4)
            setup_overlay_ipv4 ${ENCAP}
            ;;
        ipv6)
            setup_overlay_ipv6 ${ENCAP}
            ;;
        *)
            exit 1;
            ;;
    esac

    if [ "${OPT_INTERACTIVE_DEBUG}" = "yes" ]; then
        cat << EOF > "${INTERACTIVE_SHELL_RC}"
PS1="l2tp-test\$ "
ENCAP="${ENCAP}"
IPVER="${IPVER}"
NS0="${NS0}"
NS1="${NS1}"
NS2="${NS2}"
NS3="${NS3}"
L2TP_IP4_1="${L2TP_IP4_1}"
L2TP_IP4_2="${L2TP_IP4_2}"
L2TP_IP6_1="${L2TP_IP6_1}"
L2TP_IP6_2="${L2TP_IP6_2}"
L2TP_UDP_PORT_1="${L2TP_UDP_PORT_1}"
L2TP_UDP_PORT_2="${L2TP_UDP_PORT_2}"
L2TP_TID_1="${L2TP_TID_1}"
L2TP_TID_2="${L2TP_TID_2}"
L2TP_SID_1="${L2TP_SID_1}"
L2TP_SID_2="${L2TP_SID_2}"
EOF
        echo "Starting interactive debug shell."
        echo "Testing with L2TP tunnel over ${IPVER} using ${ENCAP}"
        echo "exit to continue tests"
        /bin/bash --rcfile "${INTERACTIVE_SHELL_RC}" -i
    fi
    
    # Test IPv4 and IPv6 reachability
    ping_test "ipv4" "${IPVER}" "${ENCAP}"
    ping_test "ipv6" "${IPVER}" "${ENCAP}"

    # Cleanup l2tp
    cleanup_overlay
}

check_features()
{
    ip l2tp help 2>&1 | grep -q "l2tp add tunnel"
    if [ $? -ne 0 ]; then
        echo "Missing l2tp support in iproute2" >&2
        exit_cleanup
    fi

    # Use ping6 on systems where ping doesn't handle IPv6
    ping -w 1 -c 1 ::1 > /dev/null 2>&1 || PING6="ping6"
}

usage()
{
    cat << EOF
Usage: $0 [-p] [-c] [-t ipver] [-e encap] [-f script]
  -p      Pause on fail
  -i      Enable interactive debug shell before running each test
  -c      Packet capture (generate pcaps)
  -t      Tunnel protocol (ipv4 | ipv6)
  -e      L2TP encap type (udp | ip)
  -f      overlay setup script file
EOF
    exit 1
}

while getopts :pict:e:f: o
do
    case $o in
        p) PAUSE_ON_FAIL="yes";;
        i) OPT_INTERACTIVE_DEBUG="yes";;
        c) OPT_PCAPS="yes";;
        t) OPT_TUNNEL_IPVER="${OPTARG}";;
        e) OPT_ENCAP="${OPTARG}";;
        f) OPT_SETUP_OVERLAY_SCRIPT="${OPTARG}";;
        S) OPT_L2TP_SESSION_SEQ="${OPTARG}";;
        *) usage;;
    esac
done

test "${OPT_TUNNEL_IPVER}" = "ipv4" || \
    test "${OPT_TUNNEL_IPVER}" = "ipv6" || \
    usage
test "${OPT_ENCAP}" = "udp" || \
    test "${OPT_ENCAP}" = "ip" || \
    usage

check_features

# Create namespaces before setting up the exit trap.
# Otherwise, exit_cleanup_all() could delete namespaces that were not created
# by this script.
create_namespaces

set -e
trap exit_cleanup_all EXIT
trap exit SIGINT

# Source script providing overlay setup functions for NS1/NS2
. "${OPT_SETUP_OVERLAY_SCRIPT}"

# setup network topology
setup_underlay

# start packet captures, if enabled
if [ "${OPT_PCAPS}" = "yes" ]; then
    start_pcap "${NS0}" veth01 TCPDUMP_PID0
    start_pcap "${NS1}" veth12 TCPDUMP_PID1
    start_pcap "${NS2}" veth21 TCPDUMP_PID2
    start_pcap "${NS3}" veth32 TCPDUMP_PID3
fi

echo $0 $@

# Run enabled test
test_overlay $OPT_TUNNEL_IPVER $OPT_ENCAP

if [ "${ERR}" -eq 1 ]; then
    echo "Some tests failed." >&2
else
    ERR=0
fi

exit $ERR
