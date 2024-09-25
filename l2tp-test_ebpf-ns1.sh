. $(dirname ${BASH_SOURCE[0]})/l2tp-test_ebpf.sh

# NS1 is configured using the ebpf datapath
setup_overlay_ns1() { setup_ebpf_overlay_ns1 "$1" "$2" "$3"; }
cleanup_overlay_ns1() { cleanup_ebpf_overlay_ns1; }

# NS2 is configured using the traditional kernel datapath
setup_overlay_ns2()
{
    setup_overlay_iproute2 \
        "${NS2}" \
        "${3}" \
        "${1}" \
        "${2}" \
        "${L2TP_TID_2}" \
        "${L2TP_TID_1}" \
        "${L2TP_SID_2}" \
        "${L2TP_SID_1}"
}
cleanup_overlay_ns2() { cleanup_overlay_ns_iproute2 "${NS2}" "${L2TP_TID_2}" "${L2TP_SID_2}"; }
