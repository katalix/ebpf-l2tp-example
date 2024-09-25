. $(dirname ${BASH_SOURCE[0]})/l2tp-test_ebpf.sh

# NS1 is configured using the ebpf datapath
setup_overlay_ns1() {
    # An initial ping between ns1 and ns2 is required in order to populate
    # the ARP cache.  Without this the ebpf call to bpf_fib_lookup fails
    # with BPF_FIB_LKUP_RET_NO_NEIGH.
    ip netns exec $NS1 ping -c 1 $2 > /dev/null
    setup_ebpf_overlay_ns1 "$1" "$2" "$3"
}
cleanup_overlay_ns1() { cleanup_ebpf_overlay_ns1; }

# NS2 is configured using the ebpf datapath
setup_overlay_ns2() { setup_ebpf_overlay_ns2 "$1" "$2" "$3"; }
cleanup_overlay_ns2() { cleanup_ebpf_overlay_ns2; }
