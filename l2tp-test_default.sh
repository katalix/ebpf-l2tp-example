setup_overlay_ns1()
{
    local IP1="$1"
    local IP2="$2"
    local ENCAP="$3"

    setup_overlay_iproute2 "${NS1}" "${ENCAP}" "${IP1}" "${IP2}" "${L2TP_TID_1}" "${L2TP_TID_2}" "${L2TP_SID_1}" "${L2TP_SID_2}"
}

setup_overlay_ns2()
{
    local IP1="$1"
    local IP2="$2"
    local ENCAP="$3"

    setup_overlay_iproute2 "${NS2}" "${ENCAP}" "${IP1}" "${IP2}" "${L2TP_TID_2}" "${L2TP_TID_1}" "${L2TP_SID_2}" "${L2TP_SID_1}"
}

cleanup_overlay_ns1()
{
    cleanup_overlay_ns_iproute2 "${NS1}" "${L2TP_TID_1}" "${L2TP_SID_1}"
}

cleanup_overlay_ns2()
{
    cleanup_overlay_ns_iproute2 "${NS2}" "${L2TP_TID_2}" "${L2TP_SID_2}"
}
