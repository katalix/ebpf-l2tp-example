.PHONY: all \
	clean \
	check \
	check_default \
	check_ebpf_ipv4_udp_encap \
	check_ebpf_ipv6_udp_encap \
	check_ebpf_ipv4_ip_encap \
	check_ebpf_ipv6_ip_encap


CFLAGS =
HAVE_IPV6_SUPPORT = yes

ifeq ($(V),1)
CFLAGS += -DVERBOSE_LOGGING
endif

HAVE_BPF_F_ADJ_ROOM_DECAP_L3_IPV4:=$(shell grep BPF_F_ADJ_ROOM_DECAP_L3_IPV4 /usr/include/linux/bpf.h)
ifeq ($(HAVE_BPF_F_ADJ_ROOM_DECAP_L3_IPV4),)
$(warning No BPF_F_ADJ_ROOM_DECAP_L3_IPV4 constant in /usr/include/linux/bpf.h: IPv6 encap not supported on this host)
HAVE_IPV6_SUPPORT = no
else
CFLAGS += -DHAVE_BPF_F_ADJ_ROOM_DECAP_L3_IPV4
endif

HAVE_BPF_LOOP_HELPER:=$(shell grep ^static.*bpf_loop /usr/include/bpf/bpf_helper_defs.h)
ifeq ($(HAVE_BPF_LOOP_HELPER),)
$(warning No bpf_loop helper defined in /usr/include/bpf/bpf_helper_defs.h: IPv6 encap not supported on this host)
HAVE_IPV6_SUPPORT = no
else
CFLAGS += -DHAVE_BPF_LOOP_HELPER
endif

TARGETS = ebpf_clsact.o map_session

all: $(TARGETS)

check_default: $(TARGETS)
	sudo ./l2tp-test.sh -t ipv4 -e udp -f l2tp-test_default.sh
	sudo ./l2tp-test.sh -t ipv4 -e udp -f l2tp-test_default.sh
	sudo ./l2tp-test.sh -t ipv6 -e ip -f l2tp-test_default.sh
	sudo ./l2tp-test.sh -t ipv6 -e ip -f l2tp-test_default.sh

check_ebpf_ipv4_udp_encap:
	sudo ./l2tp-test.sh -t ipv4 -e udp -f l2tp-test_ebpf-ns1.sh
	sudo ./l2tp-test.sh -t ipv4 -e udp -f l2tp-test_ebpf-ns2.sh
	sudo ./l2tp-test.sh -t ipv4 -e udp -f l2tp-test_ebpf-ns1-ns2.sh

check_ebpf_ipv6_udp_encap:
ifeq ($(HAVE_IPV6_SUPPORT),yes)
	sudo ./l2tp-test.sh -t ipv6 -e udp -f l2tp-test_ebpf-ns1.sh
	sudo ./l2tp-test.sh -t ipv6 -e udp -f l2tp-test_ebpf-ns2.sh
	sudo ./l2tp-test.sh -t ipv6 -e udp -f l2tp-test_ebpf-ns1-ns2.sh
endif

check_ebpf_ipv4_ip_encap:
	sudo ./l2tp-test.sh -t ipv4 -e ip -f l2tp-test_ebpf-ns1.sh
	sudo ./l2tp-test.sh -t ipv4 -e ip -f l2tp-test_ebpf-ns2.sh
	sudo ./l2tp-test.sh -t ipv4 -e ip -f l2tp-test_ebpf-ns1-ns2.sh

check_ebpf_ipv6_ip_encap:
ifeq ($(HAVE_IPV6_SUPPORT),yes)
	sudo ./l2tp-test.sh -t ipv6 -e ip -f l2tp-test_ebpf-ns1.sh
	sudo ./l2tp-test.sh -t ipv6 -e ip -f l2tp-test_ebpf-ns2.sh
	sudo ./l2tp-test.sh -t ipv6 -e ip -f l2tp-test_ebpf-ns1-ns2.sh
endif

check: check_default \
	check_ebpf_ipv4_udp_encap \
	check_ebpf_ipv6_udp_encap \
	check_ebpf_ipv4_ip_encap \
	check_ebpf_ipv6_ip_encap

clean:
	rm -f ebpf_clsact.o map_session

ebpf_clsact.o: ebpf_clsact.c maps.h
	clang -O2 -g -Wall $(CFLAGS) -target bpf -c $< -o $@

map_session: map_session.c maps.h
	gcc -Werror -Wall $(CFLAGS) -o $@ $< -lbpf
