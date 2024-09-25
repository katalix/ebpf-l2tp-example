# eBPF L2TP example

This small demo application implements L2TPv3 Ethernet encapsulation and decapsulation
using eBPF to replace the traditional Linux kernel L2TP dataplane.

In the Linux kernel implementation, Ethernet pseudowires are instantiated using iproute2
to create the tunnel and session instance.  The Ethernet pseudowire is represented by a
virtual netdev, *l2tpethX*.

Frames received by *l2tpethX* are encapsulated with L2TP headers and transmitted over the
L2TP tunnel.

L2TP frames received over the tunnel are decapsulated and presented on *l2tpethX*.

The L2TP virtual device is typically bridged with a physical Ethernet interface, thereby
connecting two L2 networks over an L3 routed network (e.g. the Internet).

```
  +----------------------------+
  |                     HOST A |
  |                            |
  |     eth0                   |
  |     ^                      |
  +-----|----------------------+
        |
        | Ethernet
        |
  +-----|----------------------+
  |     v               LCCE 1 |
  |   +----------+             |
  |   | eth0     | br0         |
  |   | l2tpeth0 |             |
  |   +----------+             |
  |                            |
  |     eth1                   |
  |     ^                      |
  +-----|----------------------+
        |
        |
        | L2TP-encapsulated Ethernet
        |
        |
  +-----|----------------------+
  |     v               LCCE 2 |
  |     eth0                   |
  |                            |
  |   +----------+             |
  |   | l2tpeth0 | br0         |
  |   | eth1     |             |
  |   +-^--------+             |
  +-----|----------------------+
        |
        | Ethernet
        |
  +-----|----------------------+
  |     v               HOST B |
  |     eth0                   |
  |                            |
  |                            |
  +----------------------------+
```

The eBPF implementation bypasses the kernel L2TP subsystem and avoids the need for
L2TP virtual network devices.

It does so by adding an ingress clsact filter to the Ethernet interface carrying L2TP
encapsulated frames, and the interface carrying decapsulated frames.

On receipt of an L2TP frame, the L2TP headers are removed, and the internal Ethernet
frame redirected to the interface carrying decapsulated frames.

On receipt of an Ethernet frame, L2TP headers are added, and the frame redirected to
the interface carrying encapsulated frames.

The eBPF code is configured using BPF maps, which may be set up using the *map_session*
helper app.

## Building

Before trying to build the code, ensure you have the following dependencies installed:

 * gcc
 * make
 * a clang toolchain that supports the bpf target
 * libbpf (headers and shared object)

The ebpf code and *map_session* app can be built using make:

    $ make

If the build complains about missing eBPF features, you will not be able to test IPv6
encap using the eBPF dataplane:

    Makefile:11: No BPF_F_ADJ_ROOM_DECAP_L3_IPV4 constant in /usr/include/linux/bpf.h: IPv6 encap not supported on this host
    Makefile:18: No bpf_loop helper defined in /usr/include/bpf/bpf_helper_defs.h: IPv6 encap not supported on this host

## Running

The *l2tp-test.sh* script creates a set of network namespaces and associated veth links
in order to be able to test the eBPF code in a controlled environment.

Datapath testing is managed using ping to send traffic across the L2TP link.

The ns1 and ns2 namespaces are responsible for L2TP encapsulation and decapsulation, and
may be individually configured to use the traditional Linux datapath or eBPF.

The simplest way to run the code is via make:

    $ make check

The **check** target will run datapath tests for all configurations supported by your system.
It uses *sudo*, so ensure your user account is set up for *sudo* access.

Alternatively, *l2tp-test.sh* can be run directly in order to manually select the configuration
to test.

To run using the traditional Linux dataplane:

    $ sudo ./l2tp-test.sh

To run with eBPF in ns1, and the traditional dataplane in ns2:

    $ sudo ./l2tp-test.sh -f l2tp-test_ebpf-ns1.sh

To run with eBPF in ns2, and the traditional dataplane in ns1:

    $ sudo ./l2tp-test.sh -f l2tp-test_ebpf-ns2.sh

To run with eBPF in both ns1 and ns2:

    $ sudo ./l2tp-test.sh -f l2tp-test_ebpf-ns1-ns2.sh

The script allows for packet capture and interactive access to the net namespaces, run
with -h to see the available options.
