use num_enum::{IntoPrimitive, TryFromPrimitive};

#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum SKB_DROP_REASON {
    /*
     * @SKB_NOT_DROPPED_YT: skb is not dropped yet (used for no-drop case)
     */
    SKB_NOT_DROPPED_YET = 0,
    /** @SKB_CONSUMED: packet has been consumed */
    SKB_CONSUMED = 1,
    /** @SKB_DROP_REASON_NOT_SPECIFIED: drop reason is not specified */
    SKB_DROP_REASON_NOT_SPECIFIED = 2,
    /** @SKB_DROP_REASON_NO_SOCKET: socket not found */
    SKB_DROP_REASON_NO_SOCKET = 3,
    /** @SKB_DROP_REASON_PKT_TOO_SMALL: packet size is too small */
    SKB_DROP_REASON_PKT_TOO_SMALL = 4,
    /** @SKB_DROP_REASON_TCP_CSUM: TCP checksum error */
    SKB_DROP_REASON_TCP_CSUM = 5,
    /** @SKB_DROP_REASON_SOCKET_FILTER: dropped by socket filter */
    SKB_DROP_REASON_SOCKET_FILTER = 6,
    /** @SKB_DROP_REASON_UDP_CSUM: UDP checksum error */
    SKB_DROP_REASON_UDP_CSUM = 7,
    /** @SKB_DROP_REASON_NETFILTER_DROP: dropped by netfilter */
    SKB_DROP_REASON_NETFILTER_DROP = 8,
    /**
     * @SKB_DROP_REASON_OTHERHOST: packet don't belong to current host
     * (interface is in promisc mode)
     */
    SKB_DROP_REASON_OTHERHOST = 9,
    /** @SKB_DROP_REASON_IP_CSUM: IP checksum error */
    SKB_DROP_REASON_IP_CSUM = 10,
    /**
     * @SKB_DROP_REASON_IP_INHDR: there is something wrong with IP header (see
     * IPSTATS_MIB_INHDRERRORS)
     */
    SKB_DROP_REASON_IP_INHDR = 11,
    /**
     * @SKB_DROP_REASON_IP_RPFILTER: IP rpfilter validate failed. see the
     * document for rp_filter in ip-sysctl.rst for more information
     */
    SKB_DROP_REASON_IP_RPFILTER = 12,
    /**
     * @SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST: destination address of L2 is
     * multicast, but L3 is unicast.
     */
    SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST = 13,
    /** @SKB_DROP_REASON_XFRM_POLICY: xfrm policy check failed */
    SKB_DROP_REASON_XFRM_POLICY = 14,
    /** @SKB_DROP_REASON_IP_NOPROTO: no support for IP protocol */
    SKB_DROP_REASON_IP_NOPROTO = 15,
    /** @SKB_DROP_REASON_SOCKET_RCVBUFF: socket receive buff is full */
    SKB_DROP_REASON_SOCKET_RCVBUFF = 16,
    /**
     * @SKB_DROP_REASON_PROTO_MEM: proto memory limition, such as udp packet
     * drop out of udp_memory_allocated.
     */
    SKB_DROP_REASON_PROTO_MEM = 17,
    /**
     * @SKB_DROP_REASON_TCP_MD5NOTFOUND: no MD5 hash and one expected,
     * corresponding to LINUX_MIB_TCPMD5NOTFOUND
     */
    SKB_DROP_REASON_TCP_MD5NOTFOUND = 18,
    /**
     * @SKB_DROP_REASON_TCP_MD5UNEXPECTED: MD5 hash and we're not expecting
     * one, corresponding to LINUX_MIB_TCPMD5UNEXPECTED
     */
    SKB_DROP_REASON_TCP_MD5UNEXPECTED = 19,
    /**
     * @SKB_DROP_REASON_TCP_MD5FAILURE: MD5 hash and its wrong, corresponding
     * to LINUX_MIB_TCPMD5FAILURE
     */
    SKB_DROP_REASON_TCP_MD5FAILURE = 20,
    /**
     * @SKB_DROP_REASON_SOCKET_BACKLOG: failed to add skb to socket backlog (
     * see LINUX_MIB_TCPBACKLOGDROP)
     */
    SKB_DROP_REASON_SOCKET_BACKLOG = 21,
    /** @SKB_DROP_REASON_TCP_FLAGS: TCP flags invalid */
    SKB_DROP_REASON_TCP_FLAGS = 22,
    /**
     * @SKB_DROP_REASON_TCP_ZEROWINDOW: TCP receive window size is zero,
     * see LINUX_MIB_TCPZEROWINDOWDROP
     */
    SKB_DROP_REASON_TCP_ZEROWINDOW = 23,
    /**
     * @SKB_DROP_REASON_TCP_OLD_DATA: the TCP data reveived is already
     * received before (spurious retrans may happened), see
     * LINUX_MIB_DELAYEDACKLOST
     */
    SKB_DROP_REASON_TCP_OLD_DATA = 24,
    /**
     * @SKB_DROP_REASON_TCP_OVERWINDOW: the TCP data is out of window,
     * the seq of the first byte exceed the right edges of receive
     * window
     */
    SKB_DROP_REASON_TCP_OVERWINDOW = 25,
    /**
     * @SKB_DROP_REASON_TCP_OFOMERGE: the data of skb is already in the ofo
     * queue, corresponding to LINUX_MIB_TCPOFOMERGE
     */
    SKB_DROP_REASON_TCP_OFOMERGE = 26,
    /**
     * @SKB_DROP_REASON_TCP_RFC7323_PAWS: PAWS check, corresponding to
     * LINUX_MIB_PAWSESTABREJECTED
     */
    SKB_DROP_REASON_TCP_RFC7323_PAWS = 27,
    /** @SKB_DROP_REASON_TCP_INVALID_SEQUENCE: Not acceptable SEQ field */
    SKB_DROP_REASON_TCP_INVALID_SEQUENCE = 28,
    /** @SKB_DROP_REASON_TCP_RESET: Invalid RST packet */
    SKB_DROP_REASON_TCP_RESET = 29,
    /**
     * @SKB_DROP_REASON_TCP_INVALID_SYN: Incoming packet has unexpected
     * SYN flag
     */
    SKB_DROP_REASON_TCP_INVALID_SYN = 30,
    /** @SKB_DROP_REASON_TCP_CLOSE: TCP socket in CLOSE state */
    SKB_DROP_REASON_TCP_CLOSE,
    /** @SKB_DROP_REASON_TCP_FASTOPEN: dropped by FASTOPEN request socket */
    SKB_DROP_REASON_TCP_FASTOPEN,
    /** @SKB_DROP_REASON_TCP_OLD_ACK: TCP ACK is old, but in window */
    SKB_DROP_REASON_TCP_OLD_ACK,
    /** @SKB_DROP_REASON_TCP_TOO_OLD_ACK: TCP ACK is too old */
    SKB_DROP_REASON_TCP_TOO_OLD_ACK,
    /**
     * @SKB_DROP_REASON_TCP_ACK_UNSENT_DATA: TCP ACK for data we haven't
     * sent yet
     */
    SKB_DROP_REASON_TCP_ACK_UNSENT_DATA,
    /** @SKB_DROP_REASON_TCP_OFO_QUEUE_PRUNE: pruned from TCP OFO queue */
    SKB_DROP_REASON_TCP_OFO_QUEUE_PRUNE,
    /** @SKB_DROP_REASON_TCP_OFO_DROP: data already in receive queue */
    SKB_DROP_REASON_TCP_OFO_DROP,
    /** @SKB_DROP_REASON_IP_OUTNOROUTES: route lookup failed */
    SKB_DROP_REASON_IP_OUTNOROUTES,
    /**
     * @SKB_DROP_REASON_BPF_CGROUP_EGRESS: dropped by BPF_PROG_TYPE_CGROUP_SKB
     * eBPF program
     */
    SKB_DROP_REASON_BPF_CGROUP_EGRESS,
    /** @SKB_DROP_REASON_IPV6DISABLED: IPv6 is disabled on the device */
    SKB_DROP_REASON_IPV6DISABLED,
    /** @SKB_DROP_REASON_NEIGH_CREATEFAIL: failed to create neigh entry */
    SKB_DROP_REASON_NEIGH_CREATEFAIL,
    /** @SKB_DROP_REASON_NEIGH_FAILED: neigh entry in failed state */
    SKB_DROP_REASON_NEIGH_FAILED,
    /** @SKB_DROP_REASON_NEIGH_QUEUEFULL: arp_queue for neigh entry is full */
    SKB_DROP_REASON_NEIGH_QUEUEFULL,
    /** @SKB_DROP_REASON_NEIGH_DEAD: neigh entry is dead */
    SKB_DROP_REASON_NEIGH_DEAD,
    /** @SKB_DROP_REASON_TC_EGRESS: dropped in TC egress HOOK */
    SKB_DROP_REASON_TC_EGRESS,
    /**
     * @SKB_DROP_REASON_QDISC_DROP: dropped by qdisc when packet outputting (
     * failed to enqueue to current qdisc)
     */
    SKB_DROP_REASON_QDISC_DROP,
    /**
     * @SKB_DROP_REASON_CPU_BACKLOG: failed to enqueue the skb to the per CPU
     * backlog queue. This can be caused by backlog queue full (see
     * netdev_max_backlog in net.rst) or RPS flow limit
     */
    SKB_DROP_REASON_CPU_BACKLOG,
    /** @SKB_DROP_REASON_XDP: dropped by XDP in input path */
    SKB_DROP_REASON_XDP,
    /** @SKB_DROP_REASON_TC_INGRESS: dropped in TC ingress HOOK */
    SKB_DROP_REASON_TC_INGRESS,
    /** @SKB_DROP_REASON_UNHANDLED_PROTO: protocol not implemented or not supported */
    SKB_DROP_REASON_UNHANDLED_PROTO,
    /** @SKB_DROP_REASON_SKB_CSUM: sk_buff checksum computation error */
    SKB_DROP_REASON_SKB_CSUM,
    /** @SKB_DROP_REASON_SKB_GSO_SEG: gso segmentation error */
    SKB_DROP_REASON_SKB_GSO_SEG,
    /**
     * @SKB_DROP_REASON_SKB_UCOPY_FAULT: failed to copy data from user space,
     * e.g., via zerocopy_sg_from_iter() or skb_orphan_frags_rx()
     */
    SKB_DROP_REASON_SKB_UCOPY_FAULT,
    /** @SKB_DROP_REASON_DEV_HDR: device driver specific header/metadata is invalid */
    SKB_DROP_REASON_DEV_HDR,
    /**
     * @SKB_DROP_REASON_DEV_READY: the device is not ready to xmit/recv due to
     * any of its data structure that is not up/ready/initialized,
     * e.g., the IFF_UP is not set, or driver specific tun->tfiles[txq]
     * is not initialized
     */
    SKB_DROP_REASON_DEV_READY,
    /** @SKB_DROP_REASON_FULL_RING: ring buffer is full */
    SKB_DROP_REASON_FULL_RING,
    /** @SKB_DROP_REASON_NOMEM: error due to OOM */
    SKB_DROP_REASON_NOMEM,
    /**
     * @SKB_DROP_REASON_HDR_TRUNC: failed to trunc/extract the header from
     * networking data, e.g., failed to pull the protocol header from
     * frags via pskb_may_pull()
     */
    SKB_DROP_REASON_HDR_TRUNC,
    /**
     * @SKB_DROP_REASON_TAP_FILTER: dropped by (ebpf) filter directly attached
     * to tun/tap, e.g., via TUNSETFILTEREBPF
     */
    SKB_DROP_REASON_TAP_FILTER,
    /**
     * @SKB_DROP_REASON_TAP_TXFILTER: dropped by tx filter implemented at
     * tun/tap, e.g., check_filter()
     */
    SKB_DROP_REASON_TAP_TXFILTER,
    /** @SKB_DROP_REASON_ICMP_CSUM: ICMP checksum error */
    SKB_DROP_REASON_ICMP_CSUM,
    /**
     * @SKB_DROP_REASON_INVALID_PROTO: the packet doesn't follow RFC 2211,
     * such as a broadcasts ICMP_TIMESTAMP
     */
    SKB_DROP_REASON_INVALID_PROTO,
    /**
     * @SKB_DROP_REASON_IP_INADDRERRORS: host unreachable, corresponding to
     * IPSTATS_MIB_INADDRERRORS
     */
    SKB_DROP_REASON_IP_INADDRERRORS,
    /**
     * @SKB_DROP_REASON_IP_INNOROUTES: network unreachable, corresponding to
     * IPSTATS_MIB_INADDRERRORS
     */
    SKB_DROP_REASON_IP_INNOROUTES,
    /**
     * @SKB_DROP_REASON_PKT_TOO_BIG: packet size is too big (maybe exceed the
     * MTU)
     */
    SKB_DROP_REASON_PKT_TOO_BIG,
    /** @SKB_DROP_REASON_DUP_FRAG: duplicate fragment */
    SKB_DROP_REASON_DUP_FRAG,
    /** @SKB_DROP_REASON_FRAG_REASM_TIMEOUT: fragment reassembly timeout */
    SKB_DROP_REASON_FRAG_REASM_TIMEOUT,
    /**
     * @SKB_DROP_REASON_FRAG_TOO_FAR: ipv4 fragment too far.
     * (/proc/sys/net/ipv4/ipfrag_max_dist)
     */
    SKB_DROP_REASON_FRAG_TOO_FAR,
    /**
     * @SKB_DROP_REASON_TCP_MINTTL: ipv4 ttl or ipv6 hoplimit below
     * the threshold (IP_MINTTL or IPV6_MINHOPCOUNT).
     */
    SKB_DROP_REASON_TCP_MINTTL,
    /** @SKB_DROP_REASON_IPV6_BAD_EXTHDR: Bad IPv6 extension header. */
    SKB_DROP_REASON_IPV6_BAD_EXTHDR,
    /** @SKB_DROP_REASON_IPV6_NDISC_FRAG: invalid frag (suppress_frag_ndisc). */
    SKB_DROP_REASON_IPV6_NDISC_FRAG,
    /** @SKB_DROP_REASON_IPV6_NDISC_HOP_LIMIT: invalid hop limit. */
    SKB_DROP_REASON_IPV6_NDISC_HOP_LIMIT,
    /** @SKB_DROP_REASON_IPV6_NDISC_BAD_CODE: invalid NDISC icmp6 code. */
    SKB_DROP_REASON_IPV6_NDISC_BAD_CODE,
    /** @SKB_DROP_REASON_IPV6_NDISC_BAD_OPTIONS: invalid NDISC options. */
    SKB_DROP_REASON_IPV6_NDISC_BAD_OPTIONS,
    /**
     * @SKB_DROP_REASON_IPV6_NDISC_NS_OTHERHOST: NEIGHBOUR SOLICITATION
     * for another host.
     */
    SKB_DROP_REASON_IPV6_NDISC_NS_OTHERHOST,
    /**
     * @SKB_DROP_REASON_MAX: the maximum of core drop reasons, which
     * shouldn't be used as a real 'reason' - only for tracing code gen
     */
    SKB_DROP_REASON_MAX,
}

// impl SKB_DROP_REASON {
//     pub fn as_str<'a>(reason: u8) -> &'a str {
//         let reason = SKB_DROP_REASON::try_from(reason);
//         match reason {
//             Some(Self::SKB_NOT_DROPPED_YET) => "SKB_NOT_DROPPED_YET",
//             Some(Self::SKB_CONSUMED) => "SKB_CONSUMED",
//             Some(Self::SKB_DROP_REASON_NOT_SPECIFIED) => "SKB_DROP_REASON_NOT_SPECIFIED",
//             Some(Self::SKB_DROP_REASON_NO_SOCKET) => "SKB_DROP_REASON_NO_SOCKET",
//             Some(Self::SKB_DROP_REASON_PKT_TOO_SMALL) => "SKB_DROP_REASON_PKT_TOO_SMALL",
//             Some(Self::SKB_DROP_REASON_TCP_CSUM) => "SKB_DROP_REASON_TCP_CSUM",
//             Some(Self::SKB_DROP_REASON_SOCKET_FILTER) => "SKB_DROP_REASON_SOCKET_FILTER",
//             Some(Self::SKB_DROP_REASON_UDP_CSUM) => "SKB_DROP_REASON_UDP_CSUM",
//             Some(Self::SKB_DROP_REASON_NETFILTER_DROP) => "SKB_DROP_REASON_NETFILTER_DROP",
//             Some(Self::SKB_DROP_REASON_OTHERHOST) => "SKB_DROP_REASON_OTHERHOST",
//             Some(Self::SKB_DROP_REASON_IP_CSUM) => "SKB_DROP_REASON_IP_CSUM",
//             Some(Self::SKB_DROP_REASON_IP_INHDR) => "SKB_DROP_REASON_IP_INHDR",
//             Some(Self::SKB_DROP_REASON_IP_RPFILTER) => "SKB_DROP_REASON_IP_RPFILTER",
//             Some(Self::SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST) => {
//                 "SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST"
//             }
//             Some(Self::SKB_DROP_REASON_XFRM_POLICY) => "SKB_DROP_REASON_XFRM_POLICY",
//             Some(Self::SKB_DROP_REASON_IP_NOPROTO) => "SKB_DROP_REASON_IP_NOPROTO",
//             Some(Self::SKB_DROP_REASON_SOCKET_RCVBUFF) => "SKB_DROP_REASON_SOCKET_RCVBUFF",
//             Some(Self::SKB_DROP_REASON_PROTO_MEM) => "SKB_DROP_REASON_PROTO_MEM",
//             Some(Self::SKB_DROP_REASON_TCP_MD5NOTFOUND) => "SKB_DROP_REASON_TCP_MD5NOTFOUND",
//             Some(Self::SKB_DROP_REASON_TCP_MD5UNEXPECTED) => "SKB_DROP_REASON_TCP_MD5UNEXPECTED",
//             Some(Self::SKB_DROP_REASON_TCP_MD5FAILURE) => "SKB_DROP_REASON_TCP_MD5FAILURE",
//             Some(Self::SKB_DROP_REASON_SOCKET_BACKLOG) => "SKB_DROP_REASON_SOCKET_BACKLOG",
//             Some(Self::SKB_DROP_REASON_TCP_FLAGS) => "SKB_DROP_REASON_TCP_FLAGS",
//             Some(Self::SKB_DROP_REASON_TCP_ZEROWINDOW) => "SKB_DROP_REASON_TCP_ZEROWINDOW",
//             Some(Self::SKB_DROP_REASON_TCP_OLD_DATA) => "SKB_DROP_REASON_TCP_OLD_DATA",
//             Some(Self::SKB_DROP_REASON_TCP_OVERWINDOW) => "SKB_DROP_REASON_TCP_OVERWINDOW",
//             Some(Self::SKB_DROP_REASON_TCP_OFOMERGE) => "SKB_DROP_REASON_TCP_OFOMERGE",
//             Some(Self::SKB_DROP_REASON_TCP_RFC7323_PAWS) => "SKB_DROP_REASON_TCP_RFC7323_PAWS",
//             Some(Self::SKB_DROP_REASON_TCP_INVALID_SEQUENCE) => {
//                 "SKB_DROP_REASON_TCP_INVALID_SEQUENCE"
//             }
//             Some(Self::SKB_DROP_REASON_TCP_RESET) => "SKB_DROP_REASON_TCP_RESET",
//             Some(Self::SKB_DROP_REASON_TCP_INVALID_SYN) => "SKB_DROP_REASON_TCP_INVALID_SYN",
//             Some(Self::SKB_DROP_REASON_TCP_CLOSE) => "SKB_DROP_REASON_TCP_CLOSE",
//             Some(Self::SKB_DROP_REASON_TCP_FASTOPEN) => "SKB_DROP_REASON_TCP_FASTOPEN",
//             Some(Self::SKB_DROP_REASON_TCP_OLD_ACK) => "SKB_DROP_REASON_TCP_OLD_ACK",
//             Some(Self::SKB_DROP_REASON_TCP_TOO_OLD_ACK) => "SKB_DROP_REASON_TCP_TOO_OLD_ACK",
//             Some(Self::SKB_DROP_REASON_TCP_ACK_UNSENT_DATA) => {
//                 "SKB_DROP_REASON_TCP_ACK_UNSENT_DATA"
//             }
//             Some(Self::SKB_DROP_REASON_TCP_OFO_QUEUE_PRUNE) => {
//                 "SKB_DROP_REASON_TCP_OFO_QUEUE_PRUNE"
//             }
//             Some(Self::SKB_DROP_REASON_TCP_OFO_DROP) => "SKB_DROP_REASON_TCP_OFO_DROP",
//             Some(Self::SKB_DROP_REASON_IP_OUTNOROUTES) => "SKB_DROP_REASON_IP_OUTNOROUTES",
//             Some(Self::SKB_DROP_REASON_BPF_CGROUP_EGRESS) => "SKB_DROP_REASON_BPF_CGROUP_EGRESS",
//             Some(Self::SKB_DROP_REASON_IPV6DISABLED) => "SKB_DROP_REASON_IPV6DISABLED",
//             Some(Self::SKB_DROP_REASON_NEIGH_CREATEFAIL) => "SKB_DROP_REASON_NEIGH_CREATEFAIL",
//             Some(Self::SKB_DROP_REASON_NEIGH_FAILED) => "SKB_DROP_REASON_NEIGH_FAILED",
//             Some(Self::SKB_DROP_REASON_NEIGH_QUEUEFULL) => "SKB_DROP_REASON_NEIGH_QUEUEFULL",
//             Some(Self::SKB_DROP_REASON_NEIGH_DEAD) => "SKB_DROP_REASON_NEIGH_DEAD",
//             Some(Self::SKB_DROP_REASON_TC_EGRESS) => "SKB_DROP_REASON_TC_EGRESS",
//             Some(Self::SKB_DROP_REASON_QDISC_DROP) => "SKB_DROP_REASON_QDISC_DROP",
//             Some(Self::SKB_DROP_REASON_CPU_BACKLOG) => "SKB_DROP_REASON_CPU_BACKLOG",
//             Some(Self::SKB_DROP_REASON_XDP) => "SKB_DROP_REASON_XDP",
//             Some(Self::SKB_DROP_REASON_TC_INGRESS) => "SKB_DROP_REASON_TC_INGRESS",
//             Some(Self::SKB_DROP_REASON_UNHANDLED_PROTO) => "SKB_DROP_REASON_UNHANDLED_PROTO",
//             Some(Self::SKB_DROP_REASON_SKB_CSUM) => "SKB_DROP_REASON_SKB_CSUM",
//             Some(Self::SKB_DROP_REASON_SKB_GSO_SEG) => "SKB_DROP_REASON_SKB_GSO_SEG",
//             Some(Self::SKB_DROP_REASON_SKB_UCOPY_FAULT) => "SKB_DROP_REASON_SKB_UCOPY_FAULT",
//             Some(Self::SKB_DROP_REASON_DEV_HDR) => "SKB_DROP_REASON_DEV_HDR",
//             Some(Self::SKB_DROP_REASON_DEV_READY) => "SKB_DROP_REASON_DEV_READY",
//             Some(Self::SKB_DROP_REASON_FULL_RING) => "SKB_DROP_REASON_FULL_RING",
//             Some(Self::SKB_DROP_REASON_NOMEM) => "SKB_DROP_REASON_NOMEM",
//             Some(Self::SKB_DROP_REASON_HDR_TRUNC) => "SKB_DROP_REASON_HDR_TRUNC",
//             Some(Self::SKB_DROP_REASON_TAP_FILTER) => "SKB_DROP_REASON_TAP_FILTER",
//             Some(Self::SKB_DROP_REASON_TAP_TXFILTER) => "SKB_DROP_REASON_TAP_TXFILTER",
//             Some(Self::SKB_DROP_REASON_ICMP_CSUM) => "SKB_DROP_REASON_ICMP_CSUM",
//             Some(Self::SKB_DROP_REASON_INVALID_PROTO) => "SKB_DROP_REASON_INVALID_PROTO",
//             Some(Self::SKB_DROP_REASON_IP_INADDRERRORS) => "SKB_DROP_REASON_IP_INADDRERRORS",
//             Some(Self::SKB_DROP_REASON_IP_INNOROUTES) => "SKB_DROP_REASON_IP_INNOROUTES",
//             Some(Self::SKB_DROP_REASON_PKT_TOO_BIG) => "SKB_DROP_REASON_PKT_TOO_BIG",
//             Some(Self::SKB_DROP_REASON_DUP_FRAG) => "SKB_DROP_REASON_DUP_FRAG",
//             Some(Self::SKB_DROP_REASON_FRAG_REASM_TIMEOUT) => "SKB_DROP_REASON_FRAG_REASM_TIMEOUT",
//             Some(Self::SKB_DROP_REASON_FRAG_TOO_FAR) => "SKB_DROP_REASON_FRAG_TOO_FAR",
//             Some(Self::SKB_DROP_REASON_TCP_MINTTL) => "SKB_DROP_REASON_TCP_MINTTL",
//             Some(Self::SKB_DROP_REASON_IPV6_BAD_EXTHDR) => "SKB_DROP_REASON_IPV6_BAD_EXTHDR",
//             Some(Self::SKB_DROP_REASON_IPV6_NDISC_FRAG) => "SKB_DROP_REASON_IPV6_NDISC_FRAG",
//             Some(Self::SKB_DROP_REASON_IPV6_NDISC_HOP_LIMIT) => {
//                 "SKB_DROP_REASON_IPV6_NDISC_HOP_LIMIT"
//             }
//             Some(Self::SKB_DROP_REASON_IPV6_NDISC_BAD_CODE) => {
//                 "SKB_DROP_REASON_IPV6_NDISC_BAD_CODE"
//             }
//             Some(Self::SKB_DROP_REASON_IPV6_NDISC_BAD_OPTIONS) => {
//                 "SKB_DROP_REASON_IPV6_NDISC_BAD_OPTIONS"
//             }
//             Some(Self::SKB_DROP_REASON_IPV6_NDISC_NS_OTHERHOST) => {
//                 "SKB_DROP_REASON_IPV6_NDISC_NS_OTHERHOST"
//             }
//             Some(Self::SKB_DROP_REASON_MAX) => "SKB_DROP_REASON_MAX",
//             _ => "???",
//         }
//     }
// }
