//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// Minimal protocol constants used by parser. They are defined here
// instead of pulling in broad kernel networking headers so bpf2go generation
// stays more reproducible across development environments.
#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define ETH_P_IPV6 0x86DD

// L4 protocol constants used for built-in bootstrap packet detection.
#define IPPROTO_ICMPV6 58
#define IPPROTO_UDP 17

// tc classifier return codes. OK continues normal packet processing, while
// SHOT drops the packet at the selected interface's egress hook.
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// Reasons emitted to userspace through bootstrap_events.
// Go code log formatting code treats them as part of the userspace ABI.
#define BOOTSTRAP_ARP 1
#define BOOTSTRAP_DHCPV4 2
#define BOOTSTRAP_DHCPV6 3
#define BOOTSTRAP_ICMPV6_ND 4

// Ethernet header for the packet's L2 frame. The eBPF program reads h_proto to
// decide whether it should allow bootstrap traffic or apply IP gates.
struct ethhdr {
    unsigned char h_dest[ETH_ALEN];
    unsigned char h_source[ETH_ALEN];
    __be16 h_proto;
};

// 802.1Q/802.1ad VLAN header. We support one VLAN tag so common access
// and provider-tagged links can still use the same bootstrap policy.
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

// IPv4 header layout used for conservative parsing. We support variable
// IHL, drops malformed headers, and drops fragments because L4 ports may be
// absent from non-initial fragments.
struct iphdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8 ihl : 4;
    __u8 version : 4;
#else
    __u8 version : 4;
    __u8 ihl : 4;
#endif
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
};

// UDP header used only for DHCPv4 detection for now. Port fields stay in
// network byte order in events and are converted by Go before logging.
struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
};

struct ipv6hdr {
    __u8 priority_version;
    __u8 flow_lbl[3];
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    __u8 saddr[16];
    __u8 daddr[16];
};

struct icmp6hdr {
    __u8 icmp6_type;
    __u8 icmp6_code;
    __sum16 icmp6_cksum;
};

// runtime_config is a singleton map value at key 0.
//
// Defaults are intentionally fail-closed: userspace writes zero values unless
// the operator explicitly enables AllowAll or an IP version gate.
struct runtime_config {
    __u8 allow_all;
    __u8 enable_v4;
    __u8 enable_v6;
    __u8 reserved0;
};

// bootstrap_event is the ring-buffer record consumed by userspace.
//
// This is deliberately small and emitted only for built-in bootstrap passes.
// Emitting every drop or pass would be too expensive on busy interfaces and
// would make the kill switch easier to pressure with traffic.
struct bootstrap_event {
    __u64 timestamp_ns;
    __u32 ifindex;
    __u16 eth_proto;
    __u8 reason;
    __u8 ip_proto;
    __be32 ipv4_saddr;
    __be32 ipv4_daddr;
    __u8 ipv6_saddr[16];
    __u8 ipv6_daddr[16];
    __be16 source_port;
    __be16 dest_port;
    __u8 icmpv6_type;
    __u8 vlan_depth;
    __u16 reserved0;
};

// Runtime policy flags. BPF_MAP_TYPE_ARRAY gives a stable singleton value that
// userspace can update atomically by replacing key 0.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct runtime_config);
    __uint(max_entries, 1);
} runtime_config SEC(".maps");

// Low-volume debug channel for packets that pass because of built-in bootstrap
// allowances. Losing an event is acceptable, but blocking packet processing is
// not, so emit_bootstrap_event simply returns if the ring buffer is full.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} bootstrap_events SEC(".maps");

// data_available is the verifier-friendly bounds check used before every packet
// header read. The verifier tracks cursor + constant/validated sizes and allows
// subsequent field accesses only when they are proven inside data_end.
static __always_inline int data_available(void *cursor, void *data_end, __u64 size) {
    return cursor + size <= data_end;
}

// emit_bootstrap_event reports a passed bootstrap packet to userspace.
//
// Header pointers are optional because each bootstrap allowance carries
// different context: ARP has no IP headers, DHCP has UDP ports, and ICMPv6 ND
// has an ICMPv6 type instead.
static __always_inline void copy_ipv6_addr(__u8 dst[16], const __u8 src[16]) {
#pragma unroll
    for (int i = 0; i < 16; i++) {
        dst[i] = src[i];
    }
}

static __always_inline void emit_bootstrap_event(struct __sk_buff *skb, __u16 eth_proto, __u8 reason,
                                                 __u8 vlan_depth, struct iphdr *ip, struct ipv6hdr *ip6,
                                                 struct udphdr *udp, struct icmp6hdr *icmp6) {
    struct bootstrap_event *event;

    event = bpf_ringbuf_reserve(&bootstrap_events, sizeof(*event), 0);
    if (!event) {
        return;
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->ifindex = skb->ifindex;
    event->eth_proto = eth_proto;
    event->reason = reason;
    event->ip_proto = ip ? ip->protocol : ip6 ? ip6->nexthdr : 0;
    event->ipv4_saddr = ip ? ip->saddr : 0;
    event->ipv4_daddr = ip ? ip->daddr : 0;
    if (ip6) {
        copy_ipv6_addr(event->ipv6_saddr, ip6->saddr);
        copy_ipv6_addr(event->ipv6_daddr, ip6->daddr);
    } else {
#pragma unroll
        for (int i = 0; i < 16; i++) {
            event->ipv6_saddr[i] = 0;
            event->ipv6_daddr[i] = 0;
        }
    }
    event->source_port = udp ? udp->source : 0;
    event->dest_port = udp ? udp->dest : 0;
    event->icmpv6_type = icmp6 ? icmp6->icmp6_type : 0;
    event->vlan_depth = vlan_depth;
    event->reserved0 = 0;

    bpf_ringbuf_submit(event, 0);
}

// DHCPv4 bootstrap traffic uses UDP ports 67 and 68. Accept either direction so
// client discovery/request traffic and server offer/ack traffic are both
// treated as link-bootstrap packets.
static __always_inline int is_dhcpv4(struct udphdr *udp) {
    __u16 source = bpf_ntohs(udp->source);
    __u16 dest = bpf_ntohs(udp->dest);

    return (source == 67 || source == 68) && (dest == 67 || dest == 68);
}

// DHCPv6 uses UDP client/server ports 546 and 547. Accept either direction so
// solicitation and server replies are allowed before routable IPv6 is enabled.
static __always_inline int is_dhcpv6(struct udphdr *udp) {
    __u16 source = bpf_ntohs(udp->source);
    __u16 dest = bpf_ntohs(udp->dest);

    return (source == 546 || source == 547) && (dest == 546 || dest == 547);
}

static __always_inline int is_icmpv6_nd(struct icmp6hdr *icmp6) {
    return icmp6->icmp6_type >= 133 && icmp6->icmp6_type <= 136;
}

// killswitch_egress enforces the fail-closed policy at tc egress.
//
// Policy order:
//  1. AllowAll passes immediately.
//  2. Malformed packets drop.
//  3. ARP, DHCPv4, DHCPv6, and ICMPv6 ND pass and emit bootstrap debug events.
//  4. IPv4/IPv6 enable flags gate routable IP traffic.
//  5. Everything else drops by default.
SEC("tc")
int killswitch_egress(struct __sk_buff *skb) {
    __u32 key = 0;
    struct runtime_config *config;
    // skb->data and skb->data_end are packet-relative pointers supplied by the
    // tc hook. Cast through long as required for eBPF pointer extraction.
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    void *cursor;
    __u16 eth_proto;
    __u8 vlan_depth = 0;

    config = bpf_map_lookup_elem(&runtime_config, &key);
    if (config && config->allow_all) {
        return TC_ACT_OK;
    }

    // Truncated Ethernet frames are invalid at this enforcement point. Drop
    // them rather than passing unknown data.
    if (!data_available(eth, data_end, sizeof(*eth))) {
        return TC_ACT_SHOT;
    }

    cursor = data + sizeof(*eth);
    eth_proto = bpf_ntohs(eth->h_proto);
    if (eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD) {
        struct vlan_hdr *vlan = cursor;

        if (!data_available(vlan, data_end, sizeof(*vlan))) {
            return TC_ACT_SHOT;
        }
        eth_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        cursor += sizeof(*vlan);
        vlan_depth = 1;
    }

    if (eth_proto == ETH_P_ARP) {
        emit_bootstrap_event(skb, eth_proto, BOOTSTRAP_ARP, vlan_depth, 0, 0, 0, 0);
        return TC_ACT_OK;
    }

    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = cursor;
        __u32 ihl_len;
        __u16 frag_off;

        // First validate the fixed IPv4 header so reading ihl/version is safe.
        if (!data_available(ip, data_end, sizeof(*ip))) {
            return TC_ACT_SHOT;
        }

        // IHL is expressed in 32-bit words. Options are allowed only after the
        // full variable-length header has been proven in bounds.
        ihl_len = ip->ihl * 4;
        if (ip->version != 4 || ihl_len < sizeof(*ip)) {
            return TC_ACT_SHOT;
        }
        if (!data_available(ip, data_end, ihl_len)) {
            return TC_ACT_SHOT;
        }

        frag_off = bpf_ntohs(ip->frag_off);
        if (frag_off & 0x3fff) {
            // Drop all IPv4 fragments for now. Non-initial fragments do not
            // carry UDP ports, and allowing mixed fragment policy is risky.
            return TC_ACT_SHOT;
        }

        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + ihl_len;

            if (!data_available(udp, data_end, sizeof(*udp))) {
                return TC_ACT_SHOT;
            }
            if (is_dhcpv4(udp)) {
                emit_bootstrap_event(skb, eth_proto, BOOTSTRAP_DHCPV4, vlan_depth, ip, 0, udp, 0);
                return TC_ACT_OK;
            }
        }

        if (!config || !config->enable_v4) {
            // EnableV4 gates routable IPv4 traffic after bootstrap exceptions.
            return TC_ACT_SHOT;
        }

        // There is no allowlist maps yet, so enabled IPv4 still fails closed.
        return TC_ACT_SHOT;
    }

    if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = cursor;
        __u8 version;

        if (!data_available(ip6, data_end, sizeof(*ip6))) {
            return TC_ACT_SHOT;
        }
        version = ip6->priority_version >> 4;
        if (version != 6) {
            return TC_ACT_SHOT;
        }

        // For now deliberately keeps IPv6 strict: only direct UDP and ICMPv6
        // headers are parsed. Extension headers and other next-header values
        // are dropped until bounded extension-header walking is added.
        if (ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip6 + sizeof(*ip6);

            if (!data_available(udp, data_end, sizeof(*udp))) {
                return TC_ACT_SHOT;
            }
            if (is_dhcpv6(udp)) {
                emit_bootstrap_event(skb, eth_proto, BOOTSTRAP_DHCPV6, vlan_depth, 0, ip6, udp, 0);
                return TC_ACT_OK;
            }
        } else if (ip6->nexthdr == IPPROTO_ICMPV6) {
            struct icmp6hdr *icmp6 = (void *)ip6 + sizeof(*ip6);

            if (!data_available(icmp6, data_end, sizeof(*icmp6))) {
                return TC_ACT_SHOT;
            }
            if (is_icmpv6_nd(icmp6)) {
                emit_bootstrap_event(skb, eth_proto, BOOTSTRAP_ICMPV6_ND, vlan_depth, 0, ip6, 0, icmp6);
                return TC_ACT_OK;
            }
        } else {
            return TC_ACT_SHOT;
        }

        if (!config || !config->enable_v6) {
            // EnableV6 gates routable IPv6 traffic after bootstrap exceptions.
            return TC_ACT_SHOT;
        }

        // There are no allowlist maps yet, so enabled IPv6 still fails closed.
        return TC_ACT_SHOT;
    }

    // Killswitch is intentionally strict: unsupported L2 protocols are dropped.
    // Later we can relax this once additional bootstrap behavior is defined.
    return TC_ACT_SHOT;
}

// Dual license is required for helpers used by this program on common kernels.
char __license[] SEC("license") = "Dual MIT/GPL";
