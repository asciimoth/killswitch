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
#define ETH_P_IPV6 0x86DD

// Used to identify DHCPv4 bootstrap packets.
#define IPPROTO_UDP 17

// tc classifier return codes. OK continues normal packet processing, while
// SHOT drops the packet at the selected interface's egress hook.
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// Reasons emitted to userspace through bootstrap_events.
// Go code log formatting code treats them as part of the userspace ABI.
#define BOOTSTRAP_ARP 1
#define BOOTSTRAP_DHCPV4 2

// Ethernet header for the packet's L2 frame. The eBPF program reads h_proto to
// decide whether it should allow bootstrap traffic or apply IP gates.
struct ethhdr {
    unsigned char h_dest[ETH_ALEN];
    unsigned char h_source[ETH_ALEN];
    __be16 h_proto;
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

// runtime_config is a singleton map value at key 0.
//
// Defaults are intentionally fail-closed: userspace writes zero values unless
// the operator explicitly enables AllowAll or an IP version gate.
struct runtime_config {
    __u8 allow_all;
    __u8 enable_v4;
    __u8 enable_v6;
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
    __u8 reserved0;
    __be32 ipv4_saddr;
    __be32 ipv4_daddr;
    __be16 source_port;
    __be16 dest_port;
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
// ip and udp are optional because ARP has no IPv4/UDP headers. For DHCPv4, the
// caller passes both so logs can include endpoint and port context.
static __always_inline void emit_bootstrap_event(struct __sk_buff *skb, __u16 eth_proto, __u8 reason,
                                                 struct iphdr *ip, struct udphdr *udp) {
    struct bootstrap_event *event;

    event = bpf_ringbuf_reserve(&bootstrap_events, sizeof(*event), 0);
    if (!event) {
        return;
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->ifindex = skb->ifindex;
    event->eth_proto = eth_proto;
    event->reason = reason;
    event->reserved0 = 0;
    event->ipv4_saddr = ip ? ip->saddr : 0;
    event->ipv4_daddr = ip ? ip->daddr : 0;
    event->source_port = udp ? udp->source : 0;
    event->dest_port = udp ? udp->dest : 0;

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

// killswitch_egress enforces the fail-closed policy at tc egress.
//
// Policy order:
//  1. AllowAll passes immediately.
//  2. Malformed packets drop.
//  3. ARP and DHCPv4 pass and emit low-volume bootstrap debug events.
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
    __u16 eth_proto;

    config = bpf_map_lookup_elem(&runtime_config, &key);
    if (config && config->allow_all) {
        return TC_ACT_OK;
    }

    // Truncated Ethernet frames are invalid at this enforcement point. Drop
    // them rather than passing unknown data.
    if (!data_available(eth, data_end, sizeof(*eth))) {
        return TC_ACT_SHOT;
    }

    eth_proto = bpf_ntohs(eth->h_proto);
    if (eth_proto == ETH_P_ARP) {
        emit_bootstrap_event(skb, eth_proto, BOOTSTRAP_ARP, 0, 0);
        return TC_ACT_OK;
    }

    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = data + sizeof(*eth);
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
                emit_bootstrap_event(skb, eth_proto, BOOTSTRAP_DHCPV4, ip, udp);
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
        if (!config || !config->enable_v6) {
            // EnableV6 is present in the ABI now, but for now we do not parse
            // DHCPv6, ICMPv6 ND, extension headers, or IPv6 allowlists.
            return TC_ACT_SHOT;
        }

        // For now there no IPv6 pass rules beyond AllowAll.
        return TC_ACT_SHOT;
    }

    // Killswitch is intentionally strict: unsupported L2 protocols are dropped.
    // Later we can relax this once additional bootstrap behavior is defined.
    return TC_ACT_SHOT;
}

// Dual license is required for helpers used by this program on common kernels.
char __license[] SEC("license") = "Dual MIT/GPL";
