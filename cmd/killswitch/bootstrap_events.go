//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf/ringbuf"
)

func readBootstrapEvents(reader *ringbuf.Reader, notifyError func(string, error)) error {
	for {
		record, err := reader.Read()
		if err != nil {
			return err
		}

		event, err := parseBootstrapEvent(record.RawSample)
		if err != nil {
			log.Printf("parse bootstrap event: %s", err)
			if notifyError != nil {
				notifyError("Bootstrap event parse error", err)
			}
			continue
		}
		log.Print(formatBootstrapEvent(event))
	}
}

func parseBootstrapEvent(raw []byte) (bootstrapEvent, error) {
	var event bootstrapEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err != nil {
		return bootstrapEvent{}, err
	}
	return event, nil
}

func formatBootstrapEvent(event bootstrapEvent) string {
	reason := "unknown"
	switch event.Reason {
	case bootstrapARP:
		reason = "arp"
	case bootstrapDHCPv4:
		reason = "dhcpv4"
	case bootstrapDHCPv6:
		reason = "dhcpv6"
	case bootstrapICMPv6:
		reason = "icmpv6_nd"
	}

	if event.Reason == bootstrapDHCPv4 {
		return fmt.Sprintf("bootstrap pass: reason=%s ifindex=%d src=%s:%d dst=%s:%d",
			reason,
			event.Ifindex,
			ipv4FromNetworkOrder(event.IPv4Saddr),
			ntohs(event.SourcePort),
			ipv4FromNetworkOrder(event.IPv4Daddr),
			ntohs(event.DestPort),
		)
	}
	if event.Reason == bootstrapDHCPv6 {
		return fmt.Sprintf("bootstrap pass: reason=%s ifindex=%d src=[%s]:%d dst=[%s]:%d vlan_depth=%d",
			reason,
			event.Ifindex,
			net.IP(event.IPv6Saddr[:]),
			ntohs(event.SourcePort),
			net.IP(event.IPv6Daddr[:]),
			ntohs(event.DestPort),
			event.VLANDepth,
		)
	}
	if event.Reason == bootstrapICMPv6 {
		return fmt.Sprintf("bootstrap pass: reason=%s ifindex=%d src=%s dst=%s type=%d vlan_depth=%d",
			reason,
			event.Ifindex,
			net.IP(event.IPv6Saddr[:]),
			net.IP(event.IPv6Daddr[:]),
			event.ICMPv6Type,
			event.VLANDepth,
		)
	}

	return fmt.Sprintf("bootstrap pass: reason=%s ifindex=%d eth_proto=0x%04x vlan_depth=%d",
		reason,
		event.Ifindex,
		event.EthProto,
		event.VLANDepth,
	)
}
