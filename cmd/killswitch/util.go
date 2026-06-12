//go:build linux

package main

import (
	"encoding/binary"
	"net"
	"net/netip"
)

func boolByte(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}

func ntohs(value uint16) uint16 {
	return value<<8 | value>>8
}

func htons(value uint16) uint16 {
	return ntohs(value)
}

func ipv4FromNetworkOrder(value uint32) net.IP {
	return net.IPv4(byte(value), byte(value>>8), byte(value>>16), byte(value>>24))
}

func ipv4Key(addr netip.Addr) uint32 {
	octets := addr.As4()
	return binary.LittleEndian.Uint32(octets[:])
}

func ipv6Key(addr netip.Addr) ipv6AddrKey {
	var key ipv6AddrKey
	octets := addr.As16()
	copy(key.Addr[:], octets[:])
	return key
}
