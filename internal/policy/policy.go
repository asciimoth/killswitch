package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const (
	IPProtoTCP = 6
	IPProtoUDP = 17
)

type PortRule struct {
	Protocol uint8
	Port     uint16
}

type HostPortRule struct {
	Protocol uint8
	AddrPort netip.AddrPort
}

func ParseAllowedMarks(values []string) ([]uint32, error) {
	out := make([]uint32, 0, len(values))
	for _, value := range values {
		parsed, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("parse allowed_marks %q: %w", value, err)
		}
		out = append(out, uint32(parsed))
	}
	return out, nil
}

func ParseAllowedPorts(values []string) ([]PortRule, error) {
	out := make([]PortRule, 0, len(values))
	for _, value := range values {
		protocol, port, err := parseProtocolPort(value)
		if err != nil {
			return nil, fmt.Errorf("parse allowed_ports %q: %w", value, err)
		}
		out = append(out, PortRule{Protocol: protocol, Port: port})
	}
	return out, nil
}

func ParseAllowedV4Hosts(values []string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		addr, err := parseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("parse allowed_v4_hosts %q: %w", value, err)
		}
		if !addr.Is4() {
			return nil, fmt.Errorf("parse allowed_v4_hosts %q: address is not IPv4", value)
		}
		out = append(out, addr)
	}
	return out, nil
}

func ParseAllowedV6Hosts(values []string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		addr, err := parseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("parse allowed_v6_hosts %q: %w", value, err)
		}
		if !addr.Is6() || addr.Is4In6() {
			return nil, fmt.Errorf("parse allowed_v6_hosts %q: address is not IPv6", value)
		}
		out = append(out, addr)
	}
	return out, nil
}

func ParseAllowedV4Hostports(values []string) ([]HostPortRule, error) {
	out := make([]HostPortRule, 0, len(values))
	for _, value := range values {
		rule, err := parseProtocolAddrPort(value)
		if err != nil {
			return nil, fmt.Errorf("parse allowed_v4_hostports %q: %w", value, err)
		}
		if !rule.AddrPort.Addr().Is4() {
			return nil, fmt.Errorf("parse allowed_v4_hostports %q: address is not IPv4", value)
		}
		out = append(out, rule)
	}
	return out, nil
}

func ParseAllowedV6Hostports(values []string) ([]HostPortRule, error) {
	out := make([]HostPortRule, 0, len(values))
	for _, value := range values {
		rule, err := parseProtocolAddrPort(value)
		if err != nil {
			return nil, fmt.Errorf("parse allowed_v6_hostports %q: %w", value, err)
		}
		if !rule.AddrPort.Addr().Is6() || rule.AddrPort.Addr().Is4In6() {
			return nil, fmt.Errorf("parse allowed_v6_hostports %q: address is not IPv6", value)
		}
		out = append(out, rule)
	}
	return out, nil
}

func parseProtocolPort(value string) (uint8, uint16, error) {
	protocolText, portText, ok := strings.Cut(value, "/")
	if !ok {
		return 0, 0, errors.New("expected protocol/port")
	}
	protocol, err := parseProtocol(protocolText)
	if err != nil {
		return 0, 0, err
	}
	port, err := parsePort(portText)
	if err != nil {
		return 0, 0, err
	}
	return protocol, port, nil
}

func parseProtocolAddrPort(value string) (HostPortRule, error) {
	protocolText, addrPortText, ok := strings.Cut(value, "/")
	if !ok {
		return HostPortRule{}, errors.New("expected protocol/address:port")
	}
	protocol, err := parseProtocol(protocolText)
	if err != nil {
		return HostPortRule{}, err
	}
	addrPort, err := netip.ParseAddrPort(addrPortText)
	if err != nil {
		return HostPortRule{}, err
	}
	return HostPortRule{Protocol: protocol, AddrPort: addrPort}, nil
}

func parseProtocol(value string) (uint8, error) {
	switch strings.ToLower(value) {
	case "tcp":
		return IPProtoTCP, nil
	case "udp":
		return IPProtoUDP, nil
	default:
		return 0, fmt.Errorf("unsupported protocol %q", value)
	}
}

func parsePort(value string) (uint16, error) {
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, err
	}
	if parsed == 0 {
		return 0, errors.New("port must be greater than zero")
	}
	return uint16(parsed), nil
}

func parseAddr(value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr.Unmap(), nil
}
