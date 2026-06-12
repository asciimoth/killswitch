//go:build linux

package main

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"github.com/vishvananda/netlink"
)

func selectedInterfaces(opts options) ([]interfaceInfo, error) {
	all, err := listInterfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	return selectInterfaces(all, opts)
}

func listInterfaces() ([]interfaceInfo, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	all := make([]interfaceInfo, 0, len(links))
	for _, l := range links {
		attrs := l.Attrs()
		if attrs == nil {
			continue
		}
		addrs, err := interfaceAddrs(l)
		if err != nil {
			return nil, err
		}
		ssid, bssid := wifiLinkInfo(attrs.Name)
		gatewayMACs, err := interfaceGatewayMACs(l)
		if err != nil {
			return nil, err
		}
		all = append(all, interfaceInfo{
			Index:       attrs.Index,
			Name:        attrs.Name,
			Type:        l.Type(),
			Addrs:       addrs,
			SSID:        ssid,
			BSSID:       bssid,
			GatewayMACs: gatewayMACs,
		})
	}
	return all, nil
}

func wifiLinkInfo(ifaceName string) (string, string) {
	output, err := exec.Command("iw", "dev", ifaceName, "link").Output()
	if err != nil {
		return "", ""
	}
	return parseIWLinkInfo(string(output))
}

func parseIWLinkInfo(output string) (string, string) {
	var ssid, bssid string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Connected to "):
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				bssid = normalizeMAC(fields[2])
			}
		case strings.HasPrefix(line, "SSID:"):
			ssid = strings.TrimSpace(strings.TrimPrefix(line, "SSID:"))
		}
	}
	return ssid, bssid
}

func interfaceGatewayMACs(link netlink.Link) ([]string, error) {
	attrs := link.Attrs()
	if attrs == nil {
		return nil, nil
	}
	routes, err := netlink.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("list routes for %s(index %d): %w", attrs.Name, attrs.Index, err)
	}
	neighs, err := netlink.NeighList(attrs.Index, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("list neighbors for %s(index %d): %w", attrs.Name, attrs.Index, err)
	}

	var out []string
	for _, route := range routes {
		if route.Gw == nil || route.Gw.IsUnspecified() {
			continue
		}
		for _, neigh := range neighs {
			if neigh.IP == nil || neigh.HardwareAddr == nil {
				continue
			}
			if route.Gw.Equal(neigh.IP) {
				out = append(out, normalizeMAC(neigh.HardwareAddr.String()))
			}
		}
	}
	return uniqueSortedStrings(out), nil
}

func interfaceAddrs(link netlink.Link) ([]netip.Addr, error) {
	addrList, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		attrs := link.Attrs()
		if attrs != nil {
			return nil, fmt.Errorf("list addresses for %s(index %d): %w", attrs.Name, attrs.Index, err)
		}
		return nil, fmt.Errorf("list addresses: %w", err)
	}

	addrs := make([]netip.Addr, 0, len(addrList))
	for _, addr := range addrList {
		parsed, ok := netipAddrFromIP(addr.IP)
		if ok {
			addrs = append(addrs, parsed)
		}
	}
	sort.Slice(addrs, func(i, j int) bool {
		return addrs[i].Less(addrs[j])
	})
	return addrs, nil
}

func netipAddrFromIP(ip net.IP) (netip.Addr, bool) {
	if v4 := ip.To4(); v4 != nil {
		addr, ok := netip.AddrFromSlice(v4)
		return addr.Unmap(), ok
	}
	if v6 := ip.To16(); v6 != nil {
		addr, ok := netip.AddrFromSlice(v6)
		return addr.Unmap(), ok
	}
	return netip.Addr{}, false
}

func selectInterfaces(all []interfaceInfo, opts options) ([]interfaceInfo, error) {
	var selected []interfaceInfo
	for _, iface := range all {
		matches, err := interfaceMatchesSelectors(iface, opts)
		if err != nil {
			return nil, err
		}
		if matches {
			selected = append(selected, iface)
		}
	}

	sort.Slice(selected, func(i, j int) bool {
		return selected[i].Name < selected[j].Name
	})
	return selected, nil
}

func interfaceMatchesSelectors(iface interfaceInfo, opts options) (bool, error) {
	ignored, err := interfaceMatchesIgnoreSelectors(iface, opts)
	if err != nil {
		return false, err
	}
	if ignored {
		return false, nil
	}

	for _, typ := range opts.InterfaceTypes {
		if iface.Type == typ {
			return true, nil
		}
	}
	for _, name := range opts.InterfaceNames {
		if iface.Name == name {
			return true, nil
		}
	}
	for _, pattern := range opts.InterfaceRegexps {
		matches, err := regexp.MatchString(pattern, iface.Name)
		if err != nil {
			return false, fmt.Errorf("compile interface regexp %q: %w", pattern, err)
		}
		if matches {
			return true, nil
		}
	}
	return false, nil
}

func interfaceMatchesIgnoreSelectors(iface interfaceInfo, opts options) (bool, error) {
	if iface.Name == "lo" {
		return true, nil
	}
	for _, typ := range opts.IgnoredInterfaceTypes {
		if iface.Type == typ {
			return true, nil
		}
	}
	for _, name := range opts.IgnoredInterfaceNames {
		if iface.Name == name {
			return true, nil
		}
	}
	for _, pattern := range opts.IgnoredInterfaceRegexps {
		matches, err := regexp.MatchString(pattern, iface.Name)
		if err != nil {
			return false, fmt.Errorf("compile ignored interface regexp %q: %w", pattern, err)
		}
		if matches {
			return true, nil
		}
	}
	return false, nil
}

func interfaceNames(ifaces []interfaceInfo) string {
	names := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		names = append(names, iface.Name)
	}
	return strings.Join(names, ", ")
}
