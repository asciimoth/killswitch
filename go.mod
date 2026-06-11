module github.com/asciimoth/killswitch

go 1.25.5

tool github.com/cilium/ebpf/cmd/bpf2go

require (
	github.com/cilium/ebpf v0.21.0
	github.com/energye/systray v1.0.3
	github.com/esiqveland/notify v0.13.3
	github.com/godbus/dbus/v5 v5.2.2
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/sys v0.46.0
)

require github.com/vishvananda/netns v0.0.5 // indirect
