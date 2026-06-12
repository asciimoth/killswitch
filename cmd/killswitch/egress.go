//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"

	"github.com/asciimoth/killswitch/internal/adminapi"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

func newEgressManager(program *ebpf.Program) *egressManager {
	return &egressManager{
		program:  program,
		attached: make(map[int]attachedInterface),
	}
}

func (m *egressManager) reconcileCurrent(opts options, strict bool) (bool, error) {
	selected, err := selectedInterfaces(opts)
	if err != nil {
		return false, err
	}
	if len(selected) == 0 {
		log.Print("No interfaces currently match the configured selectors")
	}
	return m.reconcile(selected, strict)
}

func (m *egressManager) reconcile(selected []interfaceInfo, strict bool) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	desired := make(map[int]interfaceInfo, len(selected))
	for _, iface := range selected {
		desired[iface.Index] = iface
	}

	changed := false
	for index, attached := range m.attached {
		if _, ok := desired[index]; ok {
			continue
		}
		if err := attached.link.Close(); err != nil {
			log.Printf("ERROR: detach tc egress program from %s(index %d type %s): %s", attached.info.Name, attached.info.Index, attached.info.Type, err)
		} else {
			log.Printf("Detached tc egress program from %s(index %d type %s)", attached.info.Name, attached.info.Index, attached.info.Type)
		}
		delete(m.attached, index)
		changed = true
	}

	var attachErr error
	for _, iface := range selected {
		if attached, ok := m.attached[iface.Index]; ok {
			attached.info = iface
			m.attached[iface.Index] = attached
			continue
		}

		l, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   m.program,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			err = fmt.Errorf("attach tc egress program to %s(index %d type %s): %w", iface.Name, iface.Index, iface.Type, err)
			log.Printf("ERROR: %s", err)
			attachErr = errors.Join(attachErr, err)
			continue
		}
		m.attached[iface.Index] = attachedInterface{link: l, info: iface}
		log.Printf("Attached tc egress program to %s(index %d type %s)", iface.Name, iface.Index, iface.Type)
		changed = true
	}

	if changed {
		log.Printf("Kill switch attached to: %s", interfaceNames(m.attachedInterfacesLocked()))
	}
	if strict {
		return changed, attachErr
	}
	return changed, nil
}

func (m *egressManager) attachedInterfacesLocked() []interfaceInfo {
	ifaces := make([]interfaceInfo, 0, len(m.attached))
	for _, attached := range m.attached {
		ifaces = append(ifaces, attached.info)
	}
	sort.Slice(ifaces, func(i, j int) bool {
		return ifaces[i].Name < ifaces[j].Name
	})
	return ifaces
}

func (m *egressManager) close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for index, attached := range m.attached {
		if err := attached.link.Close(); err != nil {
			log.Printf("closing link for %s(index %d): %s", attached.info.Name, attached.info.Index, err)
		}
		delete(m.attached, index)
	}
}

func watchInterfaces(ctx context.Context, manager *egressManager, policies *policyManager, reconcileMu *sync.Mutex, notify func(adminapi.EventType)) error {
	linkUpdates := make(chan netlink.LinkUpdate, 32)
	addrUpdates := make(chan netlink.AddrUpdate, 32)
	routeUpdates := make(chan netlink.RouteUpdate, 32)
	neighUpdates := make(chan netlink.NeighUpdate, 32)
	done := make(chan struct{})
	defer close(done)

	subscribeErrs := make(chan error, 1)
	errCallback := func(err error) {
		select {
		case subscribeErrs <- err:
		default:
			log.Printf("ERROR: netlink link watcher: %s", err)
		}
	}

	if err := netlink.LinkSubscribeWithOptions(linkUpdates, done, netlink.LinkSubscribeOptions{
		ErrorCallback: errCallback,
	}); err != nil {
		return fmt.Errorf("subscribe to netlink link updates: %w", err)
	}
	if err := netlink.AddrSubscribeWithOptions(addrUpdates, done, netlink.AddrSubscribeOptions{
		ErrorCallback: errCallback,
	}); err != nil {
		return fmt.Errorf("subscribe to netlink addr updates: %w", err)
	}
	if err := netlink.RouteSubscribeWithOptions(routeUpdates, done, netlink.RouteSubscribeOptions{
		ErrorCallback: errCallback,
	}); err != nil {
		return fmt.Errorf("subscribe to netlink route updates: %w", err)
	}
	if err := netlink.NeighSubscribeWithOptions(neighUpdates, done, netlink.NeighSubscribeOptions{
		ErrorCallback: errCallback,
	}); err != nil {
		return fmt.Errorf("subscribe to netlink neighbor updates: %w", err)
	}

	if _, err := manager.reconcileCurrent(policies.optionsSnapshot(), true); err != nil {
		return err
	}
	policyChanged, err := policies.reconcileAttached(manager, true)
	if err != nil {
		return err
	}
	if notify != nil {
		notify(adminapi.EventTypeInterfaces)
		if policyChanged {
			notify(adminapi.EventTypeConfig)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-subscribeErrs:
			return fmt.Errorf("netlink watcher: %w", err)
		case <-linkUpdates:
			reconcileMu.Lock()
			opts := policies.optionsSnapshot()
			interfacesChanged, err := manager.reconcileCurrent(opts, false)
			if err != nil {
				log.Printf("ERROR: reconcile interfaces after netlink link update: %s", err)
			}
			policyChanged, err := policies.reconcileAttached(manager, true)
			if err != nil {
				log.Printf("ERROR: reconcile rulesets after netlink link update: %s", err)
			}
			reconcileMu.Unlock()
			if notify != nil {
				notify(adminapi.EventTypeInterfaces)
				if interfacesChanged || policyChanged {
					notify(adminapi.EventTypeConfig)
				}
			}
		case <-addrUpdates:
			reconcileMu.Lock()
			_, err := manager.reconcileCurrent(policies.optionsSnapshot(), false)
			if err != nil {
				log.Printf("ERROR: reconcile interfaces after netlink addr update: %s", err)
			}
			policyChanged, err := policies.reconcileAttached(manager, true)
			if err != nil {
				log.Printf("ERROR: reconcile rulesets after netlink addr update: %s", err)
			}
			reconcileMu.Unlock()
			if notify != nil {
				notify(adminapi.EventTypeInterfaces)
				if policyChanged {
					notify(adminapi.EventTypeConfig)
				}
			}
		case <-routeUpdates:
			reconcileMu.Lock()
			interfacesChanged, err := manager.reconcileCurrent(policies.optionsSnapshot(), false)
			if err != nil {
				log.Printf("ERROR: reconcile interfaces after netlink route update: %s", err)
			}
			policyChanged, err := policies.reconcileAttached(manager, true)
			if err != nil {
				log.Printf("ERROR: reconcile rulesets after netlink route update: %s", err)
			}
			reconcileMu.Unlock()
			if notify != nil {
				if interfacesChanged {
					notify(adminapi.EventTypeInterfaces)
				}
				if policyChanged {
					notify(adminapi.EventTypeConfig)
				}
			}
		case <-neighUpdates:
			reconcileMu.Lock()
			interfacesChanged, err := manager.reconcileCurrent(policies.optionsSnapshot(), false)
			if err != nil {
				log.Printf("ERROR: reconcile interfaces after netlink neighbor update: %s", err)
			}
			policyChanged, err := policies.reconcileAttached(manager, true)
			if err != nil {
				log.Printf("ERROR: reconcile rulesets after netlink neighbor update: %s", err)
			}
			reconcileMu.Unlock()
			if notify != nil {
				if interfacesChanged {
					notify(adminapi.EventTypeInterfaces)
				}
				if policyChanged {
					notify(adminapi.EventTypeConfig)
				}
			}
		}
	}
}
