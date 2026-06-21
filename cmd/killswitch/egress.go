//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/asciimoth/killswitch/internal/adminapi"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

const (
	netlinkUpdateBufferSize  = 1024
	netlinkReceiveBufferSize = 4 * 1024 * 1024
	netlinkReconcileDelay    = 100 * time.Millisecond
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
	var linkUpdates chan netlink.LinkUpdate
	var addrUpdates chan netlink.AddrUpdate
	var routeUpdates chan netlink.RouteUpdate
	var neighUpdates chan netlink.NeighUpdate

	type subscriptionError struct {
		generation int
		err        error
	}
	subscribeErrs := make(chan subscriptionError, 1)

	subscribe := func(done <-chan struct{}, generation int) error {
		linkUpdates = make(chan netlink.LinkUpdate, netlinkUpdateBufferSize)
		addrUpdates = make(chan netlink.AddrUpdate, netlinkUpdateBufferSize)
		routeUpdates = make(chan netlink.RouteUpdate, netlinkUpdateBufferSize)
		neighUpdates = make(chan netlink.NeighUpdate, netlinkUpdateBufferSize)
		errCallback := func(err error) {
			select {
			case subscribeErrs <- subscriptionError{generation: generation, err: err}:
			default:
				log.Printf("ERROR: netlink watcher: %s", err)
			}
		}
		if err := netlink.LinkSubscribeWithOptions(linkUpdates, done, netlink.LinkSubscribeOptions{
			ErrorCallback:          errCallback,
			ReceiveBufferSize:      netlinkReceiveBufferSize,
			ReceiveBufferForceSize: true,
		}); err != nil {
			return fmt.Errorf("subscribe to netlink link updates: %w", err)
		}
		if err := netlink.AddrSubscribeWithOptions(addrUpdates, done, netlink.AddrSubscribeOptions{
			ErrorCallback:          errCallback,
			ReceiveBufferSize:      netlinkReceiveBufferSize,
			ReceiveBufferForceSize: true,
		}); err != nil {
			return fmt.Errorf("subscribe to netlink addr updates: %w", err)
		}
		if err := netlink.RouteSubscribeWithOptions(routeUpdates, done, netlink.RouteSubscribeOptions{
			ErrorCallback:          errCallback,
			ReceiveBufferSize:      netlinkReceiveBufferSize,
			ReceiveBufferForceSize: true,
		}); err != nil {
			return fmt.Errorf("subscribe to netlink route updates: %w", err)
		}
		if err := netlink.NeighSubscribeWithOptions(neighUpdates, done, netlink.NeighSubscribeOptions{
			ErrorCallback:          errCallback,
			ReceiveBufferSize:      netlinkReceiveBufferSize,
			ReceiveBufferForceSize: true,
		}); err != nil {
			return fmt.Errorf("subscribe to netlink neighbor updates: %w", err)
		}
		return nil
	}

	reconcile := func(reason string, strict bool, notifyInterfaces bool) error {
		reconcileMu.Lock()
		interfacesChanged, ifaceErr := manager.reconcileCurrent(policies.optionsSnapshot(), strict)
		if ifaceErr != nil {
			log.Printf("ERROR: reconcile interfaces after %s: %s", reason, ifaceErr)
		}
		policyChanged, policyErr := policies.reconcileAttached(manager, true)
		if policyErr != nil {
			log.Printf("ERROR: reconcile rulesets after %s: %s", reason, policyErr)
		}
		reconcileMu.Unlock()
		if notify != nil {
			if notifyInterfaces || interfacesChanged {
				notify(adminapi.EventTypeInterfaces)
			}
			if interfacesChanged || policyChanged {
				notify(adminapi.EventTypeConfig)
			}
		}
		if strict {
			return errors.Join(ifaceErr, policyErr)
		}
		return nil
	}

	subscriptionDone := make(chan struct{})
	defer close(subscriptionDone)
	subscriptionGeneration := 1
	if err := subscribe(subscriptionDone, subscriptionGeneration); err != nil {
		return err
	}
	if err := reconcile("startup", true, true); err != nil {
		return err
	}

	reconcileTimer := time.NewTimer(time.Hour)
	if !reconcileTimer.Stop() {
		<-reconcileTimer.C
	}
	defer reconcileTimer.Stop()
	reconcilePending := false
	notifyInterfaces := false
	scheduleReconcile := func(interfaces bool) {
		reconcilePending = true
		notifyInterfaces = notifyInterfaces || interfaces
		reconcileTimer.Reset(netlinkReconcileDelay)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case subErr := <-subscribeErrs:
			if subErr.generation != subscriptionGeneration {
				continue
			}
			log.Printf("ERROR: netlink watcher: %s; resubscribing", subErr.err)
			close(subscriptionDone)
			subscriptionDone = make(chan struct{})
			subscriptionGeneration++
			if err := subscribe(subscriptionDone, subscriptionGeneration); err != nil {
				return fmt.Errorf("resubscribe to netlink updates: %w", err)
			}
			_ = reconcile("netlink resubscribe", false, true)
		case <-linkUpdates:
			scheduleReconcile(true)
		case <-addrUpdates:
			scheduleReconcile(true)
		case <-routeUpdates:
			scheduleReconcile(false)
		case <-neighUpdates:
			scheduleReconcile(false)
		case <-reconcileTimer.C:
			if reconcilePending {
				interfaces := notifyInterfaces
				reconcilePending = false
				notifyInterfaces = false
				_ = reconcile("netlink update", false, interfaces)
			}
		}
	}
}
