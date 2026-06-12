package main

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"

	"github.com/asciimoth/killswitch/internal/adminapi"
	dbusnotify "github.com/esiqveland/notify"
	"github.com/godbus/dbus/v5"
)

const allowAllNotificationActionDisable = "disable-allow-all"
const captivePortalNotificationActionOpen = "open-captive-portal"

type desktopNotifier struct {
	mu                  sync.Mutex
	dbusNotifier        dbusnotify.Notifier
	dbusConn            *dbus.Conn
	allowAllID          uint32
	allowAllDisableFunc func()
	captivePortalID     uint32
	captivePortalOpen   func()
}
type configNotificationWatcher struct {
	notifyInterfaceChanges bool
	notifyGlobalAllowAll   bool
	disableAllowAll        chan<- struct{}
	lastInterfaces         map[string]adminapi.Interface
	allowAllShown          bool
}

func (w *configNotificationWatcher) applyInitial(cfg adminapi.CurrentConfig) {
	w.lastInterfaces = attachedInterfaceMap(cfg)
}

func (w *configNotificationWatcher) update(notifications notifier, cfg adminapi.CurrentConfig) {
	if w.notifyInterfaceChanges {
		w.updateInterfaces(notifications, cfg)
	} else {
		w.lastInterfaces = attachedInterfaceMap(cfg)
	}
	w.updateGlobalAllowAll(notifications, cfg)
}

func (w *configNotificationWatcher) updateInterfaces(notifications notifier, cfg adminapi.CurrentConfig) {
	next := attachedInterfaceMap(cfg)
	if w.lastInterfaces == nil {
		w.lastInterfaces = next
		return
	}

	for _, iface := range appearedInterfaces(w.lastInterfaces, next) {
		if err := notifications.Notify(adminapi.Notification{
			Level:  adminapi.NotificationLevelNormal,
			Header: "Interface appeared",
			Text:   interfaceDescription(iface),
		}); err != nil {
			log.Printf("send interface appeared notification: %s", err)
		}
	}
	for _, iface := range disappearedInterfaces(w.lastInterfaces, next) {
		if err := notifications.Notify(adminapi.Notification{
			Level:  adminapi.NotificationLevelWarn,
			Header: "Interface disappeared",
			Text:   interfaceDescription(iface),
		}); err != nil {
			log.Printf("send interface disappeared notification: %s", err)
		}
	}

	w.lastInterfaces = next
}

func attachedInterfaceMap(cfg adminapi.CurrentConfig) map[string]adminapi.Interface {
	out := make(map[string]adminapi.Interface)
	for _, iface := range cfg.EffectiveInterfaces {
		if !iface.Attached {
			continue
		}
		out[iface.Name] = adminapi.Interface{
			Index:       iface.Index,
			Name:        iface.Name,
			Type:        iface.Type,
			SSID:        iface.SSID,
			BSSID:       iface.BSSID,
			GatewayMACs: cloneStrings(iface.GatewayMACs),
			Matched:     iface.Matched,
			Killswitch:  iface.Attached,
		}
	}
	if len(out) > 0 {
		return out
	}
	for _, iface := range cfg.Interfaces {
		if iface.Killswitch {
			out[iface.Name] = iface
		}
	}
	return out
}

func (w *configNotificationWatcher) updateGlobalAllowAll(notifications notifier, cfg adminapi.CurrentConfig) {
	if !w.notifyGlobalAllowAll {
		w.allowAllShown = cfg.BasePolicy.AllowAll
		return
	}
	if cfg.BasePolicy.AllowAll {
		if w.allowAllShown {
			return
		}
		w.allowAllShown = true
		if err := notifications.NotifyGlobalAllowAll(func() {
			select {
			case w.disableAllowAll <- struct{}{}:
			default:
			}
		}); err != nil {
			log.Printf("send global allow_all notification: %s", err)
		}
		return
	}
	if w.allowAllShown {
		if err := notifications.CloseGlobalAllowAll(); err != nil {
			log.Printf("close global allow_all notification: %s", err)
		}
	}
	w.allowAllShown = false
}

func appearedInterfaces(old, next map[string]adminapi.Interface) []adminapi.Interface {
	return interfaceDiff(next, old)
}

func disappearedInterfaces(old, next map[string]adminapi.Interface) []adminapi.Interface {
	return interfaceDiff(old, next)
}

func interfaceDiff(a, b map[string]adminapi.Interface) []adminapi.Interface {
	names := make([]string, 0)
	for name := range a {
		if _, ok := b[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	out := make([]adminapi.Interface, 0, len(names))
	for _, name := range names {
		out = append(out, a[name])
	}
	return out
}

func interfaceDescription(iface adminapi.Interface) string {
	if iface.Type == "" {
		return iface.Name
	}
	return fmt.Sprintf("%s (%s)", iface.Name, iface.Type)
}
func newDesktopNotifier() *desktopNotifier {
	return &desktopNotifier{}
}

func (n *desktopNotifier) Notify(notification adminapi.Notification) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.dbusNotifier == nil {
		if err := n.openDBusNotifierLocked(); err != nil {
			return err
		}
	}

	note := dbusnotify.Notification{
		AppName:       "Killswitch",
		Summary:       notificationTitle(notification),
		Body:          notification.Text,
		ExpireTimeout: dbusnotify.ExpireTimeoutSetByNotificationServer,
	}
	note.SetUrgency(notificationUrgency(notification))

	_, err := n.dbusNotifier.SendNotification(note)
	return err
}

func (n *desktopNotifier) NotifyGlobalAllowAll(disable func()) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.allowAllDisableFunc = disable
	if n.dbusNotifier == nil {
		if err := n.openDBusNotifierLocked(); err != nil {
			return err
		}
	}

	note := dbusnotify.Notification{
		AppName:    "Killswitch",
		ReplacesID: n.allowAllID,
		Summary:    "Killswitch: global allow all enabled",
		Body:       "Global allow_all is enabled outside of rulesets and applies to all interfaces.",
		Actions: []dbusnotify.Action{
			{Key: allowAllNotificationActionDisable, Label: "Disable allow all"},
		},
		ExpireTimeout: dbusnotify.ExpireTimeoutNever,
	}
	note.SetUrgency(dbusnotify.UrgencyCritical)

	id, err := n.dbusNotifier.SendNotification(note)
	if err != nil {
		return err
	}
	n.allowAllID = id
	return nil
}

func (n *desktopNotifier) NotifyCaptivePortal(notification adminapi.Notification, open func()) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.captivePortalOpen = open
	if n.dbusNotifier == nil {
		if err := n.openDBusNotifierLocked(); err != nil {
			return err
		}
	}

	note := dbusnotify.Notification{
		AppName:    "Killswitch",
		ReplacesID: n.captivePortalID,
		Summary:    notificationTitle(notification),
		Body:       notification.Text,
		Actions: []dbusnotify.Action{
			{Key: captivePortalNotificationActionOpen, Label: "Open login page"},
		},
		ExpireTimeout: dbusnotify.ExpireTimeoutNever,
	}
	note.SetUrgency(notificationUrgency(notification))

	id, err := n.dbusNotifier.SendNotification(note)
	if err != nil {
		return err
	}
	n.captivePortalID = id
	return nil
}

func (n *desktopNotifier) openDBusNotifierLocked() error {
	conn, err := dbus.SessionBusPrivate()
	if err != nil {
		return err
	}
	if err := conn.Auth(nil); err != nil {
		conn.Close() //nolint:errcheck
		return err
	}
	if err := conn.Hello(); err != nil {
		conn.Close() //nolint:errcheck
		return err
	}

	notifier, err := dbusnotify.New(conn, dbusnotify.WithOnAction(func(action *dbusnotify.ActionInvokedSignal) {
		if action.ActionKey != allowAllNotificationActionDisable && action.ActionKey != captivePortalNotificationActionOpen {
			return
		}
		n.mu.Lock()
		switch action.ActionKey {
		case allowAllNotificationActionDisable:
			if n.allowAllID != 0 && action.ID != n.allowAllID {
				n.mu.Unlock()
				return
			}
			disable := n.allowAllDisableFunc
			n.mu.Unlock()
			if disable != nil {
				disable()
			}
		case captivePortalNotificationActionOpen:
			if n.captivePortalID != 0 && action.ID != n.captivePortalID {
				n.mu.Unlock()
				return
			}
			open := n.captivePortalOpen
			n.mu.Unlock()
			if open != nil {
				open()
			}
		}
	}))
	if err != nil {
		conn.Close() //nolint:errcheck
		return err
	}

	n.dbusConn = conn
	n.dbusNotifier = notifier
	return nil
}

func (n *desktopNotifier) CloseGlobalAllowAll() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.dbusNotifier == nil || n.allowAllID == 0 {
		return nil
	}
	_, err := n.dbusNotifier.CloseNotification(n.allowAllID)
	n.allowAllID = 0
	return err
}

func (n *desktopNotifier) CloseCaptivePortal() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.captivePortalOpen = nil
	if n.dbusNotifier == nil || n.captivePortalID == 0 {
		return nil
	}
	_, err := n.dbusNotifier.CloseNotification(n.captivePortalID)
	n.captivePortalID = 0
	return err
}

func (n *desktopNotifier) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	var errs []error
	if n.dbusNotifier != nil {
		if n.allowAllID != 0 {
			if _, err := n.dbusNotifier.CloseNotification(n.allowAllID); err != nil {
				errs = append(errs, err)
			}
			n.allowAllID = 0
		}
		if n.captivePortalID != 0 {
			if _, err := n.dbusNotifier.CloseNotification(n.captivePortalID); err != nil {
				errs = append(errs, err)
			}
			n.captivePortalID = 0
		}
		n.captivePortalOpen = nil
		if err := n.dbusNotifier.Close(); err != nil {
			errs = append(errs, err)
		}
		n.dbusNotifier = nil
	}
	if n.dbusConn != nil {
		if err := n.dbusConn.Close(); err != nil {
			errs = append(errs, err)
		}
		n.dbusConn = nil
	}
	return errors.Join(errs...)
}

func notificationTitle(notification adminapi.Notification) string {
	if notification.Header != "" {
		return "Killswitch: " + notification.Header
	}
	switch notification.Level {
	case adminapi.NotificationLevelWarn:
		return "Killswitch warning"
	case adminapi.NotificationLevelError:
		return "Killswitch error"
	default:
		return "Killswitch"
	}
}

func notificationUrgency(notification adminapi.Notification) dbusnotify.Urgency {
	switch notification.Level {
	case adminapi.NotificationLevelWarn, adminapi.NotificationLevelError:
		return dbusnotify.UrgencyCritical
	default:
		return dbusnotify.UrgencyNormal
	}
}
