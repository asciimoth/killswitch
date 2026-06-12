package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/asciimoth/killswitch/internal/adminapi"
	"github.com/asciimoth/socksgo"
)

const networkCheckStatusHeader = "X-NetworkManager-Status"

type networkCheckStatus string

const (
	networkCheckStatusInternetAvailable networkCheckStatus = "internet available"
	networkCheckStatusNoInternet        networkCheckStatus = "no internet"
	networkCheckStatusLoginRequired     networkCheckStatus = "login required"
)

type networkCheckResult struct {
	Reason         string
	Status         networkCheckStatus
	PortalURL      string
	Proxy          string
	Detail         string
	SocksProxyHost string
	SocksProxyPort uint16
	SocksProxyAddr string
}

type networkCheckWatcher struct {
	opts                   networkCheckOptions
	running                bool
	lastStatus             networkCheckStatus
	haveStatus             bool
	lastInterfacesSnapshot string
	lastCaptivePortal      *networkCheckResult
}

func newNetworkCheckWatcher(opts networkCheckOptions) *networkCheckWatcher {
	return &networkCheckWatcher{opts: opts}
}

func (w *networkCheckWatcher) applyInitial(cfg adminapi.CurrentConfig) {
	w.lastInterfacesSnapshot = interfacesSnapshot(cfg)
}

func (w *networkCheckWatcher) checkIfInterfacesChanged(ctx context.Context, cfg adminapi.CurrentConfig, results chan<- networkCheckResult, reason string) {
	snapshot := interfacesSnapshot(cfg)
	if snapshot == w.lastInterfacesSnapshot {
		return
	}
	w.lastInterfacesSnapshot = snapshot
	w.check(ctx, cfg, results, reason)
}

func (w *networkCheckWatcher) checkInterfacesEvent(ctx context.Context, cfg adminapi.CurrentConfig, results chan<- networkCheckResult) {
	w.lastInterfacesSnapshot = interfacesSnapshot(cfg)
	w.check(ctx, cfg, results, "interfaces")
}

func (w *networkCheckWatcher) check(ctx context.Context, cfg adminapi.CurrentConfig, results chan<- networkCheckResult, reason string) {
	if !w.opts.Enabled {
		return
	}
	if w.running {
		log.Printf("Network check skipped (%s): previous check is still running", reason)
		return
	}
	w.running = true
	log.Printf("Network check started (%s): url=%s", reason, w.opts.URL)
	go func() {
		result := runNetworkCheck(ctx, w.opts, cfg, reason)
		select {
		case results <- result:
		case <-ctx.Done():
		}
	}()
}

func (w *networkCheckWatcher) finish(ctx context.Context, notifications notifier, tray trayController, result networkCheckResult) {
	w.running = false
	if result.PortalURL != "" {
		log.Printf("Network check finished (%s): status=%s proxy=%s portal=%s detail=%s", result.Reason, result.Status, result.Proxy, result.PortalURL, result.Detail)
	} else {
		log.Printf("Network check finished (%s): status=%s proxy=%s detail=%s", result.Reason, result.Status, result.Proxy, result.Detail)
	}
	tray.UpdateNetwork(networkTrayState{
		Enabled:       true,
		Status:        result.Status,
		PortalURL:     result.PortalURL,
		OpenLoginPage: result.Status == networkCheckStatusLoginRequired && len(w.opts.CaptivePortal.Cmd) > 0,
	})

	changed := !w.haveStatus || w.lastStatus != result.Status
	firstInternet := !w.haveStatus && result.Status == networkCheckStatusInternetAvailable
	w.haveStatus = true
	w.lastStatus = result.Status
	if result.Status == networkCheckStatusLoginRequired {
		w.lastCaptivePortal = &result
	} else if result.Status != networkCheckStatusLoginRequired {
		w.lastCaptivePortal = nil
		if err := notifications.CloseCaptivePortal(); err != nil {
			log.Printf("close captive portal notification: %s", err)
		}
	}
	if !w.opts.Notify || !changed || firstInternet {
		return
	}
	if result.Status == networkCheckStatusLoginRequired {
		if err := notifications.NotifyCaptivePortal(networkCheckNotification(result), func() {
			w.openCaptivePortal(ctx, notifications, result)
		}); err != nil {
			log.Printf("send captive portal notification: %s", err)
		}
		return
	}
	if err := notifications.Notify(networkCheckNotification(result)); err != nil {
		log.Printf("send network check notification: %s", err)
	}
}

func (w *networkCheckWatcher) openLastCaptivePortal(ctx context.Context, notifications notifier) {
	if w.lastCaptivePortal == nil {
		return
	}
	w.openCaptivePortal(ctx, notifications, *w.lastCaptivePortal)
}

func (w *networkCheckWatcher) openCaptivePortal(ctx context.Context, notifications notifier, result networkCheckResult) {
	if len(w.opts.CaptivePortal.Cmd) == 0 {
		return
	}
	go executeCaptivePortalCommand(ctx, notifications, w.opts.CaptivePortal, result)
}

func runNetworkCheck(ctx context.Context, opts networkCheckOptions, cfg adminapi.CurrentConfig, reason string) networkCheckResult {
	proxy := "direct"
	socksProxyHost := cfg.SocksProxy.Host
	socksProxyPort := cfg.SocksProxy.Port
	socksProxyAddr := ""
	if socksProxyHost != "" && socksProxyPort != 0 {
		socksProxyAddr = "socks5://" + net.JoinHostPort(socksProxyHost, fmt.Sprintf("%d", socksProxyPort))
	}
	client := &http.Client{
		Transport:     networkCheckTransport(nil),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       opts.Timeout,
	}
	if cfg.SocksProxy.Running {
		proxyAddr := net.JoinHostPort(socksProxyHost, fmt.Sprintf("%d", socksProxyPort))
		socksClient := &socksgo.Client{
			SocksVersion: "5",
			ProxyAddr:    proxyAddr,
			Filter:       func(_, _ string) bool { return false },
		}
		client.Transport = networkCheckTransport(socksClient.Dial)
		proxy = proxyAddr
	}

	// req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.URL, nil)
	// if err != nil {
	// 	return networkCheckResult{Reason: reason, Status: networkCheckStatusNoInternet, Proxy: proxy, Detail: err.Error(), SocksProxyHost: socksProxyHost, SocksProxyPort: socksProxyPort, SocksProxyAddr: socksProxyAddr}
	// }
	// resp, err := client.Do(req)

	resp, req, err := DoRequestWithRetries(ctx, client, opts.URL)

	if err != nil {
		return networkCheckResult{Reason: reason, Status: networkCheckStatusNoInternet, Proxy: proxy, Detail: err.Error(), SocksProxyHost: socksProxyHost, SocksProxyPort: socksProxyPort, SocksProxyAddr: socksProxyAddr}
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return networkCheckResult{
			Reason:         reason,
			Status:         networkCheckStatusLoginRequired,
			PortalURL:      redirectURL(resp, req.URL),
			Proxy:          proxy,
			Detail:         fmt.Sprintf("redirect status %d", resp.StatusCode),
			SocksProxyHost: socksProxyHost,
			SocksProxyPort: socksProxyPort,
			SocksProxyAddr: socksProxyAddr,
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return networkCheckResult{Reason: reason, Status: networkCheckStatusNoInternet, Proxy: proxy, Detail: err.Error(), SocksProxyHost: socksProxyHost, SocksProxyPort: socksProxyPort, SocksProxyAddr: socksProxyAddr}
	}

	if networkCheckMatchesExpected(opts, resp, string(body)) {
		return networkCheckResult{
			Reason:         reason,
			Status:         networkCheckStatusInternetAvailable,
			Proxy:          proxy,
			Detail:         fmt.Sprintf("matched status %d", resp.StatusCode),
			SocksProxyHost: socksProxyHost,
			SocksProxyPort: socksProxyPort,
			SocksProxyAddr: socksProxyAddr,
		}
	}

	return networkCheckResult{
		Reason:         reason,
		Status:         networkCheckStatusLoginRequired,
		Proxy:          proxy,
		Detail:         fmt.Sprintf("unexpected status=%d header=%q body_len=%d", resp.StatusCode, resp.Header.Get(networkCheckStatusHeader), len(body)),
		SocksProxyHost: socksProxyHost,
		SocksProxyPort: socksProxyPort,
		SocksProxyAddr: socksProxyAddr,
	}
}

type captivePortalTemplateData struct {
	Tmp            string
	ProxyHost      string
	ProxyPort      uint16
	ProxyAddr      string
	SouksProxyHost string
	SocksProxyPort uint16
	SocksProxyAddr string
	Portal         string
}

func executeCaptivePortalCommand(ctx context.Context, notifications notifier, opts captivePortalOptions, result networkCheckResult) {
	if len(opts.Cmd) == 0 {
		return
	}
	tmp, err := os.MkdirTemp("", "killswitch-captive-portal-*")
	if err != nil {
		reportCaptivePortalCommandError(notifications, "create temp dir", err)
		return
	}
	defer func() {
		if err := os.RemoveAll(tmp); err != nil {
			reportCaptivePortalCommandError(notifications, "remove temp dir", err)
		}
	}()
	tmp, err = filepath.Abs(tmp)
	if err != nil {
		reportCaptivePortalCommandError(notifications, "resolve temp dir", err)
		return
	}

	data := captivePortalTemplateData{
		Tmp:            tmp,
		ProxyHost:      result.SocksProxyHost,
		ProxyPort:      result.SocksProxyPort,
		ProxyAddr:      result.SocksProxyAddr,
		SocksProxyPort: result.SocksProxyPort,
		SocksProxyAddr: result.SocksProxyAddr,
		Portal:         result.PortalURL,
	}
	if data.Portal == "" {
		data.Portal = "http://example.com"
	}

	cmdArgs, err := renderCaptivePortalTemplates("cmd", opts.Cmd, data)
	if err != nil {
		reportCaptivePortalCommandError(notifications, "render command", err)
		return
	}
	envOverrides, err := renderCaptivePortalEnvTemplates(opts.Env, data)
	if err != nil {
		reportCaptivePortalCommandError(notifications, "render env", err)
		return
	}

	log.Printf("Captive portal command started: cmd=%q portal=%s tmp=%s", cmdArgs, data.Portal, tmp)
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = append(os.Environ(), envOverrides...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail != "" {
			err = fmt.Errorf("%w: %s", err, detail)
		}
		reportCaptivePortalCommandError(notifications, "execute command", err)
		return
	}
	log.Printf("Captive portal command finished: cmd=%q", cmdArgs)
}

func renderCaptivePortalEnvTemplates(env map[string]string, data captivePortalTemplateData) ([]string, error) {
	if len(env) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, key := range keys {
		value, err := renderCaptivePortalTemplate("env."+key, env[key], data)
		if err != nil {
			return nil, err
		}
		out = append(out, key+"="+value)
	}
	return out, nil
}

func renderCaptivePortalTemplates(name string, values []string, data captivePortalTemplateData) ([]string, error) {
	out := make([]string, 0, len(values))
	for i, value := range values {
		rendered, err := renderCaptivePortalTemplate(fmt.Sprintf("%s[%d]", name, i), value, data)
		if err != nil {
			return nil, err
		}
		out = append(out, rendered)
	}
	return out, nil
}

func renderCaptivePortalTemplate(name, value string, data captivePortalTemplateData) (string, error) {
	tpl, err := template.New(name).Option("missingkey=error").Parse(value)
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	if err := tpl.Execute(&out, data); err != nil {
		return "", err
	}
	return out.String(), nil
}

func reportCaptivePortalCommandError(notifications notifier, action string, err error) {
	log.Printf("Captive portal command %s: %s", action, err)
	if notifyErr := notifications.Notify(adminapi.Notification{
		Level:  adminapi.NotificationLevelError,
		Header: "Captive portal command failed",
		Text:   fmt.Sprintf("%s: %s", action, err),
	}); notifyErr != nil {
		log.Printf("send captive portal command error notification: %s", notifyErr)
	}
}

func networkCheckTransport(dialContext func(context.Context, string, string) (net.Conn, error)) *http.Transport {
	transport := &http.Transport{}
	if dialContext != nil {
		transport.DialContext = dialContext
	}
	return transport
}

func networkCheckMatchesExpected(opts networkCheckOptions, resp *http.Response, body string) bool {
	if resp.StatusCode != opts.Status {
		return false
	}
	if opts.Header != "" && resp.Header.Get(networkCheckStatusHeader) != opts.Header {
		return false
	}
	if opts.Text != "" && !strings.Contains(body, opts.Text) {
		return false
	}
	return true
}

func redirectURL(resp *http.Response, base *url.URL) string {
	location := resp.Header.Get("Location")
	if location == "" {
		return ""
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return location
	}
	return base.ResolveReference(parsed).String()
}

func networkCheckNotification(result networkCheckResult) adminapi.Notification {
	level := adminapi.NotificationLevelWarn
	header := "Network connectivity changed"
	text := string(result.Status)
	if result.Status == networkCheckStatusInternetAvailable {
		level = adminapi.NotificationLevelNormal
		text = "internet available"
	}
	if result.PortalURL != "" {
		text = fmt.Sprintf("%s: %s", text, result.PortalURL)
	}
	return adminapi.Notification{
		Level:  level,
		Header: header,
		Text:   text,
	}
}

func interfacesSnapshot(cfg adminapi.CurrentConfig) string {
	data, err := json.Marshal(struct {
		Interfaces          []adminapi.Interface       `json:"interfaces,omitempty"`
		EffectiveInterfaces []adminapi.InterfacePolicy `json:"effective_interfaces,omitempty"`
	}{
		Interfaces:          cfg.Interfaces,
		EffectiveInterfaces: cfg.EffectiveInterfaces,
	})
	if err != nil {
		return ""
	}
	return string(data)
}
func isTimeout(err error) bool {
	// Check for context deadline exceeded
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// Check for network-level timeouts
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return false
}

func DoRequestWithRetries(
	ctx context.Context,
	client *http.Client,
	url string,
) (*http.Response, *http.Request, error) {
	timeouts := []time.Duration{
		1 * time.Second, 2 * time.Second, 10 * time.Second,
	}

	var (
		lastErr error
		lastReq *http.Request
	)
	for _, timeout := range timeouts {
		subCtx, cancel := context.WithTimeout(ctx, timeout)

		req, err := http.NewRequestWithContext(subCtx, http.MethodGet, url, nil)
		lastReq = req
		if err != nil {
			cancel()
			return nil, req, err
		}

		resp, err := client.Do(req)
		cancel()

		if err == nil {
			return resp, req, nil
		}

		lastErr = err

		if isTimeout(err) {
			continue
		}

		return nil, req, err
	}
	return nil, lastReq, lastErr
}
