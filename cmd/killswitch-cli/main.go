package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/asciimoth/killswitch/internal/adminapi"
	"golang.org/x/sys/unix"
)

func main() {
	log.SetFlags(0)
	if err := runCLI(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		log.Fatal(err)
	}
}

func runCLI(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		if err := printUsage(stderr); err != nil {
			return err
		}
		return flag.ErrHelp
	}

	switch args[0] {
	case "get-cfg":
		return runGetConfig(args[1:], stdout, stderr)
	case "add":
		return runMutation(adminapi.MutationAdd, args[1:], stdout, stderr)
	case "remove":
		return runMutation(adminapi.MutationRemove, args[1:], stdout, stderr)
	case "set":
		return runMutation(adminapi.MutationSet, args[1:], stdout, stderr)
	case "tmp-ruleset":
		return runTemporaryRuleset(args[1:], os.Stdin, stdout, stderr)
	case "force-ruleset":
		return runForceRuleset(args[1:], os.Stdin, stdout, stderr)
	case "notifications":
		return runNotifications(args[1:], stdout, stderr)
	case "debug-notify":
		return runDebugNotify(args[1:], stdout, stderr)
	case "socks-proxy":
		return runSocksProxy(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		return printUsage(stdout)
	default:
		if err := printUsage(stderr); err != nil {
			return err
		}
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func runNotifications(args []string, stdout, stderr io.Writer) error {
	jsonOutArg, args := extractJSONOutArg(args)
	flags := flag.NewFlagSet("notifications", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socketPath := flags.String("socket", adminapi.DefaultSocketPath, "admin API Unix socket path")
	flags.StringVar(socketPath, "s", adminapi.DefaultSocketPath, "admin API Unix socket path")
	jsonOut := flags.Bool("json-out", jsonOutArg, "print compact JSON output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("notifications expects no positional arguments, got: %s", strings.Join(flags.Args(), " "))
	}

	client, err := adminapi.DialUnix(context.Background(), *socketPath)
	if err != nil {
		return err
	}
	defer client.Close() //nolint:errcheck
	if err := client.Subscribe(adminapi.EventTypeNotification); err != nil {
		return err
	}
	return watchNotifications(client, stdout, *jsonOut)
}

func watchNotifications(client *adminapi.Client, stdout io.Writer, jsonOut bool) error {
	events := make(chan adminapi.Notification, 1)
	errs := make(chan error, 1)
	go func() {
		for {
			notification, err := client.WaitForNotification()
			if err != nil {
				errs <- err
				return
			}
			events <- notification
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	for {
		select {
		case notification := <-events:
			if jsonOut {
				if err := printJSONLine(stdout, notification); err != nil {
					return err
				}
				continue
			}
			if err := printNotification(stdout, notification); err != nil {
				return err
			}
		case err := <-errs:
			if adminapi.IsEOF(err) {
				return errors.New("server disconnected")
			}
			return err
		case <-signals:
			return nil
		}
	}
}

func runDebugNotify(args []string, stdout, stderr io.Writer) error {
	jsonOutArg, args := extractJSONOutArg(args)
	flags := flag.NewFlagSet("debug-notify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socketPath := flags.String("socket", adminapi.DefaultSocketPath, "admin API Unix socket path")
	flags.StringVar(socketPath, "s", adminapi.DefaultSocketPath, "admin API Unix socket path")
	level := flags.String("level", string(adminapi.NotificationLevelNormal), "notification level: normal, warn, or error")
	header := flags.String("header", "", "optional notification header")
	text := flags.String("text", "", "notification text")
	jsonOut := flags.Bool("json-out", jsonOutArg, "print compact JSON output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("debug-notify expects no positional arguments, got: %s", strings.Join(flags.Args(), " "))
	}
	if *text == "" {
		return errors.New("debug-notify requires -text")
	}

	client, err := adminapi.DialUnix(context.Background(), *socketPath)
	if err != nil {
		return err
	}
	defer client.Close() //nolint:errcheck

	result, err := client.DebugNotify(adminapi.Notification{
		Level:  adminapi.NotificationLevel(*level),
		Header: *header,
		Text:   *text,
	})
	if err != nil {
		return err
	}
	if !result.OK {
		return errors.New(result.Error)
	}
	if *jsonOut {
		return printJSONLine(stdout, result)
	}
	_, err = fmt.Fprintln(stdout, "sent")
	return err
}

func runSocksProxy(args []string, stdout, stderr io.Writer) error {
	jsonOutArg, args := extractJSONOutArg(args)
	flags := flag.NewFlagSet("socks-proxy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socketPath := flags.String("socket", adminapi.DefaultSocketPath, "admin API Unix socket path")
	flags.StringVar(socketPath, "s", adminapi.DefaultSocketPath, "admin API Unix socket path")
	jsonOut := flags.Bool("json-out", jsonOutArg, "print compact JSON output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("socks-proxy requires exactly one action: start or stop")
	}
	var enabled bool
	switch flags.Arg(0) {
	case "start":
		enabled = true
	case "stop":
		enabled = false
	default:
		return fmt.Errorf("unknown socks-proxy action %q", flags.Arg(0))
	}

	raw, err := json.Marshal(enabled)
	if err != nil {
		return err
	}
	client, err := adminapi.DialUnix(context.Background(), *socketPath)
	if err != nil {
		return err
	}
	defer client.Close() //nolint:errcheck
	result, err := client.Mutate(adminapi.MutationRequest{
		Operation: adminapi.MutationSet,
		Target:    "socks_proxy",
		Value:     raw,
	})
	if err != nil {
		return err
	}
	if !result.OK && result.Error != "" {
		return errors.New(result.Error)
	}
	if *jsonOut {
		return printJSONLine(stdout, result)
	}
	if result.Error != "" {
		_, err = fmt.Fprintf(stdout, "socks proxy requested %s, but it is not running: %s\n", flags.Arg(0), result.Error)
		return err
	}
	action := "stopped"
	if enabled {
		action = "started"
	}
	_, err = fmt.Fprintf(stdout, "socks proxy %s\n", action)
	return err
}

func runTemporaryRuleset(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	jsonOutArg, args := extractJSONOutArg(args)
	flags := flag.NewFlagSet("tmp-ruleset", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socketPath := flags.String("socket", adminapi.DefaultSocketPath, "admin API Unix socket path")
	flags.StringVar(socketPath, "s", adminapi.DefaultSocketPath, "admin API Unix socket path")
	jsonValue := flags.String("json", "", "temporary allow-rules JSON; prefix with @ to read a file")
	interfaces := flags.String("interfaces", "", "comma-separated interface names this temporary ruleset affects")
	jsonOut := flags.Bool("json-out", jsonOutArg, "print compact JSON output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("tmp-ruleset expects no positional arguments, got: %s", strings.Join(flags.Args(), " "))
	}
	if *jsonValue == "" {
		return errors.New("tmp-ruleset requires -json JSON or -json @FILE")
	}
	if *interfaces == "" {
		return errors.New("tmp-ruleset requires -interfaces NAME[,NAME...]")
	}
	raw, err := readJSONArgument(*jsonValue)
	if err != nil {
		return err
	}
	interfaceNames := parseCSV(*interfaces)

	client, err := adminapi.DialUnix(context.Background(), *socketPath)
	if err != nil {
		return err
	}
	defer client.Close() //nolint:errcheck

	result, err := client.Mutate(adminapi.MutationRequest{
		Operation:  adminapi.MutationSet,
		Target:     "tmp_ruleset",
		Interfaces: interfaceNames,
		Value:      raw,
	})
	if err != nil {
		return err
	}
	if !result.OK {
		return errors.New(result.Error)
	}
	if *jsonOut {
		if err := printJSONLine(stdout, result); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(stdout, "temporary ruleset installed for %s; press Ctrl+C, Ctrl+D, or Esc to remove it\n", strings.Join(interfaceNames, ", ")); err != nil {
			return err
		}
	}
	restoreInput, err := rawInputMode(stdin)
	if err != nil {
		return err
	}
	defer restoreInput()

	serverDone := make(chan error, 1)
	go func() {
		for {
			if _, err := client.Receive(); err != nil {
				serverDone <- err
				return
			}
		}
	}()

	inputDone := make(chan error, 1)
	go func() {
		inputDone <- waitForStopInput(stdin)
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	select {
	case err := <-serverDone:
		if adminapi.IsEOF(err) {
			return errors.New("server disconnected")
		}
		return fmt.Errorf("server disconnected: %w", err)
	case err := <-inputDone:
		return err
	case <-signals:
		return nil
	}
}

func runForceRuleset(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	jsonOutArg, args := extractJSONOutArg(args)
	flags := flag.NewFlagSet("force-ruleset", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socketPath := flags.String("socket", adminapi.DefaultSocketPath, "admin API Unix socket path")
	flags.StringVar(socketPath, "s", adminapi.DefaultSocketPath, "admin API Unix socket path")
	ruleset := flags.String("ruleset", "", "ruleset name to force activate")
	flags.StringVar(ruleset, "r", "", "ruleset name to force activate")
	interfaces := flags.String("interfaces", "", "comma-separated interface names this forced ruleset affects")
	jsonOut := flags.Bool("json-out", jsonOutArg, "print compact JSON output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("force-ruleset expects no positional arguments, got: %s", strings.Join(flags.Args(), " "))
	}
	if *ruleset == "" {
		return errors.New("force-ruleset requires -ruleset NAME")
	}
	if *interfaces == "" {
		return errors.New("force-ruleset requires -interfaces NAME[,NAME...]")
	}
	interfaceNames := parseCSV(*interfaces)

	client, err := adminapi.DialUnix(context.Background(), *socketPath)
	if err != nil {
		return err
	}
	defer client.Close() //nolint:errcheck

	result, err := client.Mutate(adminapi.MutationRequest{
		Operation:  adminapi.MutationSet,
		Target:     "force_ruleset",
		Ruleset:    *ruleset,
		Interfaces: interfaceNames,
	})
	if err != nil {
		return err
	}
	if !result.OK {
		return errors.New(result.Error)
	}
	if *jsonOut {
		if err := printJSONLine(stdout, result); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(stdout, "ruleset %q force activated for %s; press Ctrl+C, Ctrl+D, or Esc to release it\n", *ruleset, strings.Join(interfaceNames, ", ")); err != nil {
			return err
		}
	}
	restoreInput, err := rawInputMode(stdin)
	if err != nil {
		return err
	}
	defer restoreInput()

	serverDone := make(chan error, 1)
	go func() {
		for {
			if _, err := client.Receive(); err != nil {
				serverDone <- err
				return
			}
		}
	}()

	inputDone := make(chan error, 1)
	go func() {
		inputDone <- waitForStopInput(stdin)
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	select {
	case err := <-serverDone:
		if adminapi.IsEOF(err) {
			return errors.New("server disconnected")
		}
		return fmt.Errorf("server disconnected: %w", err)
	case err := <-inputDone:
		return err
	case <-signals:
		return nil
	}
}

func rawInputMode(r io.Reader) (func(), error) {
	file, ok := r.(*os.File)
	if !ok {
		return func() {}, nil
	}
	fd := int(file.Fd())
	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		if errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.EINVAL) {
			return func() {}, nil
		}
		return nil, fmt.Errorf("inspect terminal mode: %w", err)
	}

	raw := *termios
	raw.Lflag &^= unix.ICANON | unix.ECHO
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
		return nil, fmt.Errorf("set raw terminal mode: %w", err)
	}
	return func() {
		_ = unix.IoctlSetTermios(fd, unix.TCSETS, termios)
	}, nil
}

func waitForStopInput(r io.Reader) error {
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 && (buf[0] == 0x03 || buf[0] == 0x04 || buf[0] == 0x1b) {
			return nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func runMutation(op adminapi.MutationOperation, args []string, stdout, stderr io.Writer) error {
	req, socketPath, jsonOut, err := mutationRequestFromArgs(op, args, stderr)
	if err != nil {
		return err
	}

	client, err := adminapi.DialUnix(context.Background(), socketPath)
	if err != nil {
		return err
	}
	defer client.Close() //nolint:errcheck

	result, err := client.Mutate(req)
	if err != nil {
		return err
	}
	if !result.OK {
		return errors.New(result.Error)
	}
	if jsonOut {
		return printJSONLine(stdout, result)
	}
	if result.Changed {
		_, err = fmt.Fprintln(stdout, "changed")
	} else {
		_, err = fmt.Fprintln(stdout, "unchanged")
	}
	return err
}

func extractJSONOutArg(args []string) (bool, []string) {
	out := args[:0]
	jsonOut := false
	for _, arg := range args {
		if arg == "--json-out" {
			jsonOut = true
			continue
		}
		out = append(out, arg)
	}
	return jsonOut, out
}

func mutationRequestFromArgs(op adminapi.MutationOperation, args []string, stderr io.Writer) (adminapi.MutationRequest, string, bool, error) {
	jsonOutArg, args := extractJSONOutArg(args)
	flags := flag.NewFlagSet(string(op), flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		_, _ = fmt.Fprint(flags.Output(), mutationUsage(string(op)))
	}
	socketPath := flags.String("socket", adminapi.DefaultSocketPath, "admin API Unix socket path")
	flags.StringVar(socketPath, "s", adminapi.DefaultSocketPath, "admin API Unix socket path")
	target := flags.String("target", "", "mutation target")
	flags.StringVar(target, "t", "", "mutation target")
	ruleset := flags.String("ruleset", "", "ruleset name for ruleset mutations")
	flags.StringVar(ruleset, "r", "", "ruleset name for ruleset mutations")
	jsonValue := flags.String("json", "", "JSON value for boolean, policy, or ruleset add/set operations; prefix with @ to read a file")
	jsonOut := flags.Bool("json-out", jsonOutArg, "print compact JSON output")
	if err := flags.Parse(args); err != nil {
		return adminapi.MutationRequest{}, "", false, err
	}
	if *target == "" {
		return adminapi.MutationRequest{}, "", false, fmt.Errorf("%s requires -target", op)
	}

	req := adminapi.MutationRequest{
		Operation: op,
		Target:    *target,
		Ruleset:   *ruleset,
		Values:    flags.Args(),
	}
	if *jsonValue != "" {
		raw, err := readJSONArgument(*jsonValue)
		if err != nil {
			return adminapi.MutationRequest{}, "", false, err
		}
		req.Value = raw
	}
	if len(req.Value) == 0 && op == adminapi.MutationSet && len(req.Values) == 1 && scalarTarget(*target) {
		raw, err := scalarJSONValue(req.Values[0])
		if err != nil {
			return adminapi.MutationRequest{}, "", false, err
		}
		req.Value = raw
		req.Values = nil
	}
	if err := validateMutationRequest(req, *jsonValue != ""); err != nil {
		return adminapi.MutationRequest{}, "", false, err
	}
	return req, *socketPath, *jsonOut, nil
}

func validateMutationRequest(req adminapi.MutationRequest, hasJSON bool) error {
	if req.Target != "ruleset" {
		return nil
	}
	if req.Ruleset == "" {
		return errors.New("ruleset mutations require -ruleset NAME")
	}
	if len(req.Values) > 0 {
		return fmt.Errorf("%s -target ruleset expects no positional arguments, got: %s", req.Operation, strings.Join(req.Values, " "))
	}
	switch req.Operation {
	case adminapi.MutationAdd, adminapi.MutationSet:
		if !hasJSON {
			return fmt.Errorf("%s -target ruleset requires -json JSON or -json @FILE", req.Operation)
		}
	case adminapi.MutationRemove:
		if hasJSON {
			return errors.New("remove -target ruleset does not accept -json")
		}
	default:
		return fmt.Errorf("unsupported ruleset operation %q", req.Operation)
	}
	return nil
}

func readJSONArgument(value string) (json.RawMessage, error) {
	if strings.HasPrefix(value, "@") {
		path := strings.TrimPrefix(value, "@")
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read JSON value %s: %w", path, err)
		}
		return json.RawMessage(raw), nil
	}
	return json.RawMessage(value), nil
}

func parseCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || seen[part] {
			continue
		}
		seen[part] = true
		out = append(out, part)
	}
	return out
}

func scalarTarget(target string) bool {
	switch target {
	case "base_policy.allow_all", "base_policy.enable_v4", "base_policy.enable_v6",
		"ruleset.disabled", "ruleset.match_all":
		return true
	default:
		return false
	}
}

func scalarJSONValue(value string) (json.RawMessage, error) {
	if value == "true" || value == "false" {
		return json.RawMessage(value), nil
	}
	if _, err := strconv.Atoi(value); err == nil {
		return json.RawMessage(value), nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func runGetConfig(args []string, stdout, stderr io.Writer) error {
	jsonOutArg, args := extractJSONOutArg(args)
	flags := flag.NewFlagSet("get-cfg", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socketPath := flags.String("socket", adminapi.DefaultSocketPath, "admin API Unix socket path")
	flags.StringVar(socketPath, "s", adminapi.DefaultSocketPath, "admin API Unix socket path")
	watch := flags.Bool("watch", false, "subscribe to config, interface, and client events and re-print on updates")
	jsonOut := flags.Bool("json-out", jsonOutArg, "print compact JSON output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("get-cfg expects no positional arguments, got: %s", strings.Join(flags.Args(), " "))
	}

	client, err := adminapi.DialUnix(context.Background(), *socketPath)
	if err != nil {
		return err
	}
	defer client.Close() //nolint:errcheck

	if *watch {
		if err := client.Subscribe(adminapi.EventTypeConfig, adminapi.EventTypeInterfaces, adminapi.EventTypeClients); err != nil {
			return err
		}
	}
	if err := client.RequestConfig(); err != nil {
		return err
	}
	cfg, err := client.WaitForConfig()
	if err != nil {
		return err
	}
	if *jsonOut {
		if !*watch {
			return printJSONLine(stdout, cfg)
		}
		if err := printJSONLine(stdout, configUpdate{Config: cfg}); err != nil {
			return err
		}
		return watchConfigJSON(client, stdout)
	}
	if err := printConfig(stdout, cfg); err != nil {
		return err
	}
	if !*watch {
		return nil
	}
	return watchConfig(client, stdout)
}

type configUpdate struct {
	EventType adminapi.EventType     `json:"event_type,omitempty"`
	Config    adminapi.CurrentConfig `json:"config"`
}

func watchConfig(client *adminapi.Client, stdout io.Writer) error {
	events := make(chan adminapi.EventMessage, 1)
	errs := make(chan error, 1)
	go func() {
		for {
			event, err := client.WaitForEvent()
			if err != nil {
				errs <- err
				return
			}
			events <- event
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	for {
		select {
		case event := <-events:
			if _, err := fmt.Fprintf(stdout, "\nEvent: %s\n\n", event.EventType); err != nil {
				return err
			}
			if err := printConfig(stdout, event.Config); err != nil {
				return err
			}
		case err := <-errs:
			if adminapi.IsEOF(err) {
				return errors.New("server disconnected")
			}
			return err
		case <-signals:
			return nil
		}
	}
}

func watchConfigJSON(client *adminapi.Client, stdout io.Writer) error {
	events := make(chan adminapi.EventMessage, 1)
	errs := make(chan error, 1)
	go func() {
		for {
			event, err := client.WaitForEvent()
			if err != nil {
				errs <- err
				return
			}
			events <- event
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	for {
		select {
		case event := <-events:
			if err := printJSONLine(stdout, configUpdate{EventType: event.EventType, Config: event.Config}); err != nil {
				return err
			}
		case err := <-errs:
			if adminapi.IsEOF(err) {
				return errors.New("server disconnected")
			}
			return err
		case <-signals:
			return nil
		}
	}
}

func printUsage(w io.Writer) error {
	if _, err := fmt.Fprintln(w, "Usage:"); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, "  killswitch-cli get-cfg [-socket PATH] [--watch] [--json-out]\n  killswitch-cli notifications [-socket PATH] [--json-out]\n  killswitch-cli debug-notify [-socket PATH] [-level normal|warn|error] [-header TEXT] -text TEXT [--json-out]\n  killswitch-cli socks-proxy [-socket PATH] start|stop [--json-out]\n  killswitch-cli add [-socket PATH] -target TARGET [-ruleset NAME] [VALUE...|-json JSON|-json @FILE] [--json-out]\n  killswitch-cli remove [-socket PATH] -target TARGET [-ruleset NAME] VALUE... [--json-out]\n  killswitch-cli remove [-socket PATH] -target ruleset -ruleset NAME [--json-out]\n  killswitch-cli set [-socket PATH] -target TARGET [-ruleset NAME] [VALUE...|-json JSON|-json @FILE] [--json-out]\n  killswitch-cli tmp-ruleset [-socket PATH] -interfaces NAME[,NAME...] -json JSON|-json @FILE [--json-out]\n  killswitch-cli force-ruleset [-socket PATH] -interfaces NAME[,NAME...] -ruleset NAME [--json-out]")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, "\n"+availableMutationTargets())
	return err
}

func mutationUsage(cmd string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Usage:\n")
	fmt.Fprintf(&b, "  killswitch-cli %s [-socket PATH] -target TARGET [-ruleset NAME] [VALUE...|-json JSON|-json @FILE] [--json-out]\n", cmd)
	if cmd == "remove" {
		fmt.Fprintf(&b, "  killswitch-cli remove [-socket PATH] -target ruleset -ruleset NAME [--json-out]\n")
	}
	fmt.Fprintf(&b, "\nOptions:\n")
	fmt.Fprintf(&b, "  -socket, -s PATH        admin API Unix socket path (default %s)\n", adminapi.DefaultSocketPath)
	fmt.Fprintf(&b, "  -target, -t TARGET      mutation target\n")
	fmt.Fprintf(&b, "  -ruleset, -r NAME       ruleset name for ruleset mutations\n")
	fmt.Fprintf(&b, "  -json JSON|@FILE        JSON value for boolean, policy, or ruleset add/set operations\n")
	fmt.Fprintf(&b, "  --json-out              print compact JSON output\n")
	fmt.Fprintf(&b, "\n%s\n", availableMutationTargets())
	return b.String()
}

func availableMutationTargets() string {
	return `Available mutation targets:
  interface lists:
    interface_types, interface_names, interface_regexps
    ignored_interface_types, ignored_interface_names, ignored_interface_regexps
  whole policy/ruleset JSON:
    base_policy
    ruleset (requires -ruleset NAME)
  base policy fields:
    base_policy.allow_all, base_policy.enable_v4, base_policy.enable_v6
    base_policy.allowed_marks, base_policy.allowed_ports
    base_policy.allowed_v4_hosts, base_policy.allowed_v6_hosts
    base_policy.allowed_v4_hostports, base_policy.allowed_v6_hostports
  ruleset fields (require -ruleset NAME):
    ruleset.disabled, ruleset.match_all
    ruleset.trigger.interface_types, ruleset.trigger.interface_names
    ruleset.trigger.interface_regexps, ruleset.trigger.ip_addrs
    ruleset.trigger.ssids, ruleset.trigger.bssids, ruleset.trigger.gateway_macs
    ruleset.policy.allow_all, ruleset.policy.enable_v4, ruleset.policy.enable_v6
    ruleset.policy.allowed_marks, ruleset.policy.allowed_ports
    ruleset.policy.allowed_v4_hosts, ruleset.policy.allowed_v6_hosts
    ruleset.policy.allowed_v4_hostports, ruleset.policy.allowed_v6_hostports`
}

func printJSONLine(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func printNotification(w io.Writer, notification adminapi.Notification) error {
	if notification.Header == "" {
		_, err := fmt.Fprintf(w, "[%s] %s\n", notification.Level, notification.Text)
		return err
	}
	_, err := fmt.Fprintf(w, "[%s] %s: %s\n", notification.Level, notification.Header, notification.Text)
	return err
}

func printConfig(w io.Writer, cfg adminapi.CurrentConfig) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	printer := outputPrinter{w: tw}

	printer.println("Admin API")
	printer.printf("  socket:\t%s\n", cfg.AdminAPI.SocketPath)
	printer.println()

	printer.println("SOCKS proxy")
	printer.printf("  enabled:\t%t\n", cfg.SocksProxy.Enabled)
	printer.printf("  running:\t%t\n", cfg.SocksProxy.Running)
	printer.printf("  listen:\t%s:%d\n", cfg.SocksProxy.Host, cfg.SocksProxy.Port)
	printer.printf("  fwmark:\t%s\n", cfg.SocksProxy.FWMark)
	printer.printOptional("  dns server", cfg.SocksProxy.DNSServer)
	printer.printOptional("  last error", cfg.SocksProxy.LastError)
	printer.println()

	printer.println("Interfaces")
	printer.printList("  types", cfg.InterfaceTypes)
	printer.printList("  names", cfg.InterfaceNames)
	printer.printList("  regexps", cfg.InterfaceRegexps)
	printer.printList("  ignored types", cfg.IgnoredInterfaceTypes)
	printer.printList("  ignored names", cfg.IgnoredInterfaceNames)
	printer.printList("  ignored regexps", cfg.IgnoredInterfaceRegexps)
	if len(cfg.Interfaces) == 0 {
		printer.println("  current:\t-")
	} else {
		printer.println("  current:")
		for _, iface := range cfg.Interfaces {
			printer.printf("    %s:\tindex=%d type=%s matched=%t killswitch=%t\n", iface.Name, iface.Index, iface.Type, iface.Matched, iface.Killswitch)
			printer.printList("      addrs", iface.Addrs)
			printer.printOptional("      ssid", iface.SSID)
			printer.printOptional("      bssid", iface.BSSID)
			printer.printList("      gateway MACs", iface.GatewayMACs)
		}
	}
	printer.println()

	printer.println("Base policy")
	printer.printAllowRules(cfg.BasePolicy)
	printer.println()

	printer.println("Effective policy")
	if len(cfg.EffectiveInterfaces) > 0 {
		for _, iface := range cfg.EffectiveInterfaces {
			printer.printf("  %s:\tindex=%d type=%s attached=%t matched=%t\n", iface.Name, iface.Index, iface.Type, iface.Attached, iface.Matched)
			printer.printOptional("    ssid", iface.SSID)
			printer.printOptional("    bssid", iface.BSSID)
			printer.printList("    gateway MACs", iface.GatewayMACs)
			printer.printList("    active rulesets", iface.ActiveRulesets)
			printer.printList("    forced rulesets", iface.ForcedRulesets)
			printer.printList("    temporary rulesets", iface.TemporaryRulesets)
			printer.printAllowRulesWithPrefix("    ", iface.EffectivePolicy)
		}
	} else {
		if cfg.ActiveRuleset == "" {
			printer.println("  active ruleset:\tnone")
		} else {
			printer.printf("  active ruleset:\t%s\n", cfg.ActiveRuleset)
		}
		printer.printAllowRules(cfg.EffectivePolicy)
	}

	if len(cfg.Rulesets) > 0 {
		printer.println()
		printer.println("Rulesets")
		for _, ruleset := range cfg.Rulesets {
			printer.printf("  %s:\tactive=%t disabled=%t match_all=%t\n", ruleset.Name, ruleset.Active, ruleset.Disabled, ruleset.MatchAll)
			printer.printList("    trigger types", ruleset.Trigger.InterfaceTypes)
			printer.printList("    trigger names", ruleset.Trigger.InterfaceNames)
			printer.printList("    trigger regexps", ruleset.Trigger.InterfaceRegexps)
			printer.printList("    trigger IPs", ruleset.Trigger.IPAddrs)
			printer.printList("    trigger SSIDs", ruleset.Trigger.SSIDs)
			printer.printList("    trigger BSSIDs", ruleset.Trigger.BSSIDs)
			printer.printList("    trigger gateway MACs", ruleset.Trigger.GatewayMACs)
			printer.printAllowRulesWithPrefix("    ", ruleset.Policy)
		}
	}

	if len(cfg.TemporaryRulesets) > 0 {
		printer.println()
		printer.println("Temporary rulesets")
		for i, ruleset := range cfg.TemporaryRulesets {
			printer.printf("  #%d:\tclient=%s\n", i+1, ruleset.Client)
			printer.printList("    interfaces", ruleset.Interfaces)
			printer.printAllowRulesWithPrefix("    ", ruleset.Policy)
		}
	}

	if len(cfg.ForceActiveRulesets) > 0 {
		printer.println()
		printer.println("Force-active rulesets")
		for _, ruleset := range cfg.ForceActiveRulesets {
			printer.printf("  %s:\tclients=%s\n", ruleset.Name, strings.Join(ruleset.Clients, ", "))
			printer.printList("    interfaces", ruleset.Interfaces)
		}
	}

	printer.println()
	printer.println("Clients")
	if len(cfg.Clients) == 0 {
		printer.println("  current:\t-")
	} else {
		for _, client := range cfg.Clients {
			printer.printf("  #%d:\tpid=%d uid=%d gid=%d owner=%s\n", client.ID, client.PID, client.UID, client.GID, client.Owner)
			printer.printEventTypes("    events", client.EventTypes)
		}
	}

	if printer.err != nil {
		return printer.err
	}
	return tw.Flush()
}

type outputPrinter struct {
	w   io.Writer
	err error
}

func (p *outputPrinter) println(a ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintln(p.w, a...)
}

func (p *outputPrinter) printf(format string, a ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format, a...)
}

func (p *outputPrinter) printAllowRules(rules adminapi.AllowRules) {
	p.printAllowRulesWithPrefix("  ", rules)
}

func (p *outputPrinter) printAllowRulesWithPrefix(prefix string, rules adminapi.AllowRules) {
	p.printf("%sallow all:\t%t\n", prefix, rules.AllowAll)
	p.printf("%senable v4:\t%t\n", prefix, rules.EnableV4)
	p.printf("%senable v6:\t%t\n", prefix, rules.EnableV6)
	p.printList(prefix+"allowed marks", rules.AllowedMarks)
	p.printList(prefix+"allowed ports", rules.AllowedPorts)
	p.printList(prefix+"allowed v4 hosts", rules.AllowedV4Hosts)
	p.printList(prefix+"allowed v6 hosts", rules.AllowedV6Hosts)
	p.printList(prefix+"allowed v4 hostports", rules.AllowedV4Pairs)
	p.printList(prefix+"allowed v6 hostports", rules.AllowedV6Pairs)
}

func (p *outputPrinter) printList(label string, values []string) {
	if len(values) == 0 {
		p.printf("%s:\t-\n", label)
		return
	}
	p.printf("%s:\t%s\n", label, strings.Join(values, ", "))
}

func (p *outputPrinter) printOptional(label, value string) {
	if value == "" {
		p.printf("%s:\t-\n", label)
		return
	}
	p.printf("%s:\t%s\n", label, value)
}

func (p *outputPrinter) printEventTypes(label string, values []adminapi.EventType) {
	if len(values) == 0 {
		p.printf("%s:\t-\n", label)
		return
	}
	text := make([]string, 0, len(values))
	for _, value := range values {
		text = append(text, string(value))
	}
	p.printf("%s:\t%s\n", label, strings.Join(text, ", "))
}
