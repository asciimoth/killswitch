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
	case "-h", "--help", "help":
		return printUsage(stdout)
	default:
		if err := printUsage(stderr); err != nil {
			return err
		}
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func runTemporaryRuleset(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("tmp-ruleset", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socketPath := flags.String("socket", adminapi.DefaultSocketPath, "admin API Unix socket path")
	flags.StringVar(socketPath, "s", adminapi.DefaultSocketPath, "admin API Unix socket path")
	jsonValue := flags.String("json", "", "temporary allow-rules JSON; prefix with @ to read a file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("tmp-ruleset expects no positional arguments, got: %s", strings.Join(flags.Args(), " "))
	}
	if *jsonValue == "" {
		return errors.New("tmp-ruleset requires -json JSON or -json @FILE")
	}
	raw, err := readJSONArgument(*jsonValue)
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
		Target:    "tmp_ruleset",
		Value:     raw,
	})
	if err != nil {
		return err
	}
	if !result.OK {
		return errors.New(result.Error)
	}
	if _, err := fmt.Fprintln(stdout, "temporary ruleset installed; press Ctrl+C, Ctrl+D, or Esc to remove it"); err != nil {
		return err
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
	flags := flag.NewFlagSet(string(op), flag.ContinueOnError)
	flags.SetOutput(stderr)
	socketPath := flags.String("socket", adminapi.DefaultSocketPath, "admin API Unix socket path")
	flags.StringVar(socketPath, "s", adminapi.DefaultSocketPath, "admin API Unix socket path")
	target := flags.String("target", "", "mutation target")
	flags.StringVar(target, "t", "", "mutation target")
	ruleset := flags.String("ruleset", "", "ruleset name for ruleset mutations")
	flags.StringVar(ruleset, "r", "", "ruleset name for ruleset mutations")
	jsonValue := flags.String("json", "", "JSON value for boolean, policy, or ruleset set operations; prefix with @ to read a file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *target == "" {
		return fmt.Errorf("%s requires -target", op)
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
			return err
		}
		req.Value = raw
	}
	if len(req.Value) == 0 && op == adminapi.MutationSet && len(req.Values) == 1 && scalarTarget(*target) {
		raw, err := scalarJSONValue(req.Values[0])
		if err != nil {
			return err
		}
		req.Value = raw
		req.Values = nil
	}

	client, err := adminapi.DialUnix(context.Background(), *socketPath)
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
	if result.Changed {
		_, err = fmt.Fprintln(stdout, "changed")
	} else {
		_, err = fmt.Fprintln(stdout, "unchanged")
	}
	return err
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

func scalarTarget(target string) bool {
	switch target {
	case "base_policy.allow_all", "base_policy.enable_v4", "base_policy.enable_v6",
		"ruleset.match_all", "ruleset.priority":
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
	flags := flag.NewFlagSet("get-cfg", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socketPath := flags.String("socket", adminapi.DefaultSocketPath, "admin API Unix socket path")
	flags.StringVar(socketPath, "s", adminapi.DefaultSocketPath, "admin API Unix socket path")
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

	if err := client.RequestConfig(); err != nil {
		return err
	}
	cfg, err := client.WaitForConfig()
	if err != nil {
		return err
	}
	return printConfig(stdout, cfg)
}

func printUsage(w io.Writer) error {
	if _, err := fmt.Fprintln(w, "Usage:"); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, "  killswitch-cli get-cfg [-socket PATH]\n  killswitch-cli add [-socket PATH] -target TARGET [-ruleset NAME] VALUE...\n  killswitch-cli remove [-socket PATH] -target TARGET [-ruleset NAME] VALUE...\n  killswitch-cli set [-socket PATH] -target TARGET [-ruleset NAME] [VALUE...|-json JSON|-json @FILE]\n  killswitch-cli tmp-ruleset [-socket PATH] -json JSON|-json @FILE")
	return err
}

func printConfig(w io.Writer, cfg adminapi.CurrentConfig) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	printer := outputPrinter{w: tw}

	printer.println("Admin API")
	printer.printf("  socket:\t%s\n", cfg.AdminAPI.SocketPath)
	printer.println()

	printer.println("Interfaces")
	printer.printList("  types", cfg.InterfaceTypes)
	printer.printList("  names", cfg.InterfaceNames)
	printer.printList("  regexps", cfg.InterfaceRegexps)
	printer.printList("  ignored types", cfg.IgnoredInterfaceTypes)
	printer.printList("  ignored names", cfg.IgnoredInterfaceNames)
	printer.printList("  ignored regexps", cfg.IgnoredInterfaceRegexps)
	printer.println()

	printer.println("Base policy")
	printer.printAllowRules(cfg.BasePolicy)
	printer.println()

	printer.println("Effective policy")
	if cfg.ActiveRuleset == "" {
		printer.println("  active ruleset:\tnone")
	} else {
		printer.printf("  active ruleset:\t%s\n", cfg.ActiveRuleset)
	}
	printer.printAllowRules(cfg.EffectivePolicy)

	if len(cfg.Rulesets) > 0 {
		printer.println()
		printer.println("Rulesets")
		for _, ruleset := range cfg.Rulesets {
			printer.printf("  %s:\tactive=%t priority=%d match_all=%t\n", ruleset.Name, ruleset.Active, ruleset.Priority, ruleset.MatchAll)
			printer.printList("    trigger types", ruleset.Trigger.InterfaceTypes)
			printer.printList("    trigger names", ruleset.Trigger.InterfaceNames)
			printer.printList("    trigger regexps", ruleset.Trigger.InterfaceRegexps)
			printer.printList("    trigger IPs", ruleset.Trigger.IPAddrs)
			printer.printAllowRulesWithPrefix("    ", ruleset.Policy)
		}
	}

	if len(cfg.TemporaryRulesets) > 0 {
		printer.println()
		printer.println("Temporary rulesets")
		for i, ruleset := range cfg.TemporaryRulesets {
			printer.printf("  #%d:\tclient=%s\n", i+1, ruleset.Client)
			printer.printAllowRulesWithPrefix("    ", ruleset.Policy)
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
