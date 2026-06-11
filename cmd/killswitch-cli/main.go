package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/asciimoth/killswitch/internal/adminapi"
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
	case "-h", "--help", "help":
		return printUsage(stdout)
	default:
		if err := printUsage(stderr); err != nil {
			return err
		}
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
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
	_, err := fmt.Fprintln(w, "  killswitch-cli get-cfg [-socket PATH]")
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
