//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/asciimoth/killswitch/internal/policy"
)

func loadOptions(configPath string, stdin io.Reader) (options, error) {
	var reader io.Reader
	if configPath == "-" {
		log.Print("Loading config from stdin")
		reader = stdin
	} else {
		log.Printf("Loading config from %s", configPath)
		file, err := os.Open(configPath)
		if err != nil {
			return options{}, fmt.Errorf("open config %q: %w", configPath, err)
		}
		defer file.Close() //nolint:errcheck
		reader = file
	}

	var cfg configFile
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return options{}, fmt.Errorf("decode config: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return options{}, errors.New("decode config: multiple JSON values")
	}

	return configToOptions(cfg)
}

func configToOptions(cfg configFile) (options, error) {
	opts := options{
		InterfaceTypes:          cfg.InterfaceTypes,
		InterfaceNames:          cfg.InterfaceNames,
		InterfaceRegexps:        cfg.InterfaceRegexps,
		IgnoredInterfaceTypes:   cfg.IgnoredInterfaceTypes,
		IgnoredInterfaceNames:   cfg.IgnoredInterfaceNames,
		IgnoredInterfaceRegexps: cfg.IgnoredInterfaceRegexps,
		AdminAPI:                adminAPIOptionsFromConfig(cfg.AdminAPI),
		SocksProxy:              socksProxyOptionsFromConfig(cfg.SocksProxy),
		allowRules: allowRules{
			AllowAll: cfg.AllowAll,
			EnableV4: cfg.EnableV4,
			EnableV6: cfg.EnableV6,
		},
	}
	if len(opts.InterfaceTypes) == 0 && len(opts.InterfaceNames) == 0 && len(opts.InterfaceRegexps) == 0 {
		return options{}, errors.New("at least one interface_types, interface_names, or interface_regexps entry is required")
	}
	if err := validateAdminAPIOptions(opts.AdminAPI); err != nil {
		return options{}, err
	}
	if err := validateSocksProxyOptions(opts.SocksProxy); err != nil {
		return options{}, err
	}

	for _, pattern := range opts.InterfaceRegexps {
		if _, err := regexp.Compile(pattern); err != nil {
			return options{}, fmt.Errorf("compile interface regexp %q: %w", pattern, err)
		}
	}
	for _, pattern := range opts.IgnoredInterfaceRegexps {
		if _, err := regexp.Compile(pattern); err != nil {
			return options{}, fmt.Errorf("compile ignored interface regexp %q: %w", pattern, err)
		}
	}
	var err error
	if opts.AllowedMarks, err = policy.ParseAllowedMarks(cfg.AllowedMarks); err != nil {
		return options{}, err
	}
	if opts.AllowedPorts, err = allowedPortKeys(cfg.AllowedPorts); err != nil {
		return options{}, err
	}
	if opts.AllowedV4Hosts, err = allowedV4HostKeys(cfg.AllowedV4Hosts); err != nil {
		return options{}, err
	}
	if opts.AllowedV6Hosts, err = allowedV6HostKeys(cfg.AllowedV6Hosts); err != nil {
		return options{}, err
	}
	if opts.AllowedV4Pairs, err = allowedV4HostportKeys(cfg.AllowedV4Pairs); err != nil {
		return options{}, err
	}
	if opts.AllowedV6Pairs, err = allowedV6HostportKeys(cfg.AllowedV6Pairs); err != nil {
		return options{}, err
	}
	if opts.Rulesets, err = rulesetsFromConfig(cfg.Rulesets); err != nil {
		return options{}, err
	}

	return opts, nil
}

func rulesetsFromConfig(configs map[string]rulesetConfig) ([]ruleset, error) {
	rulesets := make([]ruleset, 0, len(configs))
	names := make([]string, 0, len(configs))
	for name := range configs {
		if name == "" {
			return nil, errors.New("ruleset name is required")
		}
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		cfg := configs[name]

		matchAll, err := parseRulesetMatch(cfg)
		if err != nil {
			return nil, fmt.Errorf("ruleset %q: %w", name, err)
		}

		trigger, err := triggerFromConfig(cfg.Trigger)
		if err != nil {
			return nil, fmt.Errorf("ruleset %q: %w", name, err)
		}

		rules, err := allowRulesFromConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("ruleset %q: %w", name, err)
		}

		rulesets = append(rulesets, ruleset{
			Name:       name,
			Disabled:   cfg.Disabled,
			MatchAll:   matchAll,
			Trigger:    trigger,
			allowRules: rules,
		})
	}
	return rulesets, nil
}

func parseRulesetMatch(cfg rulesetConfig) (bool, error) {
	switch strings.ToLower(cfg.Match) {
	case "", "or":
		return cfg.MatchAll, nil
	case "and":
		return true, nil
	default:
		return false, fmt.Errorf("match must be \"and\" or \"or\", got %q", cfg.Match)
	}
}

func triggerFromConfig(cfg triggerConfig) (rulesetTrigger, error) {
	trigger := rulesetTrigger{
		InterfaceTypes:   cfg.InterfaceTypes,
		InterfaceNames:   cfg.InterfaceNames,
		InterfaceRegexps: cfg.InterfaceRegexps,
		SSIDs:            cfg.SSIDs,
	}
	for _, pattern := range trigger.InterfaceRegexps {
		if _, err := regexp.Compile(pattern); err != nil {
			return rulesetTrigger{}, fmt.Errorf("compile trigger interface regexp %q: %w", pattern, err)
		}
	}
	for _, value := range cfg.IPAddrs {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return rulesetTrigger{}, fmt.Errorf("parse trigger ip_addrs %q: %w", value, err)
		}
		trigger.IPAddrs = append(trigger.IPAddrs, addr.Unmap())
	}
	var err error
	if trigger.BSSIDs, err = normalizeMACList("trigger bssids", cfg.BSSIDs); err != nil {
		return rulesetTrigger{}, err
	}
	if trigger.GatewayMACs, err = normalizeMACList("trigger gateway_macs", cfg.GatewayMACs); err != nil {
		return rulesetTrigger{}, err
	}
	if !rulesetTriggerHasPredicates(trigger) {
		return rulesetTrigger{}, errors.New("trigger requires at least one interface_types, interface_names, interface_regexps, ip_addrs, ssids, bssids, or gateway_macs entry")
	}
	return trigger, nil
}

func allowRulesFromConfig(cfg rulesetConfig) (allowRules, error) {
	rules := allowRules{
		AllowAll: cfg.AllowAll,
		EnableV4: cfg.EnableV4,
		EnableV6: cfg.EnableV6,
	}
	var err error
	if rules.AllowedMarks, err = policy.ParseAllowedMarks(cfg.AllowedMarks); err != nil {
		return allowRules{}, err
	}
	if rules.AllowedPorts, err = allowedPortKeys(cfg.AllowedPorts); err != nil {
		return allowRules{}, err
	}
	if rules.AllowedV4Hosts, err = allowedV4HostKeys(cfg.AllowedV4Hosts); err != nil {
		return allowRules{}, err
	}
	if rules.AllowedV6Hosts, err = allowedV6HostKeys(cfg.AllowedV6Hosts); err != nil {
		return allowRules{}, err
	}
	if rules.AllowedV4Pairs, err = allowedV4HostportKeys(cfg.AllowedV4Pairs); err != nil {
		return allowRules{}, err
	}
	if rules.AllowedV6Pairs, err = allowedV6HostportKeys(cfg.AllowedV6Pairs); err != nil {
		return allowRules{}, err
	}
	return rules, nil
}
