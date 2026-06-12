# killswitch
`killswitch` is a Linux eBPF network kill switch. The system daemon attaches an
egress program to selected interfaces, keeps per-interface policy,
and drops traffic routed to this interfaces unless the current policy
explicitly allows it (it works nice with [pmark](https://github.com/asciimoth/p-mark) btw).

The project includes:
- `killswitch`: system daemon that owns interface monitoring, eBPF attachment,
  policy evaluation, the admin API, and the optional local SOCKS proxy.
- `killswitch-user`: desktop-session helper for notifications, tray controls,
  network checks, and captive portal handling.
- `killswitch-cli`: command line client killswitch daemon.

> [!CAUTION]
> killswitch is an __experimental__ and __unstable__ software that work under 
> high privileges while havent being audited yet.
> __Do not use in production.__  

## Features
- Fail-closed IPv4 and IPv6 egress filtering.
- Interface selection by type, exact name, and regular expression.
- Per-interface effective policies.
- Global allow rules for fwmarks, ports, destination hosts, and host+port pairs.
- Named rulesets activated by interface, address, Wi-Fi, and gateway triggers.
- Temporary connection-owned rulesets for application integrations.
- Forced ruleset activation for interactive or supervised workflows.
- Optional local SOCKS proxy whose fwmark is automatically allowed.
- Unix-socket admin API with peer credential based authorization.
- Desktop notifications, tray integration, and networks login pages handling.

## Installation
### Nix
Build or run directly from the flake:
```sh
nix build github:asciimoth/killswitch#killswitch
nix profile add github:asciimoth/killswitch#killswitch
```

You can also use system service:
```nix
imports = [ inputs.killswitch.nixosModules.killswitch ];

environment.systemPackages = [
  inputs.killswitch.packages.${pkgs.system}.killswitch
];

services.killswitch = {
  enable = true;
  settings = {
    interface_types = [ "device" ];
    interface_regexps = [ "^(en|wl|ww)" ];

    allow_all = false;
    enable_v4 = true;
    enable_v6 = true;
    # allowed_ports = [ "udp/53" "tcp/53" ];

    socks_proxy = {
      enabled = true;
      port =  1080;
      fwmark = "0xeb9f0001";
      dns_server = "8.8.8.8";
      protected = {
        usernames = [ "root" "myuser" ];
      };
    };
  };
};
```

### Deb, and rpm-based systems
Packages are published to [my deb/rpm repository](https://repo.moth.contact):

Setup it for your sytstem via script (or manually):
```sh
curl https://repo.moth.contact/setup.sh | bash
```

Then install with your system package manager:
```sh
sudo apt install killswitch
# or
sudo dnf install killswitch
# or
sudo yum install killswitch
```

### GitHub Releases
Release archives and package artifacts are published on the
[GitHub releases page](https://github.com/asciimoth/killswitch/releases).

### Arch
[AUR](https://aur.archlinux.org/packages/killswitch-bin) is available

## Daemon Setup
By default, the daemon reads `/etc/killswitch/killswitch.json`. The config is a
single JSON object; unknown fields are rejected.

Example:
```json
{
  "interface_types": ["device"],
  "interface_names": ["eth0", "wlan0"],
  "interface_regexps": ["^(en|wl|ww)"],
  "ignored_interface_types": ["bridge"],
  "ignored_interface_names": ["docker0"],
  "ignored_interface_regexps": ["^(veth|br-)"],
  "admin_api": {
    "socket_path": "/run/killswitch/admin.sock",
    "auth": {
      "groupnames": ["killswitch"]
    }
  },
  "socks_proxy": {
    "enabled": true,
    "port": 1080,
    "fwmark": "0xeb9f0001",
    "dns_server": "8.8.8.8",
    "protected": {
      "usernames": ["root", "alice"]
    }
  },
  "rulesets": {
    "wireguard-up": {
      "disabled": false,
      "match": "or",
      "trigger": {
        "interface_names": ["wg0"],
        "ip_addrs": ["10.64.0.2"]
      },
      "enable_v4": true,
      "enable_v6": true,
      "allowed_v4_hostports": ["udp/198.51.100.10:51820"]
    }
  },
  "allow_all": false,
  "enable_v4": true,
  "enable_v6": true,
  "allowed_marks": ["0x42"],
  "allowed_ports": [],
  "allowed_v4_hosts": [],
  "allowed_v6_hosts": [],
  "allowed_v4_hostports": ["udp/198.51.100.10:51820"],
  "allowed_v6_hostports": []
}
```

### Interface Filtering
At least one of these include selectors is required:
- `interface_types`
- `interface_names`
- `interface_regexps`

The matching ignore selectors are applied after includes:
- `ignored_interface_types`
- `ignored_interface_names`
- `ignored_interface_regexps`

Ignored interfaces are not managed by the daemon. The loopback interface `lo` is
always ignored.

### Global Policy
The top-level policy is the base policy for every selected interface:
- `allow_all`: pass all packets before normal packet parsing. This should be a
  temporary recovery or debugging setting.
- `enable_v4`: enable IPv4 traffic evaluation. When false, routable IPv4 traffic
  is dropped except built-in bootstrap traffic.
- `enable_v6`: enable IPv6 traffic evaluation. When false, routable IPv6 traffic
  is dropped except built-in bootstrap traffic.
- `allowed_marks`: allow packets with matching fwmarks, for example `"0x42"` or
  `"100"`.
- `allowed_ports`: allow TCP or UDP destination ports on any host, for example
  `"tcp/443"` or `"udp/53"`.
- `allowed_v4_hosts`, `allowed_v6_hosts`: allow destination hosts regardless of
  port.
- `allowed_v4_hostports`, `allowed_v6_hostports`: allow protocol, destination
  host, and destination port tuples, for example `"udp/198.51.100.10:51820"` or
  `"tcp/[2001:db8::10]:443"`.

Prefer host+port rules for fixed endpoints. `allowed_ports` usually is too
broad because it permits that destination port on every host.

The eBPF program allows ARP, DHCPv4, DHCPv6, and ICMPv6 Neighbor Discovery
bootstrap traffic separately from these allow rules.

### Rulesets
`rulesets` is an object keyed by ruleset name. A ruleset contains:
- `disabled`: ignore the ruleset without deleting it.
- `match`: `"or"` or `"and"`. `"or"` activates when any trigger predicate
  matches. `"and"` requires every configured trigger group to match. The API also
  exposes this as `match_all`.
- `trigger`: activation predicates.
- Policy fields using the same names as the global policy.

Supported trigger fields:
- `interface_types`
- `interface_names`
- `interface_regexps`
- `ip_addrs`
- `ssids`
- `bssids`
- `gateway_macs`

Rulesets activate independently per interface. For each selected interface, the
daemon starts with the global policy and merges every enabled named ruleset whose
trigger matches that interface. Disabled rulesets are ignored.

### SOCKS Proxy
The daemon can run a local SOCKS proxy on `127.0.0.1`. It is controlled by the
`socks_proxy` config block and can also be started or stopped through
`killswitch-cli`.

- `enabled`: start the proxy with the daemon.
- `port`: local listen port. The default is `1080`.
- `fwmark`: mark applied to outbound proxy traffic. The configured mark is
  automatically merged into `allowed_marks` while the proxy is running.
- `dns_server`: optional DNS server used by proxied DNS handling.
- `protected.uids`, `protected.gids`, `protected.usernames`: limit which local
  users can connect to the proxy.

Per-user proxy access is a convenience boundary, not bulletproof protection. The
listener checks the owner of incoming local connections on a best-effort basis,
and that check can be subject to race conditions.

### Admin API
The admin API is enabled by default. It listens on a Unix socket, defaulting to
`/run/killswitch/admin.sock`.

Config fields:
- `admin_api.socket_path`: absolute path to the Unix socket.
- `admin_api.debug`: enables debug notification injection for testing clients.
- `admin_api.auth.uids`
- `admin_api.auth.gids`
- `admin_api.auth.usernames`
- `admin_api.auth.groupnames`

If no auth rules are configured, the daemon allows members of the `killswitch`
group. The API uses peer credentials from the Unix socket connection.

## Desktop Integration
`killswitch-user` should run inside the user's graphical session. It connects to
the daemon admin API and handles user-facing notifications, tray state, and
network checks.

By default, it uses:
```text
$XDG_CONFIG_HOME/killswitch/killswitch-user.json
```

or:
```text
~/.config/killswitch/killswitch-user.json
```

If your session starts `killswitch-user` before the desktop bar or D-Bus services
are ready, add a startup delay:
```sh
killswitch-user --delay 10s
```

Example:
```json
{
  "socket_path": "/run/killswitch/admin.sock",
  "notify_interface_changes": true,
  "notify_global_allow_all": true,
  "tray_enabled": true,
  "network_check": {
    "period": "300s",
    "url": "http://connectivity-check.ubuntu.com/",
    "status": 204,
    "header": "online",
    "notify": true,
    "captive_portal": {
      "cmd": [
        "chromium",
        "--proxy-server={{.ProxyAddr}}",
        "--user-data-dir={{.Tmp}}",
        "--no-first-run",
        "--password-store=basic",
        "{{.Portal}}"
      ]
    }
  }
}
```

Config fields:
- `socket_path`: admin API socket path.
- `notify_interface_changes`: show notifications when managed interfaces change.
- `notify_global_allow_all`: show notifications when the global `allow_all`
  state changes.
- `tray_enabled`: enable the system tray UI.
- `network_check`: enable periodic connectivity checks when `url` is set.

Network check fields:

- `period`: interval such as `"300s"`.
- `url`: HTTP endpoint to check.
- `status`: expected HTTP status code.
- `text`: optional expected response text.
- `header`: optional expected response header.
- `timeout`: optional request timeout.
- `notify`: show notifications for network check state changes.
- `captive_portal`: command launched when the network appears to require login.

The captive portal command supports template values such as `{{.Portal}}`,
`{{.ProxyAddr}}`, and `{{.Tmp}}`. Chromium is recommended for captive portal
flows because it accepts a SOCKS proxy URL through command line arguments.

## CLI Usage
`killswitch-cli` talks to the daemon admin API. Every subcommand accepts
`-socket PATH` or `-s PATH` when the daemon socket is not the default.

Inspect current daemon state:
```sh
killswitch-cli get-cfg
killswitch-cli get-cfg --watch
killswitch-cli get-cfg --json-out
```

Watch notifications:
```sh
killswitch-cli notifications
killswitch-cli notifications --json-out
```

Start or stop the daemon SOCKS proxy:
```sh
killswitch-cli socks-proxy start
killswitch-cli socks-proxy stop
```

Mutate global policy:
```sh
killswitch-cli set -target base_policy.enable_v4 true
killswitch-cli set -target base_policy.allow_all false
killswitch-cli add -target base_policy.allowed_v4_hostports udp/198.51.100.10:51820
killswitch-cli remove -target base_policy.allowed_marks 0x42
```

Add, change, or remove a named ruleset:
```sh
killswitch-cli add -target ruleset -ruleset wireguard-up -json '{"trigger":{"interface_names":["wg0"]},"policy":{"enable_v4":true,"allowed_v4_hostports":["udp/198.51.100.10:51820"]}}'
killswitch-cli set -target ruleset.disabled -ruleset wireguard-up true
killswitch-cli remove -target ruleset -ruleset wireguard-up
```

Install a temporary ruleset and keep it alive until Ctrl+C, Ctrl+D, Esc, or
server disconnect:
```sh
killswitch-cli tmp-ruleset -interfaces wg0 -json '{"enable_v4":true,"allowed_v4_hostports":["udp/198.51.100.10:51820"]}'
```

Force a named ruleset active for selected interfaces for the lifetime of the CLI
connection:
```sh
killswitch-cli force-ruleset -interfaces wg0 -ruleset wireguard-up
```

Temporary and forced rulesets are connection-scoped. They are removed
automatically when the owning client disconnects.

## Application Integration
Applications should treat killswitch bypass as an explicit user choice. Keep it
disabled by default and enable it only after the user has intentionally opted in.

Recommended strategies:
- Use owned temporary rulesets for short-lived access. A temporary ruleset is
  tied to the admin API client connection and is automatically removed when the
  app exits, crashes, or disconnects.
- Prefer endpoint whitelists when the app talks to known addresses. Add
  host+port rules only for the required protocol, address, and port.
- Use the fwmark strategy when the app able to maek all of its traffic.
  Use a temporal client owned rule with `allowed_marks`.

## TODO
- [ ] Privileges drop after startup in killswitch demon?
- [ ] Security audit
- [ ] killswitch-cli shell autocompletions
- [ ] Setup examples with popular VPN clients
    - [ ] Tailscale?
    - [ ] Amnesia
- [ ] Allow multiple urls to check network connectivity

## Licenses
This repository is dual licensed under GPL or MIT; see
[LICENSE-GPL](./LICENSE-GPL)
and
[LICENSE-MIT](./LICENSE-MIT).

Note: the Go bindings embed precompiled eBPF object blobs generated by `bpf2go`
(`cmd/killswitch/killswitch_bpf*.o`).
Those blobs are built from the open-source0
[killswitch.c](./cmd/killswitch/killswitch.c) which
declare `Dual MIT/GPL` for the kernel verifier.  
You can regenerate them with:
```sh
go generate ./...
```
