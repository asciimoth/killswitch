set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load := true

generate:
  go generate ./...

build: generate
  go build -o killswitch ./cmd/killswitch
  go build -o killswitch-user ./cmd/killswitch-user
  go build -o killswitch-cli ./cmd/killswitch-cli

daemon: build
  sudo ./killswitch ./killswitch.example.json

user: build
  ./killswitch-user ./killswitch-user.example.json

get-cfg: build
  ./killswitch-cli get-cfg --watch

notifications: build
  ./killswitch-cli notifications

debug-notify level="error" text="debug notification" header="Debug": build
  ./killswitch-cli debug-notify -level '{{level}}' -header '{{header}}' -text '{{text}}'

disable: build
  ./killswitch-cli set -target ruleset.disabled -ruleset wireguard-up true

cli-add: build
  ./killswitch-cli add -target base_policy.allowed_ports tcp/443

tmp-ruleset: build
  ./killswitch-cli tmp-ruleset -interfaces wg0 -json '{"enable_v4":true,"allowed_v4_hostports":["udp/198.51.100.10:51820"]}'

allow-all: build
  ./killswitch-cli set -target base_policy.allow_all true

force-ruleset: build
  ./killswitch-cli force-ruleset -interfaces enp86s0u1u1 -ruleset wireguard-up

test:
  go test ./... -count=1
