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

cli-help: build
  ./killswitch-cli --help

tmp-ruleset: build
  ./killswitch-cli tmp-ruleset -interfaces wg0 -json '{"enable_v4":true,"allowed_v4_hostports":["udp/198.51.100.10:51820"]}'

allow-all: build
  ./killswitch-cli set -target base_policy.allow_all true

force-ruleset: build
  ./killswitch-cli force-ruleset -interfaces enp86s0u1u1 -ruleset wireguard-up

test:
  go test ./... -count=1

release-check-env:
	@missing=0; \
	for name in GITHUB_TOKEN GPG_FINGERPRINT PACKAGE_MAINTAINER AUR_KEY MYREPO; do \
		if [ -z "${!name:-}" ]; then \
			echo "missing required environment variable: ${name}" >&2; \
			missing=1; \
		fi; \
	done; \
	if [ "${missing}" -ne 0 ]; then \
		exit 1; \
	fi

release-check: release-check-env
	goreleaser check

release-snapshot: release-check-env
	SSH_BIN="${SSH_BIN:-$(command -v ssh)}" goreleaser release --clean --snapshot --skip=publish --skip=validate

release: release-check-env
	SSH_BIN="${SSH_BIN:-$(command -v ssh)}" goreleaser release --clean --skip=validate
	"$MYREPO/maintain" save feat "add pmark $(git describe --tags --abbrev=0)"

