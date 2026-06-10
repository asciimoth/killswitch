set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load := true

generate:
  go generate ./...

build: generate
  go build -o killswitch ./cmd/killswitch
  go build -o killswitch-user ./cmd/killswitch-user
  go build -o killswitch-cli ./cmd/killswitch-cli
  go build -o killswitch-gui ./cmd/killswitch-gui

daemon: build
  printf '%s\n' \
    '{' \
    '  "interface_types": ["device"],' \
    '  "interface_names": ["eth0", "wlan0"],' \
    '  "interface_regexps": ["^(en|wl|ww)"],' \
    '  "allow_all": false,' \
    '  "enable_v4": true,' \
    '  "enable_v6": true,' \
    '  "allowed_marks": ["0xeb9f0001"],' \
    '  "allowed_ports": ["tcp/53", "udp/53"],' \
    '  "allowed_v4_hosts": [],' \
    '  "allowed_v6_hosts": [],' \
    '  "allowed_v4_hostports": [' \
    '  ],' \
    '  "allowed_v6_hostports": [' \
    '  ]' \
    '}' \
    | sudo ./killswitch -

test:
  go test ./... -count=1
