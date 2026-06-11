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
  sudo ./killswitch ./killswitch.example.json

get-cfg: build
  ./killswitch-cli get-cfg

cli-add: build
  ./killswitch-cli add -target base_policy.allowed_ports tcp/443

test:
  go test ./... -count=1
