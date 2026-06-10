set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load := true

generate:
  go generate ./...

test:
  go test ./... -count=1

