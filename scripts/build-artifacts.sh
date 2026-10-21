#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags='-s -w' \
    -o "$build_dir/familychat-push-gateway" ./cmd/familychat-push-gateway
  tar -czf "dist/familychat-push-gateway-linux-$arch.tar.gz" -C "$build_dir" familychat-push-gateway
done
tar -czf dist/familychat-push-gateway-deployment.tar.gz README.md compose.yaml .env.example .dockerignore .gitignore Dockerfile go.mod cmd internal
