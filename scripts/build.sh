#!/bin/sh
# Build both peers from one revision; no services are started.
set -eu
cd "$(dirname "$0")/.."
revision=$(git rev-parse HEAD)
if test -n "$(git status --porcelain --untracked-files=normal)"; then revision="${revision}+dirty"; fi
mkdir -p dist
for role in server agent; do
  go build -ldflags "-X github.com/shafreeck/burrow/internal/diagnostic.Revision=$revision" -o "dist/burrow-$role" "./cmd/burrow-$role"
done
printf 'Built server and agent at %s\n' "$revision"
