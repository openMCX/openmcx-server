#!/usr/bin/env bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# gofmt the given Go files, then vet and build the services module (and optionally run its tests),
# in the openmcx-lint image: the check after editing Go files of a large refactoring.
#   tools/refactor/check-go.sh [--test] FILE...     (paths relative to the repository root)
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
test=0; [ "${1:-}" = --test ] && { test=1; shift; }
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e GOCACHE=/gopath/cache -e GOPATH=/gopath -e GOFLAGS=-mod=vendor \
  -v mcxadmin-gopath:/gopath -v "$PWD:/src" -w /src/services openmcx-lint:0.1 bash -c '
test=$1; shift
files=(); for file in "$@"; do files+=("/src/$file"); done
[ ${#files[@]} -eq 0 ] || gofmt -w "${files[@]}"
go vet ./... || exit 1
go build ./... || exit 1
[ "$test" = 0 ] || go test ./... -count=1 2>&1 | tail -4
echo "Go: OK"
' check "$test" "$@"
