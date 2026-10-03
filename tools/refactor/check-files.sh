#!/usr/bin/env bash
# Format the given C++ files (clang-format 23) and compile each alone with the build's flags
# (syntax only), in the openmcx-lint image: the check after editing a few files of a large
# refactoring, without building everything.
#   tools/refactor/check-files.sh FILE...            in mcxserver
#   MCXSERVER=/path tools/refactor/check-files.sh FILE...   in mcxclient (the sibling checkout it links)
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
[ $# -gt 0 ] || { echo "usage: check-files.sh FILE..." >&2; exit 2; }
server=${MCXSERVER:-}
mounts=(-v "$PWD:/src")
cmake_extra=()
if [ -n "$server" ]; then mounts+=(-v "$(cd "$server" && pwd):/mcxserver:ro"); cmake_extra=(-DMCXSERVER_DIR=/mcxserver); fi
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp "${mounts[@]}" -w /src openmcx-lint:0.1 bash -c '
set -uo pipefail
build=/tmp/check-build
cmake -S . -B $build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON '"${cmake_extra[*]:-}"' >/dev/null 2>&1 || { echo "cmake failed"; exit 1; }
clang-format -i "$@"
status=0
for file in "$@"; do
  case "$file" in *.hpp) continue ;; esac
  command=$(python3 -c "
import json,sys,shlex
entries=json.load(open(\"$build/compile_commands.json\"))
path=\"/src/$file\"
for e in entries:
    if e[\"file\"]==path:
        args=e.get(\"arguments\") or shlex.split(e[\"command\"])
        out=[]; skip=False
        for a in args:
            if skip: skip=False; continue
            if a==\"-o\": skip=True; continue
            if a==\"-c\": continue
            out.append(a)
        print(shlex.join(out+[\"-fsyntax-only\"])); break
")
  [ -n "$command" ] || { echo "$file: not in the build"; status=1; continue; }
  (cd $build && eval "$command") 2>&1 | grep -E "error|warning" | head -20
  [ "${PIPESTATUS[0]}" = 0 ] && echo "$file: OK" || { echo "$file: FAILED"; status=1; }
done
exit $status
' check "$@"
