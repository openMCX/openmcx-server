#!/usr/bin/env bash
# Prove that edits to C++ files changed no code: compile each file as committed (HEAD) and as
# it is now, with the build's flags at -O2 and no debug information, and compare the object
# files. Renamed local variables and parameters, comments and formatting leave them identical;
# any change in behaviour, string or number does not. A file whose objects differ is compared
# once more with assert() normalised (normalise_asserts.py): assert stores its line and its
# expression text, which comments and renames change, and __LINE__ is pinned to 0 there for
# any other macro that records it (test macros); that pass prints
# "same code (asserts normalised)". Other uses of __LINE__ remain a difference.
#   tools/refactor/same-code.sh FILE...                     in mcxserver
#   MCXSERVER=/path tools/refactor/same-code.sh FILE...     in mcxclient
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cd "$(git rev-parse --show-toplevel)"
[ $# -gt 0 ] || { echo "usage: same-code.sh FILE..." >&2; exit 2; }
server=${MCXSERVER:-}
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/before"
git archive HEAD | tar -x -C "$work/before"
cp "$here/normalise_asserts.py" "$work/"
# Moved files are compared with their committed version under the old path ("new old" per line).
git diff -M --name-status HEAD | awk '$1 ~ /^R/ {print $3, $2}' > "$work/renames"
mounts=(-v "$PWD:/after:ro" -v "$work/before:/before:ro" -v "$work:/work")
extra=""
if [ -n "$server" ]; then mounts+=(-v "$(cd "$server" && pwd):/mcxserver:ro"); extra="-DMCXSERVER_DIR=/mcxserver"; fi
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp "${mounts[@]}" openmcx-lint:0.1 bash -c '
set -uo pipefail
extra=$1; shift
for tree in before after; do cmake -S /$tree -B /work/build-$tree -DCMAKE_EXPORT_COMPILE_COMMANDS=ON $extra >/dev/null 2>&1; done
status=0
for file in "$@"; do
  case "$file" in *.hpp) continue ;; esac
  for tree in before after; do
    source=$file
    if [ $tree = before ]; then source=$(awk -v moved="$file" '"'"'$1 == moved {print $2}'"'"' /work/renames); source=${source:-$file}; fi
    [ -f /$tree/$source ] || { echo "$file: missing in $tree"; status=1; continue 2; }
    command=$(python3 -c "
import json,shlex
for e in json.load(open(\"/work/build-$tree/compile_commands.json\")):
    if e[\"file\"]==\"/$tree/$source\":
        args=e.get(\"arguments\") or shlex.split(e[\"command\"]); out=[]; skip=False
        for a in args:
            if skip: skip=False; continue
            if a==\"-o\": skip=True; continue
            if a in (\"-c\",\"-g\",\"-flto\",\"-flto=auto\",\"-fno-fat-lto-objects\") or a.startswith((\"-O\",\"-g\")): continue
            out.append(a)
        print(shlex.join(out+[\"-O2\",\"-g0\"])); break
")
    echo "$command" > /work/$tree.command
    (cd /work/build-$tree && eval "$command -c -o /work/$tree.o") >/dev/null 2>&1 || { echo "$file: does not compile ($tree)"; status=1; continue 2; }
    strip --strip-debug -R .comment -o /work/$tree.stripped /work/$tree.o
  done
  if cmp -s /work/before.stripped /work/after.stripped; then echo "$file: same code"; continue; fi
  # Second pass: preprocess, blank the assert() arguments, compile the result.
  for tree in before after; do
    command=$(cat /work/$tree.command)
    (cd /work/build-$tree && eval "$command -Wno-builtin-macro-redefined -U__LINE__ -D__LINE__=0 -E -P -o /work/$tree.ii") >/dev/null 2>&1
    python3 /work/normalise_asserts.py /work/$tree.ii /work/$tree.normal.cpp
    compiler=$(echo "$command" | awk "{print \$1}")
    (cd /work && $compiler -std=c++20 -O2 -g0 -w -c /work/$tree.normal.cpp -o /work/$tree.normal.o) >/dev/null 2>&1
    strip --strip-debug -R .comment -o /work/$tree.normal.stripped /work/$tree.normal.o 2>/dev/null
  done
  if cmp -s /work/before.normal.stripped /work/after.normal.stripped; then echo "$file: same code (asserts normalised)"; else echo "$file: CODE CHANGED"; status=1; fi
done
exit $status
' same "$extra" "$@"
