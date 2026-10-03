#!/usr/bin/env python3
"""Give function declarations the parameter names of their definitions (the companion of the step 5
renames, which changed names in the definitions only).

For every function or member function defined in the given translation units, the declarations of
it (in headers or the same file) whose parameter names differ are rewritten to the definition's
names. Only parameter names in declarations change, which changes no code. Run in the openmcx-lint
image (libclang):

  sync_params.py COMPILE_DB_DIR FILE.cpp...
"""

import sys
from collections import defaultdict
from pathlib import Path

from clang import cindex

FUNCTION_KINDS = (
    cindex.CursorKind.FUNCTION_DECL,
    cindex.CursorKind.CXX_METHOD,
    cindex.CursorKind.CONSTRUCTOR,
    cindex.CursorKind.DESTRUCTOR,
)


# -------------------------------------------------------------------------------
def parse(database, path):
    command = list(database.getCompileCommands(str(Path(path).resolve()))[0].arguments)
    arguments, skip = [], False
    for argument in command[1:]:
        if skip:
            skip = False
            continue
        if argument in ('-o', '-c'):
            skip = argument == '-o'
            continue
        if argument.endswith(Path(path).name):
            continue
        arguments.append(argument)
    return cindex.Index.create().parse(str(Path(path).resolve()), args=arguments)


# -------------------------------------------------------------------------------
def parameters(cursor):
    return [child for child in cursor.get_children() if child.kind == cindex.CursorKind.PARM_DECL]


# -------------------------------------------------------------------------------
def walk(node, root):
    """The cursors of the project's own files (system and library headers are not descended)."""
    yield node
    for child in node.get_children():
        if child.location.file and not Path(child.location.file.name).resolve().is_relative_to(root):
            continue
        yield from walk(child, root)


# -------------------------------------------------------------------------------
def main():
    build = sys.argv[1]
    database = cindex.CompilationDatabase.fromDirectory(build)
    root = Path.cwd().resolve()
    edits = defaultdict(dict)  # file -> {offset: (old, new)}
    for source in sys.argv[2:]:
        unit = parse(database, source)
        for cursor in walk(unit.cursor, root):
            if cursor.kind not in FUNCTION_KINDS or not cursor.is_definition():
                continue
            if not cursor.location.file or not Path(cursor.location.file.name).resolve().is_relative_to(root):
                continue
            wanted = [parameter.spelling for parameter in parameters(cursor)]
            # Every other declaration of this function: the canonical one and the redeclarations
            # libclang reaches through it.
            seen = set()
            declaration = cursor.canonical
            for candidate in [declaration]:
                key = (candidate.location.file.name if candidate.location.file else None, candidate.location.offset)
                if key in seen or candidate == cursor:
                    continue
                seen.add(key)
                if candidate.is_definition() or not candidate.location.file:
                    continue
                path = Path(candidate.location.file.name).resolve()
                if not path.is_relative_to(root):
                    continue
                have = parameters(candidate)
                if len(have) != len(wanted):
                    continue
                for parameter, name in zip(have, wanted):
                    if parameter.spelling and name and parameter.spelling != name:
                        edits[path][parameter.location.offset] = (parameter.spelling, name)
    changed = 0
    for path, changes in edits.items():
        text = path.read_bytes()
        for offset in sorted(changes, reverse=True):
            old, new = changes[offset]
            if text[offset : offset + len(old)].decode() != old:
                sys.exit(f'{path}: unexpected text at {offset}: expected {old}')
            text = text[:offset] + new.encode() + text[offset + len(old) :]
            changed += 1
        path.write_bytes(text)
        print(f'{path.relative_to(root)}: {len(changes)} parameter names')
    print(f'{changed} declaration parameter names changed')


if __name__ == '__main__':
    main()
