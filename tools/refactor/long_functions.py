#!/usr/bin/env python3
"""List the function definitions longer than a limit (CODING_STYLE.md section 3.2: about 60 lines), longest first.
Run in the openmcx-lint image (libclang):

  long_functions.py COMPILE_DB_DIR LIMIT FILE.cpp...
"""

import sys
from pathlib import Path

from clang import cindex

KINDS = (
    cindex.CursorKind.FUNCTION_DECL,
    cindex.CursorKind.CXX_METHOD,
    cindex.CursorKind.CONSTRUCTOR,
    cindex.CursorKind.DESTRUCTOR,
    cindex.CursorKind.FUNCTION_TEMPLATE,
)


# -------------------------------------------------------------------------------
def arguments_for(database, path):
    """The file's compile flags from the compilation database, without the output and the file itself."""
    command = list(database.getCompileCommands(str(Path(path).resolve()))[0].arguments)
    flags, skip = [], False
    for argument in command[1:]:
        if skip:
            skip = False
        elif argument == '-o':
            skip = True
        elif argument != '-c' and not argument.endswith(Path(path).name):
            flags.append(argument)
    return flags


# -------------------------------------------------------------------------------
def main():
    database = cindex.CompilationDatabase.fromDirectory(sys.argv[1])
    limit = int(sys.argv[2])
    root = Path.cwd().resolve()
    found = {}
    for source in sys.argv[3:]:
        unit = cindex.Index.create().parse(str(Path(source).resolve()), args=arguments_for(database, source))
        for cursor in unit.cursor.walk_preorder():
            if cursor.kind not in KINDS or not cursor.is_definition() or not cursor.location.file:
                continue
            path = Path(cursor.location.file.name).resolve()
            if not path.is_relative_to(root):
                continue
            length = cursor.extent.end.line - cursor.extent.start.line + 1
            if length > limit:
                name = (
                    f'{cursor.semantic_parent.spelling}::{cursor.spelling}'
                    if cursor.semantic_parent
                    else cursor.spelling
                )
                found[(str(path.relative_to(root)), cursor.extent.start.line)] = (length, name)
    for (path, line), (length, name) in sorted(found.items(), key=lambda item: -item[1][0]):
        print(f'{length:5d}  {path}:{line}  {name}')


if __name__ == '__main__':
    main()
