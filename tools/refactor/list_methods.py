#!/usr/bin/env python3
"""List the member functions of one class, with their lines, as Clang parses them.
Usage: list_methods.py COMPILE_DB_DIR SOURCE CLASS"""

import sys
from clang import cindex

build, source, class_name = sys.argv[1:4]
database = cindex.CompilationDatabase.fromDirectory(build)
commands = database.getCompileCommands(source)
arguments = [
    arg for arg in list(commands[0].arguments)[1:] if arg not in ("-c", "-o") and not arg.endswith((".o", source))
]
unit = cindex.Index.create().parse(source, args=arguments)
errors = [diagnostic for diagnostic in unit.diagnostics if diagnostic.severity >= cindex.Diagnostic.Error]
if errors:
    print("\n".join(str(diagnostic) for diagnostic in errors[:5]), file=sys.stderr)
    sys.exit(1)


# ------------------------------------------------------------------------------
def find(node):
    """The definition of class_name in the source file, searched depth-first from node, or None."""
    outer, _, inner = class_name.rpartition("::")
    if (
        node.kind in (cindex.CursorKind.CLASS_DECL, cindex.CursorKind.STRUCT_DECL)
        and node.spelling == inner
        and (not outer or (node.semantic_parent and node.semantic_parent.spelling == outer))
        and node.is_definition()
        and node.location.file
        and node.location.file.name == source
    ):
        return node
    for child in node.get_children():
        found = find(child)
        if found:
            return found


klass = find(unit.cursor)
kinds = (
    cindex.CursorKind.CXX_METHOD,
    cindex.CursorKind.CONSTRUCTOR,
    cindex.CursorKind.DESTRUCTOR,
    cindex.CursorKind.FUNCTION_TEMPLATE,
)
for child in klass.get_children():
    if child.kind in kinds and child.is_definition():
        print(
            f"{child.extent.start.line:6} {child.extent.end.line - child.extent.start.line + 1:5} {child.kind.name[:6]} {child.spelling}"
        )
