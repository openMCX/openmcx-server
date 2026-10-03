#!/usr/bin/env python3
"""Split one C++ class, written with its member functions defined inside the class body, into
a header with the class declaration and source files with the member function definitions,
grouped by topic.

Nothing but the place of the code changes: every definition keeps its text and the comment
directly above it; the class keeps its members, their order and access. Kept inline in the
header: one-line member functions, templates, functions with a deduced return type and
constexpr functions (so no call loses inlining it had). Moved out: everything else, as
`ReturnType Class::name(parameters) qualifiers { ... }`, with default arguments left on the
declaration and nested type names in the return type qualified with the class name.

Usage (in the openmcx-lint image, which has libclang):
  split_class.py PLAN.json COMPILE_DB_DIR

PLAN.json:
  {"source": "src/server.cpp", "class": "Server", "out_dir": "src/mcptt",
   "header": "server.hpp", "main": "main.cpp", "default": "server.cpp",
   "preamble": "// ... file comment for the header ...",
   "groups": [{"file": "affiliation.cpp", "from": "affiliation_limit", "to": "end_implicit_affiliation",
               "title": "Affiliation (TS 24.379 clause 9.2)"}, ...]}
Groups name a run of member functions in class order, from the first function named `from`
to the next function named `to`.
"""

import json
import re
import sys
from pathlib import Path

from clang import cindex

METHOD_KINDS = (cindex.CursorKind.CXX_METHOD, cindex.CursorKind.CONSTRUCTOR, cindex.CursorKind.DESTRUCTOR)
TYPE_KINDS = (
    cindex.CursorKind.STRUCT_DECL,
    cindex.CursorKind.CLASS_DECL,
    cindex.CursorKind.ENUM_DECL,
    cindex.CursorKind.TYPEDEF_DECL,
    cindex.CursorKind.TYPE_ALIAS_DECL,
)


# -------------------------------------------------------------------------------
def parse(build, source):
    """The translation unit of source, with its compile command from the compilation database."""
    database = cindex.CompilationDatabase.fromDirectory(build)
    command = list(database.getCompileCommands(str(Path(source).resolve()))[0].arguments)
    arguments = []
    skip_next = False
    for argument in command[1:]:
        if skip_next:
            skip_next = False
            continue
        if argument in ('-o', '-c'):
            skip_next = argument == '-o'
            continue
        if argument.endswith(Path(source).name):
            continue
        arguments.append(argument)
    unit = cindex.Index.create().parse(str(Path(source).resolve()), args=arguments)
    errors = [str(diagnostic) for diagnostic in unit.diagnostics if diagnostic.severity >= cindex.Diagnostic.Error]
    if errors:
        sys.exit('parse errors:\n' + '\n'.join(errors[:10]))
    return unit


# -------------------------------------------------------------------------------
def find_class(node, name, source):
    """The definition of the class or struct `name` in source; `Outer::Inner` names a nested one
    defined at namespace scope (a pimpl such as `struct SipEngine::Impl { ... }`)."""
    outer, _, inner = name.rpartition('::')
    if (
        node.kind in (cindex.CursorKind.CLASS_DECL, cindex.CursorKind.STRUCT_DECL)
        and node.spelling == inner
        and (not outer or (node.semantic_parent and node.semantic_parent.spelling == outer))
        and node.is_definition()
        and node.location.file
        and Path(node.location.file.name).resolve() == Path(source).resolve()
    ):
        return node
    for child in node.get_children():
        found = find_class(child, name, source)
        if found:
            return found
    return None


# -------------------------------------------------------------------------------
def matching_paren(text, open_index):
    """Index of the parenthesis closing the one at open_index."""
    depth = 0
    for index in range(open_index, len(text)):
        if text[index] == '(':
            depth += 1
        elif text[index] == ')':
            depth -= 1
            if depth == 0:
                return index
    raise ValueError('unbalanced parentheses')


# -------------------------------------------------------------------------------
def split_top_level(text, separator=','):
    """Split at separators outside (), <>, [], {} and string literals."""
    parts, depth, current, quote = [], 0, [], None
    for character in text:
        if quote:
            current.append(character)
            if character == quote:
                quote = None
            continue
        if character in '"\'':
            quote = character
        elif character in '(<[{':
            depth += 1
        elif character in ')>]}':
            depth -= 1
        elif character == separator and depth == 0:
            parts.append(''.join(current))
            current = []
            continue
        current.append(character)
    parts.append(''.join(current))
    return parts


# -------------------------------------------------------------------------------
def without_defaults(parameters):
    """The parameter list without default arguments (they stay on the declaration)."""
    if not parameters.strip():
        return parameters
    kept = []
    for parameter in split_top_level(parameters):
        pieces = split_top_level(parameter, '=')
        kept.append(pieces[0].rstrip())
    return ','.join(kept)


# -------------------------------------------------------------------------------
def leading_comment_start(text, offset):
    """Offset where the comment lines directly above offset begin (offset itself when none)."""
    line_start = text.rfind('\n', 0, offset) + 1
    start = line_start
    while start > 0:
        previous_end = start - 1
        previous_start = text.rfind('\n', 0, previous_end) + 1
        line = text[previous_start:previous_end].strip()
        if line.startswith('//') and not line.startswith('// ----'):
            start = previous_start
        else:
            break
    return start


# -------------------------------------------------------------------------------
def method_parts(text, method, nested_types, class_name):
    """The declaration and the out-of-class definition of one member function."""
    body = next(child for child in method.get_children() if child.kind == cindex.CursorKind.COMPOUND_STMT)
    start, body_start, end = method.extent.start.offset, body.extent.start.offset, method.extent.end.offset
    signature = text[start:body_start].rstrip()
    name = method.spelling
    pattern = ('~' + re.escape(name[1:]) + r'\b') if name.startswith('~') else (r'\b' + re.escape(name) + r'\b')
    name_match = re.search('(' + pattern + r')\s*\(', signature)
    if not name_match:
        raise ValueError(f'cannot find the name of {name} in: {signature}')
    prefix = signature[: name_match.start(1)]
    open_paren = signature.index('(', name_match.end(1) - 1)
    close_paren = matching_paren(signature, open_paren)
    parameters = signature[open_paren + 1 : close_paren]
    after = signature[close_paren + 1 :]
    # A constructor's member initializer list belongs to the definition only.
    initializers = ''
    qualifiers = after
    if method.kind == cindex.CursorKind.CONSTRUCTOR and ':' in after:
        colon = after.index(':')
        qualifiers, initializers = after[:colon], after[colon:]
    declaration = f'{prefix}{name}({parameters}){qualifiers.rstrip()};'
    # The definition: no static/virtual/explicit/inline, no override/final, no default arguments.
    definition_prefix = re.sub(r'\b(static|virtual|explicit|inline)\s+', '', prefix)
    definition_qualifiers = re.sub(r'\s*\b(override|final)\b', '', qualifiers).rstrip()
    for nested in nested_types:
        definition_prefix = re.sub(
            r'(?<![:\w])' + re.escape(nested) + r'\b', f'{class_name}::{nested}', definition_prefix
        )
    head = f'{definition_prefix}{class_name}::{name}({without_defaults(parameters)}){definition_qualifiers}'
    if initializers:
        head += ' ' + initializers.strip()
    definition = head + ' ' + text[body_start:end]
    return declaration, definition, start, end


# -------------------------------------------------------------------------------
def keep_inline(text, method):
    """One-liners, templates, deduced return types and constexpr stay in the class."""
    if method.kind == cindex.CursorKind.FUNCTION_TEMPLATE:
        return True
    # "= default", "= delete" and function-try-blocks have no plain body to move.
    if not any(child.kind == cindex.CursorKind.COMPOUND_STMT for child in method.get_children()):
        return True
    source = text[method.extent.start.offset : method.extent.end.offset]
    head = source.split('{', 1)[0]
    if method.extent.start.line == method.extent.end.line:
        return True
    if re.search(r'\bconstexpr\b', head) or re.match(r'\s*(static\s+)?auto\b(?!.*->)', head):
        return True
    return False


# -------------------------------------------------------------------------------
def main():
    plan = json.loads(Path(sys.argv[1]).read_text())
    build = sys.argv[2]
    source = Path(plan['source'])
    class_name = plan['class']
    text = source.read_text()
    unit = parse(build, source)
    klass = find_class(unit.cursor, class_name, source)
    if klass is None:
        sys.exit(f'class {class_name} not found in {source}')
    nested_types = [child.spelling for child in klass.get_children() if child.kind in TYPE_KINDS and child.spelling]
    methods = [
        child
        for child in klass.get_children()
        if (child.kind in METHOD_KINDS or child.kind == cindex.CursorKind.FUNCTION_TEMPLATE) and child.is_definition()
    ]
    names = [method.spelling for method in methods]

    # Topic of each member function, from the plan's runs.
    topic = [plan['default']] * len(methods)
    titles = {plan['default']: plan.get('default_title', f'{class_name}: core')}
    for group in plan['groups']:
        first = names.index(group['from'])
        last = names.index(group['to'], first)
        for index in range(first, last + 1):
            topic[index] = group['file']
        titles[group['file']] = group['title']

    # Rewrite the class: moved definitions become declarations; their comments move with them.
    out_dir = Path(plan['out_dir'])
    definitions = {}
    edits = []
    moved = 0
    for method, file_name in zip(methods, topic):
        if keep_inline(text, method):
            continue
        declaration, definition, start, end = method_parts(text, method, nested_types, class_name)
        comment_start = leading_comment_start(text, start)
        comment = text[comment_start : text.rfind('\n', 0, start) + 1] if comment_start < start else ''
        indent = text[text.rfind('\n', 0, start) + 1 : start]
        definitions.setdefault(file_name, []).append(
            '//------------------------------------------------------------------------------\n'
            + dedent(comment + indent + definition, indent)
        )
        edits.append((comment_start, end, indent + declaration))
        moved += 1
    rewritten = text
    for start, end, replacement in sorted(edits, reverse=True):
        line_start = rewritten.rfind('\n', 0, start) + 1
        rewritten = rewritten[:line_start] + replacement + rewritten[end:]

    # The header: everything up to the end of the class, the free parts moved to main.
    class_end = klass.extent.end.offset
    offset_shift = len(rewritten) - len(text)
    header_text, tail = split_tail(rewritten, class_end + offset_shift)
    header = out_dir / plan['header']
    guard_text = plan.get('preamble', '').rstrip() + '\n#pragma once\n\n' + header_text.rstrip() + '\n'
    guard_text = move_anonymous_namespace(guard_text, plan)
    out_dir.mkdir(parents=True, exist_ok=True)
    header.write_text(close_namespace(guard_text))
    for file_name, bodies in definitions.items():
        (out_dir / file_name).write_text(
            f'// {titles.get(file_name, file_name)}\n'
            f'// Member functions of {class_name} (declared in {plan["header"]}).\n\n'
            f'#include "{plan["header"]}"\n\nnamespace mcx {{\n\n' + '\n\n'.join(bodies) + '\n\n} // namespace mcx\n'
        )
    (out_dir / plan['main']).write_text(main_file(tail, plan))
    print(f'{moved} member functions moved, {len(methods) - moved} kept inline; files:')
    for file_name in sorted(definitions):
        print(f'  {out_dir / file_name}: {len(definitions[file_name])}')


# -------------------------------------------------------------------------------
def dedent(block, indent):
    """Remove one class-body indentation level from every line of a moved definition."""
    lines = block.split('\n')
    return '\n'.join(line[len(indent) :] if line.startswith(indent) else line for line in lines)


# -------------------------------------------------------------------------------
def split_tail(text, class_end):
    """The text up to the class's closing '};', and what follows it."""
    end = text.index(';', class_end) + 1
    return text[:end], text[end:]


# -------------------------------------------------------------------------------
def move_anonymous_namespace(header_text, plan):
    """The signal flag and handler the class and main share: declared in the header, defined in main."""
    for old, new in plan.get('header_replace', []):
        header_text = header_text.replace(old, new)
    return header_text


# -------------------------------------------------------------------------------
def close_namespace(header_text):
    return header_text.rstrip() + '\n} // namespace mcx\n'


# -------------------------------------------------------------------------------
def main_file(tail, plan):
    """main(), after the class: the rest of the original file."""
    tail = re.sub(r'^\s*\}\s*//\s*namespace mcx\s*\n', '', tail)
    return (
        plan.get('main_preamble', '').rstrip()
        + f'\n\n#include "{plan["header"]}"\n\n'
        + plan.get('main_definitions', '')
        + tail.lstrip('\n')
    )


if __name__ == '__main__':
    main()
