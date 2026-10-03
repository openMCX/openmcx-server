#!/usr/bin/env python3
"""Split a C++ source file of free functions into topic files, the companion of split_class.py for files without one big class.

The file's anonymous-namespace helpers become an internal module: their constants, types and
declarations in an internal header (in a named namespace the topic files use), their
definitions in a helpers file. The public functions after them go, unchanged and in order, to
the topic files the plan names: each group starts at the function it names and runs to the next
group's first function. A separator line goes before every definition (docs/CODING_STYLE.md 3.1).

Usage: split_functions.py PLAN.json
PLAN.json:
  {"source": "src/protocol.cpp", "out_dir": "src/protocol", "header": "protocol_internal.hpp",
   "helpers": "xml_support.cpp", "detail_namespace": "protocol_detail",
   "preamble": "// ... header comment ...",
   "helpers_title": "...",
   "groups": [{"file": "conference.cpp", "from": "xml_escape", "title": "..."}, ...]}
"""

import json
import re
import sys
from pathlib import Path

SEPARATOR = '//------------------------------------------------------------------------------\n'


# -------------------------------------------------------------------------------
def top_level_items(block):
    """(text, leading comment) of each top-level declaration or definition in block."""
    items, position, length = [], 0, len(block)
    while position < length:
        match = re.match(r'((?:[ \t]*//[^\n]*\n|[ \t]*\n)*)', block[position:])
        comment = match.group(1)
        position += len(comment)
        if position >= length:
            break
        depth, quote, index = 0, None, position
        while index < length:
            character = block[index]
            if quote:
                if character == '\\':
                    index += 2
                    continue
                if character == quote:
                    quote = None
            elif block.startswith('//', index):
                index = block.find('\n', index)
                index = length if index < 0 else index
                continue
            elif block.startswith('/*', index):
                index = block.find('*/', index) + 2
                continue
            elif character in '"\'':
                quote = character
            elif character == '{':
                depth += 1
            elif character == '}':
                depth -= 1
                if depth == 0 and not re.match(r'\s*;', block[index + 1 :]):
                    index += 1
                    break
            elif character == ';' and depth == 0:
                index += 1
                break
            index += 1
        items.append((block[position:index], comment))
        position = index
    return items


# -------------------------------------------------------------------------------
def split_top_level(text, separator):
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
def function_head(item):
    """The text before the body of a function definition, or None for anything else."""
    head = item.split('{', 1)[0]
    stripped = head.strip()
    if '(' not in stripped or not item.rstrip().endswith('}'):
        return None
    if re.match(r'(struct|class|enum|union|using|namespace|template)\b', stripped):
        return None
    if re.match(r'(inline\s+)?(constexpr|const)\b', stripped) and '=' in stripped.split('(')[0]:
        return None
    return head


# -------------------------------------------------------------------------------
def without_defaults(head):
    """A function head without its default arguments (they stay on the declaration)."""
    open_index = head.index('(')
    depth, close_index = 0, None
    for index in range(open_index, len(head)):
        if head[index] == '(':
            depth += 1
        elif head[index] == ')':
            depth -= 1
            if depth == 0:
                close_index = index
                break
    parameters = head[open_index + 1 : close_index]
    kept = [split_top_level(parameter, '=')[0].rstrip() for parameter in split_top_level(parameters, ',')]
    return head[: open_index + 1] + ','.join(kept) + head[close_index:]


# -------------------------------------------------------------------------------
def function_name(head):
    names = re.findall(r'(\w+)\s*\(', head)
    return names[0] if names else None


# -------------------------------------------------------------------------------
def main():
    plan = json.loads(Path(sys.argv[1]).read_text())
    source = Path(plan['source'])
    text = source.read_text()
    namespace_start = text.index('namespace mcx {\n')
    includes = text[:namespace_start].rstrip()
    block_start = text.index('namespace {\n', namespace_start)
    block_end = text.index('} // namespace\n', block_start)
    helper_block = text[block_start + len('namespace {\n') : block_end]
    rest_end = text.rindex('} // namespace mcx')
    rest = text[block_end + len('} // namespace\n') : rest_end]

    header_parts, helper_definitions = [], []
    for item, comment in top_level_items(helper_block):
        head = function_head(item)
        if head is None:
            declaration = re.sub(r'^(\s*)constexpr\b', r'\1inline constexpr', item.strip(), count=1)
            header_parts.append(comment.strip('\n') + ('\n' if comment.strip() else '') + declaration)
            continue
        header_parts.append(comment.strip('\n') + ('\n' if comment.strip() else '') + head.strip() + ';')
        body = item[len(head) :]
        helper_definitions.append(
            SEPARATOR + comment.lstrip('\n') + without_defaults(head).rstrip() + ' ' + body.strip()
        )

    starts = {group['from']: group for group in plan['groups']}
    files, current = {}, None
    for item, comment in top_level_items(rest):
        head = function_head(item)
        name = function_name(head) if head else None
        if name in starts:
            current = starts[name]
        if head is None:
            # Constants and types between the functions: shared, so in the internal header.
            declaration = re.sub(r'^(\s*)(static\s+)?constexpr\b', r'\1inline constexpr', item.strip(), count=1)
            header_parts.append(comment.strip('\n') + ('\n' if comment.strip() else '') + declaration)
            continue
        if current is None:
            sys.exit(f'no group for the first definition: {item[:80]}')
        prefix = SEPARATOR
        files.setdefault(current['file'], (current, []))[1].append(prefix + comment.lstrip('\n') + item.strip())

    out_dir = Path(plan['out_dir'])
    out_dir.mkdir(parents=True, exist_ok=True)
    detail = plan['detail_namespace']
    (out_dir / plan['header']).write_text(
        plan['preamble'].rstrip()
        + '\n\n#pragma once\n\n'
        + includes
        + f'\n\nnamespace mcx {{\nnamespace {detail} {{\n\n'
        + '\n\n'.join(header_parts)
        + f'\n\n}} // namespace {detail}\nusing namespace {detail};\n}} // namespace mcx\n'
    )
    (out_dir / plan['helpers']).write_text(
        f'// {plan["helpers_title"]}\n\n#include "{plan["header"]}"\n\nnamespace mcx {{\nnamespace {detail} {{\n\n'
        + '\n\n'.join(helper_definitions)
        + f'\n\n}} // namespace {detail}\n}} // namespace mcx\n'
    )
    for file_name, (group, items) in files.items():
        (out_dir / file_name).write_text(
            f'// {group["title"]}\n\n#include "{plan["header"]}"\n\nnamespace mcx {{\n\n'
            + '\n\n'.join(items)
            + '\n\n} // namespace mcx\n'
        )
    print(
        f'{len(helper_definitions)} helpers; files:',
        ', '.join(f'{name} ({len(items)})' for name, (_, items) in files.items()),
    )


if __name__ == '__main__':
    main()
