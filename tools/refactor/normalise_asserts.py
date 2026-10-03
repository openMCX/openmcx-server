#!/usr/bin/env python3
"""Blank what assert() stores in a preprocessed C++ file: the expression text, the file name, the
line and the function name passed to __assert_fail. Comments and renames inside an assert change
these and nothing else; same-code.sh compares the files again after this.

  normalise_asserts.py INPUT.ii OUTPUT.cpp
"""

import sys

CALL = '__assert_fail'
BLANK = CALL + '("X", "F", 0, __extension__ __PRETTY_FUNCTION__)'


# -------------------------------------------------------------------------------
def end_of_call(text, start):
    """The index of the parenthesis closing the call that opens at start, skipping string literals."""
    depth, index = 0, start
    while True:
        char = text[index]
        if char == '"':
            index += 1
            while text[index] != '"':
                index += 2 if text[index] == '\\' else 1
        elif char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
            if depth == 0:
                return index
        index += 1


# -------------------------------------------------------------------------------
def main():
    with open(sys.argv[1], encoding='utf-8') as source:
        text = source.read()
    parts, position = [], 0
    while (found := text.find(CALL, position)) >= 0:
        # The declaration in <assert.h> ("extern void __assert_fail (...)") stays as it is.
        if text[max(0, found - 12) : found].strip().endswith('void'):
            parts.append(text[position : found + len(CALL)])
            position = found + len(CALL)
            continue
        parts.append(text[position:found] + BLANK)
        position = end_of_call(text, text.index('(', found)) + 1
    parts.append(text[position:])
    with open(sys.argv[2], 'w', encoding='utf-8') as output:
        output.write(''.join(parts))


if __name__ == '__main__':
    main()
