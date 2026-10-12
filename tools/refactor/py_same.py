#!/usr/bin/env python3
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

"""Prove that edits to Python files changed no code: compare the syntax tree of each file as
committed (git HEAD) and as it is now, with the names of variables, parameters and loop targets
normalised away and docstrings and comments ignored. Renamed local names and reformatting leave
the trees equal; any change of logic, string, number, attribute or call does not.

  tools/refactor/py_same.py [--whole-file] FILE.py...

--whole-file also numbers the module's own names (functions, classes, globals): for scripts that no
other file imports, whose module-level names may be renamed too.
"""

import ast
import subprocess
import sys


# -------------------------------------------------------------------------------
SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


# -------------------------------------------------------------------------------
class Scope:
    """A function, lambda or comprehension scope and the names it binds, in order of first binding."""

    def __init__(self, parent, number):
        self.parent = parent
        self.number = number
        self.bound = {}
        self.outer = set()  # declared global or nonlocal: resolved outside

    def bind(self, name):
        if name not in self.outer:
            self.bound.setdefault(name, len(self.bound))

    def resolve(self, name):
        scope = self
        while scope is not None:
            if name in scope.bound:
                return f'local{scope.number}.{scope.bound[name]}'
            scope = scope.parent
        return name  # module-level, builtin or class attribute: never renamed


# -------------------------------------------------------------------------------
def scopes_of(tree, whole_file=False):
    """First pass: each scope node's Scope, with Python's binding rules (parameters; assignment,
    loop, with and except targets; imports and nested functions inside functions; global and
    nonlocal names excluded). Module and class level names are not scoped: they keep their names."""
    scopes = {}

    def visit(node, scope):
        if isinstance(node, SCOPES):
            scope = scopes[node] = Scope(scope, len(scopes))
            if not isinstance(node, COMPREHENSIONS):
                arguments = node.args
                for argument in arguments.posonlyargs + arguments.args + arguments.kwonlyargs:
                    scope.bind(argument.arg)
                for argument in (arguments.vararg, arguments.kwarg):
                    if argument:
                        scope.bind(argument.arg)
        elif scope is not None:
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                scope.outer.update(node.names)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                scope.bind(node.id)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                scope.bind(node.name)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    scope.bind((alias.asname or alias.name).split('.')[0])
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                scope.bind(node.name)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and scope is not None:
                scope.bind(child.name)  # a nested function's name lives in the enclosing scope
            visit(child, scope)

    module = Scope(None, -1) if whole_file else None
    visit(tree, module)
    return scopes, module


# -------------------------------------------------------------------------------
class Normalise(ast.NodeTransformer):
    """Second pass: every local name becomes its scope's number and its binding order there, so a
    consistent rename leaves the tree equal while merging or splitting names does not; module names,
    builtins, attributes and keyword arguments keep their spelling; docstrings are dropped."""

    def __init__(self, scopes, module=None):
        self.scopes = scopes
        self.stack = [module]

    def visit(self, node):
        scope = self.scopes.get(node) if isinstance(node, SCOPES) else None
        if scope is None:
            return super().visit(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # The function's own name, decorators, defaults and annotations belong to the enclosing scope.
            node.name = self.resolve(node.name)
            node.decorator_list = [self.visit(item) for item in node.decorator_list]
            node.args.defaults = [self.visit(item) for item in node.args.defaults]
            node.args.kw_defaults = [self.visit(item) if item else None for item in node.args.kw_defaults]
            node.returns = self.visit(node.returns) if node.returns else None
            self.body_without_docstring(node)
            self.stack.append(scope)
            for argument in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
                argument.arg = self.resolve(argument.arg)
            for argument in (node.args.vararg, node.args.kwarg):
                if argument:
                    argument.arg = self.resolve(argument.arg)
            node.body = [self.visit(item) for item in node.body]
            self.stack.pop()
            return node
        self.stack.append(scope)
        result = super().visit(node)
        self.stack.pop()
        return result

    def resolve(self, name):
        return self.stack[-1].resolve(name) if self.stack[-1] else name

    def visit_Name(self, node):
        node.id = self.resolve(node.id)
        return node

    def visit_arg(self, node):
        node.arg = self.resolve(node.arg)
        return node

    def visit_ExceptHandler(self, node):
        if node.name:
            node.name = self.resolve(node.name)
        self.generic_visit(node)
        return node

    def body_without_docstring(self, node):
        first = node.body[0] if node.body else None
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
            node.body = node.body[1:]

    def visit_ClassDef(self, node):
        if self.stack[-1]:
            node.name = self.resolve(node.name)
        self.body_without_docstring(node)
        # A class body is no scope for the methods inside it (Python's rule): keep the enclosing one.
        self.generic_visit(node)
        return node


# -------------------------------------------------------------------------------
def shape(source, whole_file=False):
    tree = ast.parse(source)
    if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant):
        tree.body = tree.body[1:]
    scopes, module = scopes_of(tree, whole_file)
    return ast.dump(Normalise(scopes, module).visit(tree), annotate_fields=False)


# -------------------------------------------------------------------------------
def main():
    status = 0
    whole_file = '--whole-file' in sys.argv[1:]
    for path in [argument for argument in sys.argv[1:] if argument != '--whole-file']:
        before = subprocess.run(['git', 'show', f'HEAD:{path}'], capture_output=True, text=True)
        if before.returncode:
            print(f'{path}: new')
            continue
        with open(path, encoding='utf-8') as source:
            after = source.read()
        if shape(before.stdout, whole_file) == shape(after, whole_file):
            print(f'{path}: same code')
        else:
            print(f'{path}: CODE CHANGED')
            status = 1
    return status


if __name__ == '__main__':
    sys.exit(main())
