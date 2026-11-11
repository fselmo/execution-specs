"""
Mutation operators for spec source.

A mutant is one small edit to one spec function, kept as the exact source
segment it replaces so it can be spliced in and undone byte for byte.
Besides the generic swaps (comparisons, arithmetic, boolean operators,
constants) the operators know the spec's idioms: `ensure` and
`if ...: raise` guards, calls made for their effect on state, the
fixed-width integer types and their wrapping methods, and the gas
constants classes.

Mutants that cannot change behavior by construction are never made: edits
inside docstrings, f-strings and type annotations.
"""

import ast
import copy
import hashlib
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Sequence, Set, Tuple, Type

COMPARE_SWAPS: Dict[Type[ast.cmpop], Tuple[Type[ast.cmpop], ...]] = {
    ast.Lt: (ast.LtE, ast.Gt),
    ast.LtE: (ast.Lt, ast.GtE),
    ast.Gt: (ast.GtE, ast.Lt),
    ast.GtE: (ast.Gt, ast.LtE),
    ast.Eq: (ast.NotEq,),
    ast.NotEq: (ast.Eq,),
    ast.Is: (ast.IsNot,),
    ast.IsNot: (ast.Is,),
    ast.In: (ast.NotIn,),
    ast.NotIn: (ast.In,),
}

BINOP_SWAPS: Dict[Type[ast.operator], Tuple[Type[ast.operator], ...]] = {
    ast.Add: (ast.Sub,),
    ast.Sub: (ast.Add,),
    ast.Mult: (ast.FloorDiv, ast.Add),
    ast.FloorDiv: (ast.Mult, ast.Mod),
    ast.Mod: (ast.FloorDiv,),
    ast.Pow: (ast.Mult,),
    ast.BitAnd: (ast.BitOr,),
    ast.BitOr: (ast.BitAnd,),
    ast.BitXor: (ast.BitOr,),
    ast.LShift: (ast.RShift,),
    ast.RShift: (ast.LShift,),
}

WRAPPING_SWAPS: Dict[str, Tuple[str, ...]] = {
    "wrapping_add": ("wrapping_sub",),
    "wrapping_sub": ("wrapping_add",),
    "wrapping_mul": ("wrapping_add",),
    "wrapping_pow": ("wrapping_mul",),
}
"""A wrapping method swapped for another of the same type."""

CHECKED: Dict[str, Type[ast.operator]] = {
    "wrapping_add": ast.Add,
    "wrapping_sub": ast.Sub,
    "wrapping_mul": ast.Mult,
    "wrapping_pow": ast.Pow,
}
"""The checked operator a wrapping method replaces: it raises where the
method wraps."""

INTEGER_SWAPS: Dict[str, Tuple[str, ...]] = {
    "U256": ("Uint",),
    "Uint": ("U256",),
    "U64": ("Uint",),
}
"""A fixed-width integer conversion swapped for another width."""

GAS_CLASSES = ("GasCosts", "StateGasCosts")
"""Classes of named gas constants whose members are swapped for their
neighbors in the class."""

GUARD_CALLS = ("ensure",)
"""Calls that raise when their condition fails: deleting one drops the
rule it enforces."""


@dataclass(frozen=True)
class Mutant:
    """One localized edit to a spec source file."""

    path: str
    """The file, relative to the repository root."""
    function: str
    lineno: int
    col_offset: int
    end_lineno: int
    end_col_offset: int
    operator: str
    original: str
    mutated: str

    @property
    def ident(self) -> str:
        """A stable id: the same edit has it whatever else is mutated."""
        key = "\0".join(
            (
                self.path,
                self.function,
                self.operator,
                self.original,
                self.mutated,
                f"{self.lineno}:{self.col_offset}",
            )
        )
        return hashlib.sha256(key.encode()).hexdigest()[:12]

    @property
    def construct(self) -> str:
        """The edit by function and text, the key for notes on it."""
        return construct(self.function, self.original, self.mutated)

    @property
    def description(self) -> str:
        """A one-line summary of the edit."""
        original = " ".join(self.original.split())
        mutated = " ".join(self.mutated.split())
        if len(original) > 70:
            original = original[:67] + "..."
        if len(mutated) > 70:
            mutated = mutated[:67] + "..."
        return f"L{self.lineno} {self.operator}: {original} -> {mutated}"


def construct(function: str, original: str, mutated: str) -> str:
    """
    An edit named by its function and text, so a note on it survives the
    file's lines moving.
    """
    return f"{function}: {' '.join(original.split())} -> " + " ".join(
        mutated.split()
    )


def line_starts(source: str) -> List[int]:
    """The offset of each line's first character in ``source``."""
    offsets = [0]
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def apply(source: str, mutant: Mutant) -> str:
    """Return ``source`` with ``mutant``'s edit made."""
    starts = line_starts(source)
    start = starts[mutant.lineno - 1] + mutant.col_offset
    end = starts[mutant.end_lineno - 1] + mutant.end_col_offset
    if source[start:end] != mutant.original:
        raise ValueError(f"{mutant.description} no longer matches")
    return source[:start] + mutant.mutated + source[end:]


def _inert_nodes(tree: ast.AST) -> Set[int]:
    """Ids of the nodes whose edits cannot change behavior."""
    inert: Set[int] = set()

    def mark(node: Optional[ast.AST]) -> None:
        if node is not None:
            inert.update(id(child) for child in ast.walk(node))

    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            mark(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            mark(node.returns)
            for arg in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
                node.args.vararg,
                node.args.kwarg,
            ):
                if arg is not None:
                    mark(arg.annotation)
        elif isinstance(node, ast.AnnAssign):
            mark(node.annotation)
        if isinstance(
            node,
            (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                mark(body[0])
    return inert


def gas_constants(source: str) -> Dict[str, List[str]]:
    """The members of each gas constants class in ``source``, in order."""
    members: Dict[str, List[str]] = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.ClassDef) and node.name in GAS_CLASSES:
            names = []
            for statement in node.body:
                if isinstance(statement, ast.AnnAssign) and isinstance(
                    statement.target, ast.Name
                ):
                    names.append(statement.target.id)
                elif isinstance(statement, ast.Assign):
                    names += [
                        target.id
                        for target in statement.targets
                        if isinstance(target, ast.Name)
                    ]
            members[node.name] = names
    return members


class _Builder:
    """Makes mutants of one function's nodes."""

    def __init__(self, path: str, source: str, function: str) -> None:
        self.path = path
        self.source = source
        self.function = function
        self.starts = line_starts(source)

    def make(
        self, node: ast.AST, mutated: str, operator: str
    ) -> Optional[Mutant]:
        original = ast.get_source_segment(self.source, node)
        if original is None or original == mutated:
            return None
        start = self.starts[node.lineno - 1] + node.col_offset  # type: ignore[attr-defined]  # noqa: E501
        if self.source[start : start + len(original)] != original:
            return None
        return Mutant(
            path=self.path,
            function=self.function,
            lineno=node.lineno,  # type: ignore[attr-defined]
            col_offset=node.col_offset,  # type: ignore[attr-defined]
            end_lineno=node.end_lineno,  # type: ignore[attr-defined]
            end_col_offset=node.end_col_offset,  # type: ignore[attr-defined]
            operator=operator,
            original=original,
            mutated=mutated,
        )

    def swap(
        self, node: ast.AST, replacement: ast.AST, operator: str
    ) -> Optional[Mutant]:
        return self.make(node, ast.unparse(replacement), operator)


def _node_mutants(
    builder: _Builder,
    node: ast.AST,
    gas: Dict[str, List[str]],
) -> Iterator[Optional[Mutant]]:
    """Every mutant of one node."""
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        for compare in COMPARE_SWAPS.get(type(node.ops[0]), ()):
            compared = copy.deepcopy(node)
            compared.ops = [compare()]
            yield builder.swap(node, compared, "compare")
    elif isinstance(node, ast.BinOp):
        for binop in BINOP_SWAPS.get(type(node.op), ()):
            computed = copy.deepcopy(node)
            computed.op = binop()
            yield builder.swap(node, computed, "binop")
    elif isinstance(node, ast.BoolOp):
        swapped = copy.deepcopy(node)
        swapped.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
        yield builder.swap(node, swapped, "boolop")
        for i in range(len(node.values)):
            rest = node.values[:i] + node.values[i + 1 :]
            kept: ast.AST = (
                rest[0] if len(rest) == 1 else ast.BoolOp(node.op, rest)
            )
            yield builder.swap(node, kept, "drop-operand")
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        yield builder.swap(node, node.operand, "drop-not")
    elif isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            yield builder.make(node, str(not node.value), "constant")
        elif isinstance(node.value, int):
            for value in (node.value + 1, node.value - 1):
                yield builder.make(node, str(value), "constant")
    elif isinstance(node, ast.If) and any(
        isinstance(statement, ast.Raise) for statement in node.body
    ):
        yield builder.make(node.test, "False", "drop-guard")
    elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        callee = node.value.func
        name = (
            callee.id
            if isinstance(callee, ast.Name)
            else callee.attr
            if isinstance(callee, ast.Attribute)
            else ""
        )
        operator = "drop-guard" if name in GUARD_CALLS else "drop-call"
        yield builder.make(node, "pass", operator)
    elif isinstance(node, ast.Call):
        callee = node.func
        if isinstance(callee, ast.Attribute) and callee.attr in CHECKED:
            for other in WRAPPING_SWAPS[callee.attr]:
                wrapped = copy.deepcopy(node)
                wrapped.func.attr = other  # type: ignore[attr-defined]
                yield builder.swap(node, wrapped, "wrapping")
            if len(node.args) == 1:
                checked = ast.BinOp(
                    callee.value, CHECKED[callee.attr](), node.args[0]
                )
                yield builder.swap(node, checked, "wrapping")
        elif isinstance(callee, ast.Name) and callee.id in INTEGER_SWAPS:
            for other in INTEGER_SWAPS[callee.id]:
                converted = copy.deepcopy(node)
                converted.func = ast.Name(other)
                yield builder.swap(node, converted, "integer-type")
    elif (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in gas
        and node.attr in gas[node.value.id]
    ):
        members = gas[node.value.id]
        at = members.index(node.attr)
        for other in {
            members[max(at - 1, 0)],
            members[(at + 1) % len(members)],
        }:
            if other != node.attr:
                yield builder.make(
                    node, f"{node.value.id}.{other}", "gas-constant"
                )


def function_mutants(
    path: str,
    source: str,
    patterns: Sequence[str],
    gas: Optional[Dict[str, List[str]]] = None,
) -> List[Mutant]:
    """
    The mutants of the top-level functions in ``source`` that match
    ``patterns`` (a name, or a prefix ending in ``*``).
    """
    tree = ast.parse(source)
    inert = _inert_nodes(tree)
    gas = gas or {}
    out: List[Mutant] = []
    seen: Set[Tuple[int, int, str]] = set()
    for function in tree.body:
        if not isinstance(
            function, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) or not matches(function.name, patterns):
            continue
        builder = _Builder(path, source, function.name)
        for statement in function.body:
            for node in ast.walk(statement):
                if id(node) in inert:
                    continue
                for mutant in _node_mutants(builder, node, gas):
                    if mutant is None:
                        continue
                    key = (mutant.lineno, mutant.col_offset, mutant.mutated)
                    if key not in seen:
                        seen.add(key)
                        out.append(mutant)
    return out


def matches(name: str, patterns: Sequence[str]) -> bool:
    """Whether ``name`` is one of ``patterns`` or starts with a `x*` one."""
    return any(
        name.startswith(pattern[:-1])
        if pattern.endswith("*")
        else name == pattern
        for pattern in patterns
    )


def function_source(source: str, name: str) -> Optional[ast.AST]:
    """The top-level function ``name`` in ``source``, if any."""
    for node in ast.parse(source).body:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ):
            return node
    return None


def same_function(a: Optional[ast.AST], b: Optional[ast.AST]) -> bool:
    """Whether two functions are the same code, docstrings aside."""
    if a is None or b is None:
        return False

    def bare(node: ast.AST) -> str:
        node = copy.deepcopy(node)
        body = node.body  # type: ignore[attr-defined]
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            node.body = body[1:] or [ast.Pass()]  # type: ignore[attr-defined]  # noqa: E501
        return ast.dump(node, include_attributes=False)

    return bare(a) == bare(b)


def previous_fork_mutants(
    path: str, source: str, previous: str, patterns: Sequence[str]
) -> List[Mutant]:
    """
    The `previous-fork` mutants: each matched function replaced by its
    namesake in ``previous`` (the same file in the fork before), where the
    two differ. It models a change a fork made being lost.
    """
    out: List[Mutant] = []
    tree = ast.parse(source)
    for function in tree.body:
        if not isinstance(
            function, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) or not matches(function.name, patterns):
            continue
        before = function_source(previous, function.name)
        if before is None or same_function(function, before):
            continue
        replacement = ast.get_source_segment(previous, before)
        builder = _Builder(path, source, function.name)
        if replacement is not None:
            mutant = builder.make(function, replacement, "previous-fork")
            if mutant is not None:
                out.append(mutant)
    return out
