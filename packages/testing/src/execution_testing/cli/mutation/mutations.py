"""
Enumerate source mutations of a spec module.

A mutant is a single, localized change to the source: a swapped comparison
or arithmetic operator, a flipped boolean, or a tweaked constant. Each mutant
records the exact source segment it replaces so it can be applied by splicing
and reverted exactly.

Mutation testing asks: if the spec is *wrong* in this small way, does any
test notice? A mutant that no test kills marks a gap in the conformance
suite. Operator swaps are the default because they are high-signal and few;
constant tweaks are opt-in because they are numerous and noisier.
"""

import ast
import copy
from dataclasses import dataclass
from typing import Dict, List, Optional, Type

# Comparison operators that map to a meaningful, still-valid alternative.
_COMPARE_SWAPS: Dict[Type[ast.cmpop], List[Type[ast.cmpop]]] = {
    ast.Lt: [ast.LtE, ast.Gt],
    ast.LtE: [ast.Lt, ast.GtE],
    ast.Gt: [ast.GtE, ast.Lt],
    ast.GtE: [ast.Gt, ast.LtE],
    ast.Eq: [ast.NotEq],
    ast.NotEq: [ast.Eq],
    ast.Is: [ast.IsNot],
    ast.IsNot: [ast.Is],
    ast.In: [ast.NotIn],
    ast.NotIn: [ast.In],
}

_BINOP_SWAPS: Dict[Type[ast.operator], List[Type[ast.operator]]] = {
    ast.Add: [ast.Sub],
    ast.Sub: [ast.Add],
    ast.Mult: [ast.FloorDiv],
    ast.FloorDiv: [ast.Mult],
    ast.Mod: [ast.Mult],
    ast.BitAnd: [ast.BitOr],
    ast.BitOr: [ast.BitAnd],
    ast.BitXor: [ast.BitAnd],
    ast.LShift: [ast.RShift],
    ast.RShift: [ast.LShift],
}

_BOOLOP_SWAPS: Dict[Type[ast.boolop], Type[ast.boolop]] = {
    ast.And: ast.Or,
    ast.Or: ast.And,
}


@dataclass
class Mutant:
    """A single localized source mutation."""

    lineno: int
    col_offset: int
    end_lineno: int
    end_col_offset: int
    operator: str
    original: str
    mutated: str

    @property
    def description(self) -> str:
        """One-line human summary of the change."""
        return (
            f"L{self.lineno} [{self.operator}] "
            f"{self.original!r} -> {self.mutated!r}"
        )


def _segment_bounds(lines_start: List[int], node: ast.AST) -> tuple[int, int]:
    """Absolute [start, end) character offsets of a node's source segment."""
    start = lines_start[node.lineno - 1] + node.col_offset  # type: ignore[attr-defined]
    end = lines_start[node.end_lineno - 1] + node.end_col_offset  # type: ignore[attr-defined]
    return start, end


def _line_start_offsets(source: str) -> List[int]:
    offsets = [0]
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def _mutant_from_node(
    source: str,
    lines_start: List[int],
    node: ast.AST,
    mutated_node: ast.AST,
    operator: str,
) -> Optional[Mutant]:
    """
    Build a mutant by unparsing ``mutated_node`` over ``node``'s segment.

    Returns ``None`` if the recomputed segment does not match the AST's own
    source segment (a safety guard against offset drift on exotic lines).
    """
    start, end = _segment_bounds(lines_start, node)
    original = source[start:end]
    if original != ast.get_source_segment(source, node):
        return None
    mutated = ast.unparse(mutated_node)
    if mutated == original:
        return None
    return Mutant(
        lineno=node.lineno,  # type: ignore[attr-defined]
        col_offset=node.col_offset,  # type: ignore[attr-defined]
        end_lineno=node.end_lineno,  # type: ignore[attr-defined]
        end_col_offset=node.end_col_offset,  # type: ignore[attr-defined]
        operator=operator,
        original=original,
        mutated=mutated,
    )


def enumerate_mutants(
    source: str, *, include_constants: bool = False
) -> List[Mutant]:
    """Return all mutants for ``source`` (operator swaps; constants opt-in)."""
    tree = ast.parse(source)
    lines_start = _line_start_offsets(source)
    mutants: List[Mutant] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            for cmp_op in _COMPARE_SWAPS.get(type(node.ops[0]), []):
                new_cmp = copy.deepcopy(node)
                new_cmp.ops = [cmp_op()]
                mutant = _mutant_from_node(
                    source, lines_start, node, new_cmp, "compare"
                )
                if mutant is not None:
                    mutants.append(mutant)

        elif isinstance(node, ast.BinOp):
            for bin_op in _BINOP_SWAPS.get(type(node.op), []):
                new_bin = copy.deepcopy(node)
                new_bin.op = bin_op()
                mutant = _mutant_from_node(
                    source, lines_start, node, new_bin, "binop"
                )
                if mutant is not None:
                    mutants.append(mutant)

        elif isinstance(node, ast.BoolOp):
            bool_op = _BOOLOP_SWAPS.get(type(node.op))
            if bool_op is not None:
                new_bool = copy.deepcopy(node)
                new_bool.op = bool_op()
                mutant = _mutant_from_node(
                    source, lines_start, node, new_bool, "boolop"
                )
                if mutant is not None:
                    mutants.append(mutant)

        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            # Drop the negation: `not x` -> `x`.
            mutant = _mutant_from_node(
                source, lines_start, node, node.operand, "unary-not"
            )
            if mutant is not None:
                mutants.append(mutant)

        elif include_constants and isinstance(node, ast.Constant):
            mutants.extend(_constant_mutants(source, lines_start, node))

    return mutants


def _constant_mutants(
    source: str, lines_start: List[int], node: ast.Constant
) -> List[Mutant]:
    out: List[Mutant] = []
    value = node.value
    if isinstance(value, bool):
        new = copy.deepcopy(node)
        new.value = not value
        mutant = _mutant_from_node(
            source, lines_start, node, new, "const-bool"
        )
        if mutant is not None:
            out.append(mutant)
    elif isinstance(value, int):
        for replacement in (value + 1, value - 1):
            new = copy.deepcopy(node)
            new.value = replacement
            mutant = _mutant_from_node(
                source, lines_start, node, new, "const-int"
            )
            if mutant is not None:
                out.append(mutant)
    return out


def apply_mutant(source: str, mutant: Mutant) -> str:
    """Return ``source`` with ``mutant`` applied via source-segment splice."""
    lines_start = _line_start_offsets(source)
    start = lines_start[mutant.lineno - 1] + mutant.col_offset
    end = lines_start[mutant.end_lineno - 1] + mutant.end_col_offset
    assert source[start:end] == mutant.original, (
        "mutant no longer matches source; was the file edited?"
    )
    return source[:start] + mutant.mutated + source[end:]
