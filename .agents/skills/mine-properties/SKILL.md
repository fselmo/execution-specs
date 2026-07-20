# Mine Properties

Agentic property mining for the reference spec (EELS), adapting Anthropic's
property-based-testing method (arXiv 2510.09907) to this repo. You read spec
code and its authority (docstrings and/or the EIP), propose **evidence-grounded**
properties, write them as Hypothesis tests, self-triage false alarms, and prove
each property's worth objectively with mutation testing.

## Inputs (dual-mode)

`$ARGUMENTS` is one of:

- **An EIP number** (e.g. `7825`) — *manifest mode*: test what the fork changed.
  Run `uv run eip-manifest --from <parent> --to <fork>` to get the EIP-attributed
  change manifest, and mine properties for that EIP's changes.
- **A spec module path** (e.g. `src/ethereum/forks/osaka/vm/gas.py`) — *paper
  mode*: mine properties for the module regardless of whether it changed. This
  catches latent bugs in long-standing code (where the paper's biggest finds
  were), so do not restrict yourself to changed code.

## The loop

1. **Analyze.** Resolve the target. In manifest mode, list the EIP's changes and
   their kinds/archetypes from `eip_properties`. In module mode, list the public
   functions with substantive docstrings.
2. **Understand.** Read the source and its docstrings. Follow import chains to
   the real implementation. **Investigate the input domain via callers** — track
   implicit preconditions (a property over inputs the callers never pass is a
   false alarm). In manifest mode, also read the EIP text for the normative rule.
3. **Propose properties — grounded in evidence only.** Only test properties the
   code or EIP *explicitly claims* (docstring, comment, caller usage, or EIP
   prose). Do not invent properties you merely believe are true. Draw from these
   **shapes** × **oracle tiers**:
   - Shapes: round-trip (`decode(encode(x)) == x`), inverse (`add`/`remove`),
     invariant (`len(f(x)) <= len(x)`), metamorphic (relate `f(x)` and `g(x)`),
     idempotence/commutativity, confluence (order-independence), and
     **single-entry crash-freedom** (a decoder/parser never crashes on valid
     input — apply to RLP/transaction/precompile decoding).
   - Oracle tiers (where does correctness come from — the fork can't be its own
     oracle): **differential** (parent fork / another client), **structural**
     (execution presence), **assertion** (grounded in the EIP/docstring — the
     only tier that hard-codes a claim). Prefer differential/structural; reserve
     assertion for claims you can cite.
4. **Write tests.** Put them in `tests_property/` (pure Hypothesis, no fill, no
   clients). Reuse `tests_property/strategies/base.py` and
   `execution_testing.fuzzing`; fork-parametrize like the existing suite; use
   `@with_each_change(kind)` from `eip_properties` for change-covariant
   archetypes. Prefer **sound but incomplete** strategies — 90% coverage of the
   input domain is enough; never generate inputs the code does not expect.
   Study `tests_property/test_gas.py` and `test_state_machine.py` as exemplars.
5. **Execute and self-triage.** Run `just test-spec-properties <file>`. For a
   failure, apply the triage rubric (below) and decide honestly: *bad property*
   (fix or drop it, record why) or *real defect* (report it). Re-check the input
   domain before believing a failure. For a pass, confirm the test actually
   exercises the claimed property (not a trivial input).
6. **Prove worth with mutation, then report.** A passing property is only
   valuable if it can *fail*. Run
   `uv run mutate --module <target> --test <your test file> --oracle properties`
   and confirm your property **kills mutants that previously survived**
   (mutation-kill-delta > 0). A property that kills nothing is weak or
   redundant — strengthen or drop it. Then produce the report (below).

## Grounding rule (record it per property)

Every property cites its authority:

- **EIP prose** → *normative*. A violation is a genuine spec bug.
- **EELS docstring** → *self-descriptive*. A violation means EELS is inconsistent
  with its own documentation — still worth fixing, lower severity.

**Never author an expected post-state or fixture.** You propose *properties*;
EELS, the differential oracle, and mutation testing judge them. A wrong frozen
fixture poisons every client's CI, so assertion-tier properties are landed only
after a human reviews the grounding.

## Triage (two tracks)

- **Spec defect** (a property/invariant fails, or clients/forks diverge): triage
  by *reproducibility → legitimacy (realistic input? actually claimed?) →
  impact*. Category: consensus-divergence (critical) > spec-vs-EIP contract >
  invariant > crash. This may become a maintainer report.
- **Coverage gap** (a mutant survives — the suite can't tell the mutation from
  correct behaviour): this is a *missing test*, not a bug. Route it to
  test-writing (write the property that kills it), never a bug report.

Rank findings; surface the top for human review rather than dumping all.

## Output

For each proposed property: the test, its shape/oracle tier, its grounding
(EIP-prose vs docstring, cited), and its mutation-kill-delta. For any spec
defect: a minimal reproducer, why it violates the cited authority, and the
triage category. Do not post anything externally — surface for human review.
