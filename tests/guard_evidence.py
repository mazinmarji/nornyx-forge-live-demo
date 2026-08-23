"""Does a guard EXECUTE something that can fail? One implementation.

THIS MODULE EXISTS BECAUSE THE RULE HAD FOUR COPIES.

Three review rounds each found the same shape, and each time the repair was
applied where the reviewer was pointing:

    round 2   `_cannot_fail` taught to fold names bound only to literals
    round 3   `executed_nodes` was calling the folder WITHOUT those bindings,
              so `dead = False; if dead:` credited both branches
    round 3   `test_killed_by_validation._defensive_evidence` turned out to be
              the PRE-REPAIR implementation of all four clauses, and it governs
              every kill in the mutation catalogue

The second round's fix made the third round's defect worse rather than better:
extracting `exercised_assertions` created a canonical implementation and left
the old copy standing, which is FG26 -- "a guard and its owner test two
different copies of the same rule" -- a class this repository already names.

So the rule has ONE home. `test_no_module_reimplements_the_evidence_screen`
refuses the discredited spellings anywhere else in `tests/`, because a rule with
one home cannot drift from itself and a rule with two always will.

WHAT THIS ANSWERS, precisely: given a function that pytest collects, how many
things does it EXECUTE that can make the test fail? Not contain -- execute.
`ast.walk` answers containment, and containment credited every one of these
while the guard did nothing:

    if False:  <the original assertions>        the cheapest edit of all
    dead = False; if dead:  <the assertions>    the same, one name away
    while False: / for _ in ():  raise ...
    if True: pass / else: raise ...
    def _inner(): assert real                   never called
    an assertion inside a lambda
    try: assert real / except AssertionError: pass
    with contextlib.suppress(AssertionError): assert real
    try: pass / except Exception: raise         a handler that never runs
    return / pytest.skip(...) before the assertions

WHERE IT STOPS, stated rather than implied, and pinned by
`UNDECIDED_BY_DESIGN`: `**`, the shifts, sequence arithmetic and operands past
2**32 are not folded, because they are what turns a folder into an interpreter
with a memory budget. Anything outside the vocabulary is UNDECIDED, and
undecided always resolves toward "this is a real assertion" -- the screen can
miss a vacuous guard, it can never fail a genuine one.
"""

from __future__ import annotations

import ast
import operator


class Undecidable(Exception):
    """This expression cannot be decided without executing code."""


#: Returned by `fold` for anything outside the vocabulary.
UNDECIDED = object()

#: THE ENTIRE VOCABULARY. Anything absent from these tables is undecided.
UNARY = {ast.Not: operator.not_, ast.USub: operator.neg,
         ast.UAdd: operator.pos, ast.Invert: operator.invert}
COMPARE = {
    ast.Eq: operator.eq, ast.NotEq: operator.ne,
    ast.Lt: operator.lt, ast.LtE: operator.le,
    ast.Gt: operator.gt, ast.GtE: operator.ge,
    ast.Is: operator.is_, ast.IsNot: operator.is_not,
    ast.In: lambda left, right: left in right,
    ast.NotIn: lambda left, right: left not in right,
}
#: Arithmetic, NUMBERS ONLY and no growth operators.
#:
#: The bitwise three are here because a completeness check found them in
#: neither this table nor the declared-gap list -- so `assert 1 | 0` was
#: credited as a real assertion while the prose claimed the only unfolded
#: shapes were exponent, shift and sequence arithmetic. They cannot grow a
#: value beyond its operands, so folding them costs nothing; `**` and the
#: shifts stay out for exactly the opposite reason.
ARITHMETIC = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.BitAnd: operator.and_, ast.BitOr: operator.or_, ast.BitXor: operator.xor,
}
MAX_OPERAND = 2 ** 32

#: Handler types that stop an assertion failing the test.
SWALLOWING = frozenset({"AssertionError", "Exception", "BaseException"})


#: Sentinel for "this expression is not a literal at all".
_NOT_LITERAL = object()


#: Literal types a name can be bound to and still be FIXED.
#:
#: IMMUTABLE ONLY, and this is not pedantry -- it is a defect this rule had for
#: about ten minutes. Extending bindings from scalars to literal containers so
#: that `empty = ()` folds also folded this, which is a real guard in
#: `tests/test_ledger_atomicity.py`:
#:
#:     disagreed = []
#:     for kill_at in range(1, KILL_POINTS + 1):
#:         ...
#:         disagreed.append((kill_at, rows, witness))
#:     assert disagreed == []
#:
#: `disagreed` is bound to `[]` and then MUTATED, which no binding analysis
#: here can see. The screen decided `[] == []` was fixed at parse time and
#: reported that a 60-kill-point atomicity sweep asserts nothing. Refusing a
#: genuine guard is the louder wrong answer, and it landed on the guard for
#: FG39 -- single use with two durable stores, the property the ledger exists
#: for.
#:
#: A tuple, a string, a number cannot be mutated, so those still fold.
_IMMUTABLE = (int, float, complex, bool, str, bytes, type(None), tuple, frozenset)


def _literal_or_none(node: ast.expr):
    """The literal value of `node` when it is IMMUTABLE, or `_NOT_LITERAL`."""
    try:
        value = ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return _NOT_LITERAL
    if not isinstance(value, _IMMUTABLE):
        return _NOT_LITERAL
    if isinstance(value, tuple) and not all(
        isinstance(item, _IMMUTABLE) for item in value
    ):
        return _NOT_LITERAL
    return value


def constant_bindings(function: ast.AST) -> dict:
    """Names whose EVERY binding in this guard is a constant literal.

    A NAME REBOUND FROM ANYTHING ELSE IS NOT IN HERE. If a guard computes a
    value and asserts it, that is a real assertion whatever its first binding
    was -- so a name assigned from a call, a subscript, a loop target, a `with`
    target, a comprehension, or an augmented assignment is excluded outright,
    not merely overwritten.
    """
    constants: dict = {}
    rebound: set = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Assign):
            targets = [t for t in node.targets if isinstance(t, ast.Name)]
            complex_target = len(targets) != len(node.targets)
            for target in targets:
                # LITERAL CONTAINERS TOO, not only scalars. `empty = ()` then
                # `for _ in empty:` is exactly as dead as `for _ in ():`, and a
                # rule that folds one but not the other is one rename away from
                # useless. `literal_eval` decides membership of the class; it
                # executes nothing.
                literal = _literal_or_none(node.value) if not complex_target else None
                if literal is not _NOT_LITERAL:
                    if target.id in constants and constants[target.id] != literal:
                        rebound.add(target.id)
                    constants[target.id] = literal
                else:
                    rebound.add(target.id)
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign, ast.NamedExpr)):
            target = getattr(node, "target", None)
            if isinstance(target, ast.Name):
                rebound.add(target.id)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            for name in ast.walk(node.target):
                if isinstance(name, ast.Name):
                    rebound.add(name.id)
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            for name in ast.walk(node.optional_vars):
                if isinstance(name, ast.Name):
                    rebound.add(name.id)
    return {name: value for name, value in constants.items()
            if name not in rebound}


def fold(node: ast.expr, bindings: dict | None = None):
    """The value of an expression fixed at parse time, or `UNDECIDED`.

    NOT AN INTERPRETER. The vocabulary is written out above and every node
    outside it is undecided, so this can only ever be too permissive.

    It does NOT compile or execute the expression. An earlier version did, with
    the builtins mapping emptied, and the security gate was right to refuse it:
    `dynamic_python_execution` does not ask whether a call site looks
    defensible, it asks whether this repository executes text it assembled, and
    the answer has to stay no in the file that judges other people's guards.
    """
    try:
        return _decide(node, bindings or {})
    except (Undecidable, ArithmeticError, TypeError,
            ValueError, IndexError, KeyError):
        return UNDECIDED


def _decide(node: ast.expr, bindings: dict):
    """One node of the vocabulary, or `Undecidable`. Recursive."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id not in bindings:
            raise Undecidable
        return bindings[node.id]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        items = [_decide(element, bindings) for element in node.elts]
        if isinstance(node, ast.List):
            return items
        return tuple(items) if isinstance(node, ast.Tuple) else set(items)
    if isinstance(node, ast.Dict):
        if any(key is None for key in node.keys):
            raise Undecidable
        return {_decide(key, bindings): _decide(value, bindings)
                for key, value in zip(node.keys, node.values)}
    if isinstance(node, ast.UnaryOp) and type(node.op) in UNARY:
        return UNARY[type(node.op)](_decide(node.operand, bindings))
    if isinstance(node, ast.BoolOp):
        # SHORT-CIRCUITING, which is how Python evaluates these and is what
        # makes the answer complete. Evaluating every operand eagerly let one
        # undecidable operand poison a result that is fixed:
        #
        #     assert True or compute()          always true, credited as real
        #     assert compute() or True          always true, credited as real
        #     assert not (compute() and False)  always true, credited as real
        #
        # `or` is truthy if ANY operand is decided truthy, wherever it sits:
        # the result is the first truthy operand, and a later decided-truthy
        # one means the expression cannot be falsy either way. `and` mirrors it.
        decided = []
        for value in node.values:
            folded = fold(value, bindings)
            if folded is UNDECIDED:
                decided.append(UNDECIDED)
                continue
            if isinstance(node.op, ast.Or) and folded:
                return folded
            if isinstance(node.op, ast.And) and not folded:
                return folded
            decided.append(folded)
        if UNDECIDED in decided:
            raise Undecidable
        return decided[-1]
    if isinstance(node, ast.IfExp):
        # `1 if True else 0` is fixed at parse time. So is `x if cond else x`
        # when both arms agree in truthiness, which is the shape that survives
        # a careless edit.
        test = fold(node.test, bindings)
        if test is not UNDECIDED:
            return _decide(node.body if test else node.orelse, bindings)
        body, orelse = fold(node.body, bindings), fold(node.orelse, bindings)
        if body is UNDECIDED or orelse is UNDECIDED:
            raise Undecidable
        if bool(body) != bool(orelse):
            raise Undecidable
        return body
    if isinstance(node, ast.Compare):
        left = _decide(node.left, bindings)
        for operation, right_node in zip(node.ops, node.comparators):
            if type(operation) not in COMPARE:
                raise Undecidable
            right = _decide(right_node, bindings)
            if not COMPARE[type(operation)](left, right):
                return False
            left = right
        return True
    if isinstance(node, ast.BinOp) and type(node.op) in ARITHMETIC:
        left, right = _decide(node.left, bindings), _decide(node.right, bindings)
        if not all(isinstance(side, (int, float)) for side in (left, right)):
            raise Undecidable  # numbers only: no sequence can be grown here
        if any(abs(side) > MAX_OPERAND for side in (left, right)):
            raise Undecidable
        return ARITHMETIC[type(node.op)](left, right)
    raise Undecidable


def cannot_fail(test: ast.expr, function: ast.AST) -> bool:
    """Is this assertion's subject fixed before the suite runs?

    `assert True` is the one everybody names and it is not the interesting one.
    A review gutted a declared guard to `assert 1 == 1`, kept its marker, and
    the audit reported the class proven: every certification node passed, rc 0,
    collection identical to pristine.
    """
    folded = fold(test, constant_bindings(function))
    if folded is not UNDECIDED:
        return bool(folded)
    if isinstance(test, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
        # A non-empty literal container is truthy at parse time. An EMPTY one
        # is falsy, so `assert []` fails every time -- noisy, but not vacuous.
        try:
            return bool(ast.literal_eval(test))
        except ValueError:
            return False
    return False


def is_pytest_call(node: ast.AST, attribute: str) -> bool:
    """`pytest.<attribute>(...)`, matched as a SHAPE rather than as text.

    The `.fail()` clause once matched ANY attribute call named `fail` on any
    object, so `record.fail(reason)` counted as a proof.
    """
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr == attribute:
        return isinstance(func.value, ast.Name) and func.value.id == "pytest"
    return isinstance(func, ast.Name) and func.id == attribute


def is_expected_refusal(expr: ast.expr) -> bool:
    """`pytest.raises(...)`, matched structurally.

    THIS WAS `"raises" in ast.dump(context_expr)` -- a substring scan over a
    dumped AST, which is FG21's own class committed inside the FG auditor. It
    matched those six characters anywhere in the dump, INCLUDING inside a
    string constant, so `with io.StringIO("raises.txt") as handle:` was
    credited as an expected-refusal block.
    """
    return is_pytest_call(expr, "raises")


def _cannot_raise(block: list) -> bool:
    """Is this block incapable of raising anything?

    Only the shapes that provably cannot: `pass`, a bare docstring or other
    constant expression, and an assignment of a constant to a plain name.
    Everything else is assumed able to raise, which is the permissive
    direction -- it keeps handlers live.
    """
    for statement in block:
        if isinstance(statement, ast.Pass):
            continue
        if isinstance(statement, ast.Expr) and isinstance(
            statement.value, ast.Constant
        ):
            continue
        if (isinstance(statement, ast.Assign)
                and isinstance(statement.value, ast.Constant)
                and all(isinstance(t, ast.Name) for t in statement.targets)):
            continue
        return False
    return True


def _terminates(statement: ast.AST, bindings: dict) -> bool:
    """Does control provably leave the block at this statement?

    Anything after an unconditional `return`, `raise`, `continue`, `break`, or
    `pytest.skip(...)` does not execute. The earlier screen looked only for
    `ast.Return` as the FIRST statement, so `pytest.skip(...)` followed by real
    assertions, and `if True: return` followed by real assertions, both counted
    the assertions below them.

    RECURSIVE THROUGH COMPOUND STATEMENTS, because `if True: return` leaves the
    block exactly as `return` does. Only branches this module can DECIDE are
    followed; an undecidable `if` may fall through, so it never terminates.
    """
    if isinstance(statement, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(statement, ast.Expr) and (
        is_pytest_call(statement.value, "skip")
        or is_pytest_call(statement.value, "xfail")
    ):
        return True
    if isinstance(statement, ast.If):
        decided = fold(statement.test, bindings)
        if decided is UNDECIDED:
            return False
        taken = statement.body if decided else statement.orelse
        return any(_terminates(inner, bindings) for inner in taken)
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        return any(_terminates(inner, bindings) for inner in statement.body)
    return False


def executed_nodes(function: ast.AST) -> list:
    """(node, swallowed) for every node the guard's own body actually runs.

    CONTAINMENT IS NOT EXECUTION, and `ast.walk` only answers containment.
    """
    bindings = constant_bindings(function)
    found: list = []

    def statements(block: list, swallowed: bool) -> None:
        for statement in block:
            visit(statement, swallowed)
            if _terminates(statement, bindings):
                return

    def executes_a_raise(block: list) -> bool:
        """Does this block EXECUTE a raise or `pytest.fail`?

        Decided by execution, not by containment. A `raise` under `if False:`
        or inside a nested `def` in a handler used to make the handler count as
        re-raising, which is containment deciding reachability -- in the module
        written because containment is not execution.
        """
        probe: list = []
        outer = list(found)  # a COPY: `found` is rebound below
        try:
            found.clear()
            statements(block, False)
            probe = list(found)
        finally:
            found.clear()
            found.extend(outer)
        return any(
            isinstance(node, ast.Raise) or is_pytest_call(node, "fail")
            for node, _ in probe
        )

    def swallows(node: ast.Try) -> bool:
        for handler in node.handlers:
            caught = handler.type
            names = caught.elts if isinstance(caught, ast.Tuple) else [caught]
            catches = caught is None or any(
                (isinstance(name, ast.Name) and name.id in SWALLOWING)
                or (isinstance(name, ast.Attribute) and name.attr in SWALLOWING)
                for name in names if name is not None
            )
            if catches and not executes_a_raise(handler.body):
                return True
        return False

    def suppresses(node: ast.With) -> bool:
        """`with contextlib.suppress(AssertionError):` swallows exactly as a
        `try/except AssertionError: pass` does, and is never an `ast.Try`, so
        the handler rule could not see it."""
        for item in node.items:
            call = item.context_expr
            if not isinstance(call, ast.Call):
                continue
            func = call.func
            named = (func.attr if isinstance(func, ast.Attribute)
                     else getattr(func, "id", ""))
            if named != "suppress":
                continue
            if any(
                (isinstance(arg, ast.Name) and arg.id in SWALLOWING)
                or (isinstance(arg, ast.Attribute) and arg.attr in SWALLOWING)
                for arg in call.args
            ):
                return True
        return False

    def visit(node: ast.AST, swallowed: bool) -> None:
        # A BODY NOBODY CALLS PROVES NOTHING.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return
        found.append((node, swallowed))
        if isinstance(node, ast.If):
            visit(node.test, swallowed)
            decided = fold(node.test, bindings)
            if decided is UNDECIDED or decided:
                statements(node.body, swallowed)
            if decided is UNDECIDED or not decided:
                statements(node.orelse, swallowed)
            return
        if isinstance(node, ast.While):
            visit(node.test, swallowed)
            decided = fold(node.test, bindings)
            if decided is UNDECIDED or decided:
                statements(node.body, swallowed)
            statements(node.orelse, swallowed)
            return
        if isinstance(node, (ast.For, ast.AsyncFor)):
            visit(node.iter, swallowed)
            decided = fold(node.iter, bindings)
            if decided is UNDECIDED or len(decided) > 0:
                statements(node.body, swallowed)
            statements(node.orelse, swallowed)
            return
        if isinstance(node, ast.Try):
            statements(node.body, swallowed or swallows(node))
            # A HANDLER FOR A BODY THAT CANNOT RAISE NEVER RUNS.
            # `try: pass / except Exception: raise AssertionError('never')`
            # passes always and executes nothing that can fail.
            if not _cannot_raise(node.body):
                for handler in node.handlers:
                    statements(handler.body, swallowed)
            statements(node.orelse, swallowed)
            statements(node.finalbody, swallowed)
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                visit(item, swallowed)
            statements(node.body, swallowed or suppresses(node))
            return
        for child in ast.iter_child_nodes(node):
            visit(child, swallowed)

    statements(getattr(function, "body", []), False)
    return found


def exercised_assertions(function: ast.AST) -> int:
    """How many things this guard EXECUTES that can fail the test.

    THE ONE IMPLEMENTATION. Every consumer calls this; a second copy is refused
    by `test_no_module_reimplements_the_evidence_screen`, because the last
    three review rounds each found the rule repaired in one place and intact in
    another.
    """
    return sum(
        1
        for node, swallowed in executed_nodes(function)
        if not swallowed
        and (
            (isinstance(node, ast.Assert) and not cannot_fail(node.test, function))
            or isinstance(node, ast.Raise)
            or (isinstance(node, ast.withitem)
                and is_expected_refusal(node.context_expr))
            or is_pytest_call(node, "fail")
        )
    )
