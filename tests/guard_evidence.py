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
the old copy standing, which is FG40 -- "a repaired rule, when a second copy of it was left
standing". That class did not exist when this was written: the sentence said
"a class this repository already names" and named FG26, which is about a probe
mutating the governed tree it measures. The class is real -- three rounds found
it -- so it was added to the inventory rather than the sentence being softened.

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

#: `ast.TryStar` exists from 3.11; on older interpreters it does not.
TRY_NODES = tuple(
    node for node in (ast.Try, getattr(ast, "TryStar", None)) if node is not None
)

#: `ast.Match` exists from 3.10.
MATCH_NODE = getattr(ast, "Match", None)

#: Pattern nodes that CAPTURE a name. `case [first, *rest]` binds both, and
#: neither appears as an `ast.Name` anywhere in the tree.
_MATCH_CAPTURES = tuple(
    node for node in (
        getattr(ast, "MatchAs", None),
        getattr(ast, "MatchStar", None),
        getattr(ast, "MatchMapping", None),
    ) if node is not None
)

#: Statement types the walker does not dispatch on, and why that is safe.
#:
#: DERIVED AGAINST THE GRAMMAR, not against what a reviewer happened to name.
#: Three consecutive review rounds found a shape the screen missed, and each
#: time I added that shape and believed the list complete. `ast.TryStar` and
#: `ast.Match` were missing for exactly as long as they have existed in Python,
#: and would have been red the day this module was written if the question had
#: been asked of the grammar instead of of me.
#:
#: A statement here falls through to the generic child walk, which is correct
#: when it neither introduces a scope, nor a conditional body, nor a way to
#: swallow a failure.
UNDISPATCHED_STATEMENTS = {
    "AnnAssign": "an annotation or a plain binding; no body",
    "Assert": "counted, not walked into",
    "Assign": "no body",
    "AugAssign": "no body",
    "Break": "no body; handled as a terminator",
    "ClassDef": "a body that executes at definition time and holds no guard",
    "Continue": "no body; handled as a terminator",
    "Delete": "no body",
    "Expr": "a bare expression; its call is inspected in place",
    "Global": "a declaration",
    "Import": "no body",
    "ImportFrom": "no body",
    "Nonlocal": "a declaration",
    "Pass": "no body",
    "Raise": "counted, not walked into",
    "Return": "no body; handled as a terminator",
    "TypeAlias": "a declaration",
}

#: Expression types `_decide` does not fold, and why.
#:
#: Same derivation, same reason. `JoinedStr` and `Subscript` were on this list
#: in spirit and in neither table in fact, which is how `assert f"{1} == {2}"`
#: -- fixed at parse time, one character from a real assertion -- was credited.
UNFOLDED_EXPRESSIONS = {
    "Attribute": "reads state",
    "Await": "reads state",
    "Call": "reads state",
    "DictComp": "iterates; folding it is interpreting",
    "Ellipsis": "deprecated alias of Constant",
    "FormattedValue": "folded only as part of its JoinedStr",
    "GeneratorExp": "iterates; folding it is interpreting",
    "Lambda": "a callable, not a value",
    "ListComp": "iterates; folding it is interpreting",
    "NamedExpr": "binds as a side effect; out of scope for a pure folder",
    "SetComp": "iterates; folding it is interpreting",
    "Slice": "folded only as part of its Subscript",
    "Starred": "unpacking, not a value",
    "Yield": "suspends",
    "YieldFrom": "suspends",
}


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


#: Statements whose body is a DIFFERENT scope. A name bound inside one of these
#: is not a module-level binding, so the module walk yields the statement and
#: stops.
NESTED_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def module_scope_statements(module: ast.AST):
    """Every statement in the MODULE's own scope, and no other scope.

    `module.body` alone was what the earlier pass read, so a constant declared
    under `if TYPE_CHECKING:` or inside a `try: ... except ImportError:` was
    invisible; walking the whole module instead would have collected the locals
    of every function in the file, which are not in scope at all.
    """
    stack = list(getattr(module, "body", []))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, NESTED_SCOPES):
            continue
        for field in ("body", "orelse", "finalbody"):
            stack.extend(getattr(node, field, None) or [])
        for handler in getattr(node, "handlers", None) or []:
            stack.extend(handler.body)
        for case in getattr(node, "cases", None) or []:
            stack.extend(case.body)


def own_nodes(statement: ast.AST):
    """Every node belonging to this statement, and to no nested statement.

    `module_scope_statements` yields a compound statement AND its children,
    so a rule that walked the whole subtree saw the same binding twice --
    once as the `Assign` that records it, once as the enclosing `If` that
    disqualifies it. Measured: a constant at column 0 was folded and the
    identical constant one level under `if True:` was not, so the escape
    `module_scope_statements` exists to close survived a single indent.

    Nested statements are skipped because they are yielded in their own
    right. Everything else belongs here: a `for` target, a `with ... as`,
    an `except ... as`, a match capture and a walrus in a test are all
    children of the compound statement rather than statements themselves.
    """
    stack = [statement]
    while stack:
        node = stack.pop()
        yield node
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                continue
            stack.append(child)


def bound_names(node: ast.AST) -> set:
    """Every name this statement binds.

    Store and Del contexts carry almost all of it -- the grammar puts an
    `ast.Name` in target position for plain assignment, augmented assignment,
    annotated assignment, walrus, loop targets, `with ... as`, comprehension
    targets and `del`, however deeply nested in tuples or starred targets. The
    rest bind without a `Name` node at all, and are listed because there is
    nowhere else to read them from.

    Over-collecting here is SAFE and under-collecting is the defect: a name this
    misses stays a "constant", its `if` folds, and the branch below it is judged
    dead -- which is how five genuine guards were refused. A name this collects
    wrongly is merely undecidable, and an undecidable branch is credited.

    THAT SAFE DIRECTION HAS A LIMIT, and it was reached. Walking the whole
    subtree meant a compound statement collected the bindings of every
    statement inside it -- and since `module_scope_statements` yields those
    statements too, the name an `Assign` had just recorded was disqualified
    by its own enclosing `if`. Over-collection there is not undecidability;
    it is the binding erasing itself. `own_nodes` stops at nested
    statements, which are visited on their own.
    `test_symtable_agrees_that_these_are_all_the_module_bindings` checks the
    dangerous direction against CPython's own binding analysis rather than
    against a table maintained here.
    """
    if isinstance(node, NESTED_SCOPES):
        # The def binds its own name; its BODY is another scope entirely. Its
        # decorators, defaults, annotations and bases are not -- they are
        # evaluated where the def appears, so a binding in one of them is a
        # binding here.
        #
        # `symtable` found this on real code and I had not thought of it:
        # `ids=[case[0] for case in SPECIMENS]` inside a `@parametrize`
        # decorator binds `case` AT MODULE LEVEL from Python 3.12, because
        # PEP 709 inlines list comprehensions into the enclosing scope.
        # Returning only `{node.name}` missed it.
        surrounding = [*node.decorator_list]
        arguments = getattr(node, "args", None)
        if isinstance(arguments, ast.arguments):
            surrounding += [d for d in arguments.defaults if d is not None]
            surrounding += [d for d in arguments.kw_defaults if d is not None]
            for group in (arguments.posonlyargs, arguments.args,
                          arguments.kwonlyargs):
                surrounding += [a.annotation for a in group if a.annotation]
        for extra in ("returns", "bases", "keywords"):
            value = getattr(node, extra, None)
            if isinstance(value, list):
                surrounding += value
            elif value is not None:
                surrounding.append(value)
        names = {node.name}
        for expression in surrounding:
            names |= _stored_names(expression)
        return names
    return _stored_names(node, own_nodes(node))


def _stored_names(node: ast.AST, nodes=None) -> set:
    """Every name bound in this subtree, or in the nodes supplied.

    `nodes` is how a caller says "this statement only, not the ones
    nested in it". Without it the whole subtree is walked, which is what
    a decorator or a default expression needs.
    """
    names: set = set()
    for inner in (ast.walk(node) if nodes is None else nodes):
        if isinstance(inner, ast.Name) and isinstance(inner.ctx, (ast.Store, ast.Del)):
            names.add(inner.id)
        elif isinstance(inner, ast.alias):
            names.add(inner.asname or inner.name.split(".")[0])
        elif isinstance(inner, NESTED_SCOPES):
            names.add(inner.name)
        elif isinstance(inner, (ast.Global, ast.Nonlocal)):
            names.update(inner.names)
        elif isinstance(inner, ast.ExceptHandler) and inner.name:
            names.add(inner.name)
        elif isinstance(inner, ast.arg):
            names.add(inner.arg)
        elif MATCH_NODE is not None:
            captured = getattr(inner, "name", None) or getattr(inner, "rest", None)
            if isinstance(inner, _MATCH_CAPTURES) and isinstance(captured, str):
                names.add(captured)
    return names


def module_constants(module: ast.AST) -> dict:
    """Module-level names whose EVERY module-level binding is a literal.

    The earlier pass read only `ast.Assign` statements in `module.body` and
    `continue`d past anything else, so a second, non-literal binding of the same
    name did not disqualify it. Measured, every one of these reported the guard
    below it DEAD -- identically to a guard that really was dead:

        FLAG = False ; FLAG = _detect()        recomputed after the literal
        COUNT = 0 ; COUNT += 1                 augmented
        STATE = False ; for STATE in ...       rebound by a loop
        enabled = False ; from config import enabled

    The docstring above said such a name was "excluded outright". It was not.
    """
    constants: dict = {}
    disqualified: set = set()
    # A `global` DECLARED IN ANY FUNCTION rebinds a module name from a
    # scope this walk never visits, so the literal assignment is not the
    # only binding and the name is not a constant. Measured:
    #
    #     _ON = True
    #     def _arm():
    #         global _ON
    #         _ON = False
    #
    # gave `{'_ON': True}`, so `if _ON:` folded live and its body was
    # credited whether or not `_arm()` had run. `ast.walk` rather than
    # `module_scope_statements`, precisely because the declaration is
    # inside another scope.
    for node in ast.walk(module):
        if isinstance(node, ast.Global):
            disqualified.update(node.names)
    for node in module_scope_statements(module):
        if isinstance(node, ast.Assign):
            targets = [t for t in node.targets if isinstance(t, ast.Name)]
            literal = (
                _literal_or_none(node.value)
                if len(targets) == len(node.targets) else _NOT_LITERAL
            )
            if literal is not _NOT_LITERAL:
                for target in targets:
                    if target.id in constants and constants[target.id] != literal:
                        disqualified.add(target.id)
                    constants[target.id] = literal
                continue
        disqualified.update(bound_names(node))
    return {name: value for name, value in constants.items()
            if name not in disqualified}


def constant_bindings(function: ast.AST, module: ast.AST | None = None) -> dict:
    """Names whose EVERY binding is an immutable constant literal.

    THREE SPELLINGS ESCAPED THIS, and one of them was demonstrated end to end
    on a real guard -- FG21's owner went from pristine RED to gutted GREEN by
    adding ONE module-level line and indenting the body under it:

        _OFF = False                      module-level, not seen at all
        dead = False; gone = dead         an alias, not seen
        first, second = False, True       tuple unpacking, not seen

    All three are `dead = False; if dead:` with a rename, and that shape is
    pinned as a specimen. A rule that catches the pinned spelling and not its
    synonyms is a rule about the spelling.

    A NAME REBOUND FROM ANYTHING ELSE IS NOT IN HERE. If a guard computes a
    value and asserts it, that is a real assertion whatever its first binding
    was -- so a name assigned from a call, a subscript, a loop target, a `with`
    target, a comprehension, or an augmented assignment is excluded outright,
    not merely overwritten. THAT SENTENCE WAS TRUE OF THE FUNCTION AND FALSE OF
    THE MODULE: the module pass read `ast.Assign` and skipped every other
    statement without disqualifying anything, so `FLAG = False` followed by
    `FLAG = _detect()` left `FLAG` a constant. See `module_constants`.

    A PARAMETER SHADOWING THE NAME, and a `global` declaration, are the two
    other ways the module binding is not the one the guard reads. Both are
    disqualified here rather than in `module_constants`, because both are facts
    about this function and not about the module.
    """
    constants: dict = {}
    rebound: set = set()

    # MODULE-LEVEL CONSTANTS ARE IN SCOPE INSIDE THE GUARD. Seeing only the
    # function's own assignments meant a module-level `_OFF = False` was
    # invisible, so `if _OFF:` was undecidable and both branches were credited.
    # Read first, so a name the guard rebinds locally still disqualifies it.
    if module is not None:
        constants.update(module_constants(module))

    # A PARAMETER IS THE BINDING IN SCOPE, whatever the module says. Measured:
    # module `ready = False` with `def test_g(ready):` folded `if ready:` to
    # False and reported the guard dead.
    arguments = getattr(function, "args", None)
    if isinstance(arguments, ast.arguments):
        for group in (arguments.posonlyargs, arguments.args, arguments.kwonlyargs):
            rebound.update(argument.arg for argument in group)
        for solo in (arguments.vararg, arguments.kwarg):
            if solo is not None:
                rebound.add(solo.arg)

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
                # `... if not complex_target else None` MEANT to disqualify
                # and did the opposite: `None is not _NOT_LITERAL`, so a
                # chained assignment bound a COMPUTED name to the constant
                # `None`. Measured: `results = report['x'] = run()` gave
                # `{'results': None}`, and `assert results == expected` was
                # then judged fixed at parse time -- a genuine guard refused.
                literal = (
                    _literal_or_none(node.value)
                    if not complex_target else _NOT_LITERAL
                )
                if literal is not _NOT_LITERAL:
                    if target.id in constants and constants[target.id] != literal:
                        rebound.add(target.id)
                    constants[target.id] = literal
                elif isinstance(node.value, ast.Name) and not complex_target:
                    # AN ALIAS IS DEFERRED, not disqualified. `gone = dead`
                    # binds a constant when `dead` does, and marking it rebound
                    # here meant the alias pass below could never rescue it --
                    # which is the whole shape: `dead = False; if dead:` with
                    # one extra line.
                    pass
                else:
                    rebound.add(target.id)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            # The guard says out loud that it may rebind this name, and where
            # from is out of view.
            rebound.update(node.names)
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

    # TUPLE UNPACKING OF A LITERAL TUPLE. `first, second = False, True` binds
    # two constants and was recorded as neither, because the target is a Tuple
    # rather than a Name.
    for node in ast.walk(function):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Tuple):
                continue
            values = _literal_or_none(node.value)
            names = [inner for inner in target.elts if isinstance(inner, ast.Name)]
            if (values is _NOT_LITERAL
                    or not isinstance(values, tuple)
                    or len(names) != len(target.elts)
                    or len(values) != len(names)):
                for inner in ast.walk(target):
                    if isinstance(inner, ast.Name):
                        rebound.add(inner.id)
                continue
            for inner, value in zip(names, values):
                if inner.id in constants and constants[inner.id] != value:
                    rebound.add(inner.id)
                constants[inner.id] = value

    settled = {name: value for name, value in constants.items()
               if name not in rebound}

    # ALIASES, to a fixed point. `dead = False; gone = dead` binds `gone` to a
    # constant just as surely, and the alias was the cheapest of the three
    # escapes: one extra line in the guard being gutted.
    #
    # Bounded by the number of assignments, so it terminates: each pass can
    # only add names, and there are finitely many.
    for _ in range(len(list(ast.walk(function)))):
        added = False
        for node in ast.walk(function):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Name):
                continue
            source = node.value.id
            if source not in settled:
                continue
            for target in node.targets:
                if (isinstance(target, ast.Name)
                        and target.id not in rebound
                        and target.id not in settled):
                    settled[target.id] = settled[source]
                    added = True
        if not added:
            break

    # AN ALIAS OF SOMETHING UNKNOWN IS UNKNOWN. Deferring above means an alias
    # whose source never resolves must be disqualified here, or a computed
    # value would be treated as absent rather than as real.
    for node in ast.walk(function):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Name):
            continue
        if node.value.id in settled:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                rebound.add(target.id)
    return {name: value for name, value in settled.items() if name not in rebound}


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
    if isinstance(node, ast.JoinedStr):
        # AN F-STRING WITH NOTHING TO INTERPOLATE IS A LITERAL, and one with
        # decidable parts is decidable. `assert f"a message"` is `assert
        # "a message"` with an f in front, and the plain form WAS caught while
        # this was not -- a one-character edit from a real assertion, reading
        # exactly like one.
        parts = []
        for piece in node.values:
            if isinstance(piece, ast.Constant):
                parts.append(str(piece.value))
                continue
            if not isinstance(piece, ast.FormattedValue):
                raise Undecidable
            inner = fold(piece.value, bindings)
            if inner is UNDECIDED or piece.format_spec is not None:
                raise Undecidable
            parts.append(str(inner))
        return "".join(parts)
    if isinstance(node, ast.Subscript):
        # A literal indexed by a literal is a literal. `assert (1, 2)[0]` and
        # `assert 'abc'[0] == 'a'` sat inside the folder's own vocabulary and
        # were credited as real assertions.
        container = _decide(node.value, bindings)
        index = _decide(node.slice, bindings)
        return container[index]
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


def cannot_fail(test: ast.expr, function: ast.AST,
                module: ast.AST | None = None) -> bool:
    """Is this assertion's subject fixed before the suite runs?

    `assert True` is the one everybody names and it is not the interesting one.
    A review gutted a declared guard to `assert 1 == 1`, kept its marker, and
    the audit reported the class proven: every certification node passed, rc 0,
    collection identical to pristine.
    """
    folded = fold(test, constant_bindings(function, module))
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


def is_pytest_call(
    node: ast.AST, attribute: str, module: ast.AST | None = None,
) -> bool:
    """`pytest.<attribute>(...)`, matched as a SHAPE rather than as text.

    The `.fail()` clause once matched ANY attribute call named `fail` on any
    object, so `record.fail(reason)` counted as a proof. That was repaired by
    requiring a `pytest` receiver -- and the BARE-NAME branch below, which
    exists for `from pytest import raises`, was left matching any function of
    that name at all:

        def fail(msg): ...          ... fail("nothing happened")   -> counted
        @contextmanager
        def raises(kind): ...       ... with raises(ValueError):   -> counted

    Half a repair is how this rule has failed before. When the module is
    supplied the bare name must actually have been imported FROM pytest;
    without it the old, permissive answer stands, because refusing every bare
    name would fail the genuine `from pytest import raises` this branch was
    added for.
    """
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr == attribute:
        return isinstance(func.value, ast.Name) and func.value.id == "pytest"
    if not (isinstance(func, ast.Name) and func.id == attribute):
        return False
    if module is None:
        return True
    return attribute in _imported_from_pytest(module)


def _imported_from_pytest(module: ast.AST) -> set:
    """Names this module bound by importing them from pytest."""
    found: set = set()
    for node in ast.walk(module):
        if isinstance(node, ast.ImportFrom) and node.module == "pytest":
            found |= {alias.asname or alias.name for alias in node.names}
    return found


def is_expected_refusal(
    expr: ast.expr, module: ast.AST | None = None,
) -> bool:
    """`pytest.raises(...)`, matched structurally.

    THIS WAS `"raises" in ast.dump(context_expr)` -- a substring scan over a
    dumped AST, which is FG21's own class committed inside the FG auditor. It
    matched those six characters anywhere in the dump, INCLUDING inside a
    string constant, so `with io.StringIO("raises.txt") as handle:` was
    credited as an expected-refusal block.
    """
    return is_pytest_call(expr, "raises", module)


def _is_non_empty(value) -> bool:
    """Does this folded value iterate at least once?

    Anything without a length is treated as iterating, which is the permissive
    direction: an undecidable loop body must be credited, never crashed on.
    """
    try:
        return len(value) > 0
    except TypeError:
        return True


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


#: Statement types that cannot end a block, and why.
#:
#: THE FOURTH VOCABULARY AXIS. `executed_nodes` dispatch and `_decide` folding
#: are both derived against the grammar; `_terminates` was not, and it decided
#: two compound statements out of six while its docstring said "RECURSIVE
#: THROUGH COMPOUND STATEMENTS".
#:
#: Measured cost of that gap: four lines at the top of any guard, every
#: assertion left in place --
#:
#:     try:
#:         return
#:     except Exception:
#:         pass
#:     <the entire real body>
#:
#: -- gutted 40 of 40 FG owners with identical `exercised` counts pristine and
#: gutted, and 4 of the 5 bodies carrying all 41 catalogue kills. Collection
#: unchanged, markers unchanged, census blind, no unreachable-code lint.
#:
#: A statement listed here falls through as "does not terminate", which is the
#: permissive direction: it can only leave a dead statement counted, never
#: refuse a live one.
NON_TERMINATING_STATEMENTS = {
    "AnnAssign": "binds; control continues",
    "Assert": "may raise, but a passing assertion continues",
    "Assign": "binds; control continues",
    "AsyncFunctionDef": "defines; control continues",
    "AugAssign": "binds; control continues",
    "ClassDef": "defines; control continues",
    "Delete": "unbinds; control continues",
    "FunctionDef": "defines; control continues",
    "Global": "a declaration",
    "Import": "binds; control continues",
    "ImportFrom": "binds; control continues",
    "Nonlocal": "a declaration",
    "Pass": "does nothing",
    "TypeAlias": "a declaration",
}


def _handlers_can_intercept(node) -> bool:
    """Can an `except` clause here stop the body's exit from leaving the block?

    No: handlers catch EXCEPTIONS, and `return`/`break`/`continue` are not
    exceptions. `try: return / except Exception: pass` executes the return and
    never enters the handler. A `raise` in the body IS interceptable, which is
    why `_body_exit_is_an_exception` is asked separately.
    """
    return bool(node.handlers)


def _body_exit_is_an_exception(
    block: list, bindings: dict, *, inside_loop: bool = False,
    module: ast.AST | None = None,
) -> bool:
    """Does this block leave only by raising?"""
    for statement in block:
        if _terminates(
            statement, bindings, inside_loop=inside_loop, module=module,
        ):
            return isinstance(statement, ast.Raise)
    return False


def _terminates(
    statement: ast.AST, bindings: dict, *, inside_loop: bool = False,
    module: ast.AST | None = None,
) -> bool:
    """Does control provably leave the block at this statement?

    Anything after an unconditional `return`, `raise`, `continue`, `break`, or
    `pytest.skip(...)` does not execute. The earlier screen looked only for
    `ast.Return` as the FIRST statement, so `pytest.skip(...)` followed by real
    assertions, and `if True: return` followed by real assertions, both counted
    the assertions below them.

    RECURSIVE THROUGH EVERY COMPOUND STATEMENT `executed_nodes` DISPATCHES, and
    using the same decisions. It used to recurse through `if` and `with` only,
    so `try: return / except Exception: pass` left the whole body below it dead
    and fully counted -- see `NON_TERMINATING_STATEMENTS` for what that cost.

    Only branches this module can DECIDE are followed; an undecidable `if` may
    fall through, so it never terminates.
    """
    if isinstance(statement, (ast.Return, ast.Raise)):
        return True
    if isinstance(statement, (ast.Continue, ast.Break)):
        # THESE LEAVE THE LOOP, NOT THE BLOCK AROUND IT.
        #
        # `inside_loop` is what tells the two apart, and getting it wrong cost
        # a real guard. When this screen learned to recurse through `for` and
        # `while` -- so that a loop whose body always returns could end a block
        # -- `break` and `continue` came along for the ride, and
        #
        #     while True:
        #         break
        #     assert real()
        #
        # was judged dead from the `assert` down. Python resumes on the next
        # statement after the loop; the assertion runs. That is the screen
        # FAILING A GENUINE GUARD, which the note at the top of this module
        # says it can never do -- so the note was false for three statement
        # types, in the direction that matters.
        return not inside_loop
    if isinstance(statement, ast.Expr) and (
        is_pytest_call(statement.value, "skip", module)
        or is_pytest_call(statement.value, "xfail", module)
    ):
        return True
    if isinstance(statement, ast.If):
        decided = fold(statement.test, bindings)
        if decided is UNDECIDED:
            # BOTH branches terminating is still termination, whatever the test.
            return bool(statement.orelse) and all(
                any(_terminates(inner, bindings, inside_loop=inside_loop, module=module)
                    for inner in branch)
                for branch in (statement.body, statement.orelse)
            )
        taken = statement.body if decided else statement.orelse
        return any(
            _terminates(inner, bindings, inside_loop=inside_loop, module=module)
            for inner in taken
        )
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        return any(
            _terminates(inner, bindings, inside_loop=inside_loop, module=module)
            for inner in statement.body
        )
    if isinstance(statement, TRY_NODES):
        # `finally` that leaves wins outright: it runs on every path.
        if any(
            _terminates(inner, bindings, inside_loop=inside_loop, module=module)
            for inner in statement.finalbody
        ):
            return True
        if not any(
            _terminates(inner, bindings, inside_loop=inside_loop, module=module)
            for inner in statement.body
        ):
            # A handler that returns only runs if something raised, so the
            # block may still fall through. `try: risky() / except: return`
            # must stay counted, and this is why.
            return False
        # The body leaves. Handlers cannot intercept a `return`, `break` or
        # `continue` -- only a `raise`.
        if _body_exit_is_an_exception(
            statement.body, bindings, inside_loop=inside_loop, module=module,
        ):
            return not _handlers_can_intercept(statement)
        return True
    if MATCH_NODE is not None and isinstance(statement, MATCH_NODE):
        # Only when some case is a catch-all, or nothing is guaranteed to run.
        exhaustive = any(
            isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None
            and case.guard is None
            for case in statement.cases
        )
        return exhaustive and all(
            any(_terminates(inner, bindings, inside_loop=inside_loop, module=module)
                for inner in case.body)
            for case in statement.cases
        )
    if isinstance(statement, ast.While):
        decided = fold(statement.test, bindings)
        if decided is UNDECIDED or not decided:
            return False
        # `inside_loop=True`: a `break` in here ends THIS loop and control
        # continues below it, so it cannot end the block this loop sits in.
        return any(
            _terminates(inner, bindings, inside_loop=True, module=module)
            for inner in statement.body
        )
    if isinstance(statement, (ast.For, ast.AsyncFor)):
        decided = fold(statement.iter, bindings)
        if decided is UNDECIDED or not _is_non_empty(decided):
            return False
        return any(
            _terminates(inner, bindings, inside_loop=True, module=module)
            for inner in statement.body
        )
    return False


#: Container constructors that pass their contents straight through.
#:
#: `except tuple([AssertionError]):` catches exactly what
#: `except AssertionError:` catches, and reads as neither.
_PASS_THROUGH = frozenset({"frozenset", "list", "set", "tuple"})


def denoted_names(expression, aliases: dict) -> set:
    """Every bare name this expression can denote, aliases resolved.

    THE SWALLOWING AXIS ASKED FOR A SPELLING, and this is what it should have
    asked. `SWALLOWING` lists three exception classes; the rule tested whether
    the handler type node was literally spelled one of them, so every one of
    these escaped it while catching exactly the same thing:

        _Err = AssertionError                      ... except _Err:
        from builtins import AssertionError as _E  ... except _E:
        _S = (AssertionError,)                     ... except _S:
        except tuple([AssertionError]):
        _Q = contextlib.suppress                   ... with _Q(AssertionError):
        from contextlib import suppress as quiet   ... with quiet(...):

    Measured end to end: one added line, `_Swallow = AssertionError`, wrapping a
    real audited guard body in `try: ... except _Swallow: pass` took its subject
    from 5 FAILED to 8 passed, with `exercised_assertions` reporting 1 both
    times.

    AN ATTRIBUTE IS NOT RESOLVED THROUGH THE BARE-NAME MAP, and the first
    version of this function did exactly that. `contextlib.suppress` denotes
    `suppress` whatever a module-level `suppress = _fallback` says, because the
    attribute is not that name. Reading it through the map -- with `.get(k,
    default)`, which REPLACES rather than widens -- let two lines that never
    touch a guard move `suppress` OUT of the set and make a real suppression
    invisible. Measured on three audited guards: pristine and gutted both
    reported the same count. That is the exact inverse of the direction this
    docstring claimed, so the claim is now the code: resolution here can only
    map a NAME to what it was bound to, and an attribute denotes itself.
    """
    if isinstance(expression, ast.Name):
        return aliases.get(expression.id, {expression.id})
    if isinstance(expression, ast.Attribute):
        # `x.suppress` denotes `suppress`. Not a bare name, so not the map's.
        return {expression.attr}
    if isinstance(expression, (ast.Tuple, ast.List, ast.Set)):
        found: set = set()
        for element in expression.elts:
            found |= denoted_names(element, aliases)
        return found
    if isinstance(expression, ast.Starred):
        return denoted_names(expression.value, aliases)
    if isinstance(expression, ast.Call):
        callee = expression.func
        named = (callee.attr if isinstance(callee, ast.Attribute)
                 else getattr(callee, "id", ""))
        if named in _PASS_THROUGH and len(expression.args) == 1:
            return denoted_names(expression.args[0], aliases)
    return set()


def _scope_aliases(nodes) -> tuple[dict, set]:
    """(name -> what it denotes, names too complicated to resolve) in ONE scope.

    Assignment and `import ... as` both bind a name to something with another
    name, and both are renames. Following only `ast.Assign` was a rule about
    one of the two spellings of the thing FG42 is about -- `_stored_names` in
    this same module already reads `ast.alias`, so the grammar was there and
    was not used.

    A name bound by anything else in this scope -- a loop target, a `with`
    target, an augmented assignment, a `global` -- is DISQUALIFIED rather than
    resolved, and keeps whatever it is spelled. Resolving it would be guessing
    which binding reached the handler, and guessing wrong in the direction that
    refuses a genuine guard is the failure this module's opening note forbids.
    That leaves an alias hidden behind such a binding unresolved, which is a
    disclosed residual, not a claim of completeness.
    """
    direct: dict = {}
    disqualified: set = set()
    for node in nodes:
        if isinstance(node, ast.Assign):
            targets = [t for t in node.targets if isinstance(t, ast.Name)]
            if len(targets) == len(node.targets):
                denoted = denoted_names(node.value, {})
                for target in targets:
                    if denoted:
                        direct.setdefault(target.id, set()).update(denoted)
                    else:
                        disqualified.add(target.id)
                continue
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                direct.setdefault(bound, set()).add(alias.name.split(".")[-1])
            continue
        disqualified |= bound_names(node)
    return direct, disqualified


def name_aliases(function: ast.AST, module: ast.AST | None = None) -> dict:
    """Names bound to other names, resolved to a fixed point.

    Deliberately NOT restricted to things that look like exception classes: the
    same map answers `_Q = contextlib.suppress`, and a rule that decided in
    advance which names were interesting would be one more rule about spelling.

    THE FUNCTION'S BINDINGS OVERRIDE THE MODULE'S, which is the scoping Python
    has. This docstring said so while the code UNIONED the two, so a guard that
    rebound a module alias locally --

        _E = AssertionError          (module)
        def guard():
            _E = ValueError          ... except _E: ...

    -- resolved `_E` to both, matched `AssertionError`, and the guard was
    reported as executing nothing. Measured: `exercised` 0, while running the
    function raises AssertionError. A live guard called dead, by the repair
    that closed the opposite hole in the same round.
    """
    module_direct, module_out = (
        _scope_aliases(module_scope_statements(module))
        if module is not None else ({}, set())
    )
    # STATEMENTS ONLY. `ast.walk` also yields the bare `ast.Name` nodes
    # inside a target, and `bound_names` on a Store-context name returns
    # that name -- so every local alias disqualified itself and none was
    # ever resolved. `module_scope_statements` already yields statements,
    # which is why the module side did not have this.
    local_direct, local_out = _scope_aliases(
        node for node in ast.walk(function) if isinstance(node, ast.stmt)
    )

    # A PARAMETER IS THE BINDING IN SCOPE, whatever the module says.
    #
    # `constant_bindings` learned this and said so; this function, added
    # later for the same scoping question, never read `function.args`.
    # Measured: module `_E = AssertionError` with `def guard(_E=ValueError)`
    # resolved `_E` to AssertionError, and a guard that really does raise
    # was reported as executing nothing -- the direction this module's
    # opening note forbids outright.
    arguments = getattr(function, "args", None)
    if isinstance(arguments, ast.arguments):
        for group in (arguments.posonlyargs, arguments.args,
                      arguments.kwonlyargs):
            for argument in group:
                local_out.add(argument.arg)
        for solo in (arguments.vararg, arguments.kwarg):
            if solo is not None:
                local_out.add(solo.arg)

    direct = {
        name: set(denoted) for name, denoted in module_direct.items()
        if name not in module_out
    }
    # LOCAL WINS OUTRIGHT -- replaced, not merged.
    for name in local_out:
        direct.pop(name, None)
    for name, denoted in local_direct.items():
        if name not in local_out:
            direct[name] = set(denoted)

    # CHAINS, to a fixed point. `_A = AssertionError; _B = _A` binds `_B` just
    # as surely, and bounded by the number of bindings so it terminates.
    for _ in range(len(direct) + 1):
        changed = False
        for name, denoted in direct.items():
            widened = set()
            for entry in denoted:
                widened |= direct.get(entry, {entry})
            if widened != denoted:
                direct[name] = widened
                changed = True
        if not changed:
            break
    return direct


def executed_nodes(function: ast.AST, module: ast.AST | None = None) -> list:
    """(node, swallowed) for every node the guard's own body actually runs.

    CONTAINMENT IS NOT EXECUTION, and `ast.walk` only answers containment.
    """
    bindings = constant_bindings(function, module)
    aliases = name_aliases(function, module)
    found: list = []

    def statements(block: list, swallowed: bool) -> None:
        for statement in block:
            visit(statement, swallowed)
            if _terminates(statement, bindings, module=module):
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
            isinstance(node, ast.Raise) or is_pytest_call(node, "fail", module)
            for node, _ in probe
        )

    def swallows(node: ast.Try) -> bool:
        for handler in node.handlers:
            caught = handler.type
            catches = caught is None or bool(
                denoted_names(caught, aliases) & SWALLOWING
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
            # THE CALLEE IS RESOLVED TOO. `_Q = contextlib.suppress`
            # then `with _Q(AssertionError):` suppresses exactly the
            # same way, and a check on the spelling never saw it.
            if "suppress" not in denoted_names(call.func, aliases):
                continue
            caught: set = set()
            for argument in call.args:
                caught |= denoted_names(argument, aliases)
            if caught & SWALLOWING:
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
            # `len()` ON A FOLDED NON-SEQUENCE RAISES, and this module's own
            # docstring says the screen "can never fail a genuine one". There
            # was a third outcome it did not admit to: crash. `for _ in rows`
            # where `rows` folds to None, an int, or a bool raised `TypeError`
            # straight out of the screen, so every consumer ERRORED rather than
            # reaching a verdict.
            if decided is UNDECIDED or _is_non_empty(decided):
                statements(node.body, swallowed)
            statements(node.orelse, swallowed)
            return
        if isinstance(node, TRY_NODES):
            # `ast.TryStar` IS A DIFFERENT NODE. `except*` arrived in 3.11 and
            # this dispatched on `ast.Try` alone, so an exception group handler
            # fell to the generic walk with `swallowed=False`:
            #
            #     try: assert real
            #     except* AssertionError: pass      counted 1, executes 0
            #
            # Measured end to end on a copy of a kill-bearing guard carrying 14
            # domain-collapse attacks: pristine 4, gutted 4, both audit guards
            # green. Nothing in the repository mentioned `TryStar` at all.
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
        if MATCH_NODE is not None and isinstance(node, MATCH_NODE):
            # EVERY CASE BODY WAS WALKED AS IF TAKEN. `match` arrived in 3.10
            # and had no dispatch, so it fell to the generic walk and a guard
            # whose assertions sit in an unreachable `case` counted them.
            #
            # A case is credited unless its pattern is one this module can
            # decide is unmatched -- which today means none of them, so every
            # case is credited and the subject expression is visited. That is
            # the permissive direction, and it is written down rather than
            # implied: what it closes is the `swallowed` flag being lost, not
            # pattern reachability.
            visit(node.subject, swallowed)
            for case in node.cases:
                statements(case.body, swallowed)
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


def exercised_assertions(function: ast.AST, module: ast.AST | None = None) -> int:
    """How many things this guard EXECUTES that can fail the test.

    THE ONE IMPLEMENTATION. Every consumer calls this; a second copy is refused
    by `test_no_module_reimplements_the_evidence_screen`, because the last
    three review rounds each found the rule repaired in one place and intact in
    another.
    """
    return sum(
        1
        for node, swallowed in executed_nodes(function, module)
        if not swallowed
        and (
            (isinstance(node, ast.Assert)
             and not cannot_fail(node.test, function, module))
            or isinstance(node, ast.Raise)
            or (isinstance(node, ast.withitem)
                and is_expected_refusal(node.context_expr, module))
            or is_pytest_call(node, "fail", module)
        )
    )
