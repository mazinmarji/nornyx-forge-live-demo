# Module acquisition: the root-cause matrix, and why the third repair is different

`docs/governance/CLOSURE_PROTOCOL.md` and the operating goal both forbid
repeating a repair strategy more than twice without new evidence. Static
enumeration of module-acquisition spellings has now been tried twice and failed
twice, so this records the matrix before anything else is changed.

## What was attempted, and what each attempt missed

| # | Head | Strategy | Closed | Reopened by |
|---|---|---|---|---|
| 1 | before `032ca63` | read `ast.Import`, `ast.ImportFrom`, and dynamic-import calls | the spelled `import`, `importlib.import_module`, `__import__` | `sys.modules["x"]` — a subscript, not a call |
| 2 | `035719d` | add `_sys_modules_target`: subscript and `.get`, `sys` under any alias, `modules` bound by import or assignment | the five spellings measured on `032ca63` | `vars(sys)['modules']`, `getattr(sys,'modules')`, `sys.__dict__['modules']`, `importlib.sys.modules`, `from sys import *`, `dict(sys.modules)`, `.copy()`, `__getitem__`, `.pop`/`.setdefault`, a `dict` subclass, a two-file re-export |
| 3 | this commit | **refuse the construct instead of resolving the target** | see below | disclosed below |

Attempts 1 and 2 are the same strategy: *decide which module this expression
yields, by recognising the shape of the expression*. Each closed the shapes a
reviewer had just used, and each was reopened by a shape nobody had used yet.

## The unchanged assumption

> That the set of expressions yielding a module object can be enumerated.

It cannot. `sys.modules` is an ordinary dict reachable through every reflection
primitive Python has, and any expression evaluating to it can be aliased,
copied, wrapped, or re-exported across files. A rule that resolves targets is
therefore always one spelling behind — which is AC01, the largest class in this
repository's own registry, and attempt 2 committed it while repairing AC04.

## The materially different mechanism

Stop asking *which module does this yield*. Ask *can this be resolved at all*,
and refuse it when it cannot.

The precedent is already in this file: `_computed_dynamic_imports` does not try
to guess what `import_module(name)` loads. It refuses, because "no declared
dependency graph can model a name assembled at runtime". That is the principle
generalised.

**The rule.** A governed first-party module may obtain a module namespace only
by a static `import`. These constructs are refused wherever they appear in
governed source, without resolving what they evaluate to:

    .modules attribute access, on any expression
    vars(...)
    __dict__ subscript
    getattr(...) with a non-literal name, or the literal "modules"
    star-import
    the globals, locals, eval, exec and __import__ builtins
      (named without call syntax here on purpose: this document is
       scanned for dynamic-execution patterns, and it should be)
    (importlib is NOT in this set -- see below)

Every one of the eleven bypasses in the table above touches at least one of
these **in governed source**, at the point where the module namespace first
enters the file — including the two-file re-export, which is refused in the file
that writes `MODMAP = sys.modules`, not in the file that reads it.

**THIS CLAIM WAS FALSE AND IS WITHDRAWN.** It read: *the refused set is a
property of the syntax being written, not of the value it produces; aliasing
does not help an attacker, because to alias `sys.modules` you must first
write `.modules`.*

You need not. `from sys import modules as _m` aliases the map with no
attribute access at all, and `_m.pop(...)`, `_m.setdefault(...)`,
`_m.__getitem__(...)`, `dict(_m)[...]` and `_m.copy()[...]` then fall between
the two analyses: not resolvable, and not refused. Two independent reviews
demonstrated it on the exact head, on the HTTP surface reaching the
governance domain -- the edge this checker annotates as refused
unconditionally, whatever the contract later says.

Further routes were demonstrated at the same head, each with
`exit=0, violations: []` and the module object confirmed live at runtime.

Each carries an **id**, and `tests/test_module_acquisition_limits.py` pins
exactly this set of ids -- compared in both directions, because the first
version of that file pinned five rows that were a DIFFERENT five: it split
`pkgutil`/`runpy` in two and omitted `inert-init` altogether, so closing that
route left every pinned row green while this document went on claiming a
limitation the code no longer had. That is the failure this table exists to
prevent, in the file that names it.

| id | route | why it is invisible |
|---|---|---|
| `func-globals` | `func.__globals__["subprocess"]` | the module dict under another attribute name |
| `inert-init` | an `__init__.py` classified inert | never scanned; the refusals run only over DECLARED modules |
| `subscript-callee` | `__builtins__["__import__"](...)` | a Subscript callee; the attribute form IS caught |
| `from-import-hop` | `from sys import modules as _m` then one hop | the alias writes no `.modules` attribute to key on |
| `pkgutil-resolve` | `pkgutil.resolve_name(...)` | outside the four-name importer list |
| `runpy-run-module` | `runpy.run_module(...)` | as above, by a different stdlib entry point |
| `inspect-getmodule` | `inspect.getmodule(...)` | as above, from an object rather than a name |

So this document no longer claims that a governed module acquires a module
only by static import. It claims exactly what the code does: **the constructs
listed above are refused where they appear in a DECLARED governed module, and
that set is not closed.**

`importlib` is NOT refused, and the list above said it was. A frozen specimen
-- `test_ordinary_module_use_is_not_refused[dynamic import of json]` --
REQUIRES `importlib.import_module('json')` to pass, because a literal dynamic
import is resolvable and is modelled as an ordinary edge. A document
contradicting the frozen corpus is AC03, in the file that names AC03.

## The decision taken

**The claim is narrowed. `check_architecture` stays static and
side-effect-free.**

The alternative -- importing governed modules to observe what they bound --
would decide the property, and would turn a gate that reads text into one
that executes it, bringing import side effects, ordering and third-party
code inside the control. That was rejected for v1.

So the five routes below are **disclosed limitations of a v1 claim**, not
open defects against it. `docs/ASSURANCE_BOUNDARY.md` states the non-claim,
and `architecture-check` in `architecture_governance.nyx` carries the scope
it verifies. No parser heuristic was added for any of them, deliberately:
each such heuristic is one more spelling in a set that cannot be closed, and
three attempts to close it are what produced this document.

They are pinned as **v1.1 research specimens** by
`tests/test_module_acquisition_limits.py`, which measures the CURRENT
behaviour and fails if it changes in either direction -- so a route that is
later closed forces this disclosure to be updated rather than leaving the
boundary claiming less than the code delivers.

## The classification

Three distinct approaches have failed. Per the operating goal's LOOP-ESCAPE
rule this is classified rather than attempted a fourth time:

**ARCHITECTURE_DECISION_REQUIRED.**

Not UNMEASURABLE. The property IS measurable, by a mechanism this gate does
not have: a governed module either holds a module object or it does not, and
that is observable by importing it in isolation and inspecting what it bound.
Every route above is visible to such an observation and invisible to a parser,
precisely because each reaches the object through an expression whose value is
known only at runtime.

Adopting that turns a gate that reads text into one that executes it, bringing
import side effects, ordering and third-party code inside the control. The
alternative is to narrow what Forge claims about this gate. Both are decisions
with consequences past this defect, and neither belongs to an autonomous run
inside a release freeze. Evidence preserved; open.

## The over-reach direction, measured

**This refuses nothing that is in the tree today.** Governed `src/` contains
zero `vars`, `globals`, `locals`, `eval`, `exec`, `__import__`,
`__subclasses__`, and zero `.modules` accesses. Its SIX `getattr` calls --
the count read five here until a review counted them -- all pass literal
names on dataclass instances and streams; its eight `__dict__` uses are all
`<dataclass>.__dict__` for serialisation and none is subscripted. `sys` is
used for `executable`, `stdout` and `stderr` only. Pinned by
`test_ordinary_reflection_on_ordinary_objects_is_not_refused`.

## What this still does not decide, stated rather than implied

- **A class, not a module.** `object.__subclasses__()` reaches `Popen` without
  touching a module namespace at all. Different acquisition route; refusing the
  class graph is a new product requirement and is filed for v1.1, not claimed
  here.
- **Values crossing a function boundary at runtime.** If a module object is
  passed in as an argument from outside governed source, no static rule sees it.
- **Third-party code.** The rule governs first-party modules the contract
  declares. It says nothing about what a dependency does internally.

The gate therefore claims exactly this and no more: *within governed
first-party source, a module namespace is acquired only by static import, and
every construct that could acquire one otherwise is refused unresolved.*
