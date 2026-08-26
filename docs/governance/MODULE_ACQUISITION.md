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
    importlib, in any form

Every one of the eleven bypasses in the table above touches at least one of
these **in governed source**, at the point where the module namespace first
enters the file — including the two-file re-export, which is refused in the file
that writes `MODMAP = sys.modules`, not in the file that reads it.

**Why this is decidable where the other was not.** The refused set is a property
of the *syntax being written*, not of the *value it produces*. Aliasing does not
help an attacker: to alias `sys.modules` you must first write `.modules`.

**Measured against the current tree, this refuses nothing that is there.**
Governed `src/` contains zero `vars`, `globals`, `locals`, `eval`, `exec`,
`__import__`, `importlib`, `__subclasses__`, and zero `.modules` accesses. Its
five `getattr` calls all pass literal names on dataclass instances and streams;
its eight `__dict__` uses are all `<dataclass>.__dict__` for serialisation and
none is subscripted. `sys` is used for `executable`, `stdout` and `stderr` only.

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
