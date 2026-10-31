# Produced application contract

**Status:** design only. This document implements nothing and changes no
gate, no eligibility decision, no provider, no evidence requirement and no
runtime behaviour. Every statement about current behaviour cites the file and
line it was read from at main `a7b20f1`; everything else is a proposal for a
later cycle and is labelled as one. Where a fact could not be checked it is
marked NOT VERIFIED.

It stays a design until a real provider-produced build exists, and none can
exist today: no provider is eligible on any platform (A-051, "What it does NOT
establish" 3).

## 1. What exists today, and what is absent

Measured from code:

- **An entry point is named, not run.** `ENTRY_POINT = "app/__main__.py"`, a
  package run as `python -m app`, "checked only for being present and parsing"
  (`src/nornyx_forge/produced_app_manifest.py:75-77`). The dependency policy is
  the standard library only (`produced_app_manifest.py:79-80`). The static check
  refuses a missing entry point, imports outside the standard library, any
  import of Forge, and dynamic import or execution primitives
  (`produced_app_manifest.py:536-600`); it executes nothing
  (`produced_app_manifest.py:555-564`).
- **A sealed manifest names what an accepted build produced.** `render_pam`
  records the subject, the application files, the entry point and the runtime
  contract's digest (`produced_app_manifest.py:166-228`). In production it is
  issued only at the GOVERN transition of an accepted build
  (`src/nornyx_forge/onboarding_app.py:1086-1111`) and persisted only by
  `CapsuleStore.save_produced_application`
  (`src/nornyx_forge/capsule_store.py:1428-1440`). `issue_gate_manifest` also
  renders one, for a build that crossed the run-act gate
  (`src/nornyx_forge/gate_handoff.py:945-1050`, `render_pam` at `:1031`); it has
  no production caller (it is named only in its module's docstring and
  `__all__`, `gate_handoff.py:50`, `:1065`; A-055, "What it does NOT
  establish" 8).
- **A handoff gate exists and nothing calls it.** `assess_readiness` re-reads
  the files, re-runs the static check and asks the Provider Contract again
  (`src/nornyx_forge/produced_app_handoff.py:405-472`); a gated build is never
  offered (`produced_app_handoff.py:433-438`); `open_application_readiness`
  is the only production entry (`produced_app_handoff.py:475-480`). No module
  outside `produced_app_handoff.py` names either function (grep of
  `src/nornyx_forge`), and no route offers an application: the routes are
  listed at `onboarding_app.py:567-1227`. The gate starts the store's `git`:
  `assert_sealed` runs `git rev-parse HEAD` and `git status --porcelain`
  (`capsule_store.py:1834-1853`), as A-051 item 5 records.
- **A runtime operation contract is rendered, and it is empty.** The renderer
  takes declared operations by their exact registered spelling and copies every
  other field from the registry (`src/nornyx_forge/contract_generator.py:306-333`);
  an unregistered spelling is refused (`contract_generator.py:309-315`); a
  requirement the BRD does not have is refused (`contract_generator.py:316-320`).
  Disposition is `permitted` only for a low-risk capability outside the two
  always-refused consequences (`contract_generator.py:264`, `300-303`). The
  shipped build declares nothing, so the table is empty and every operation is
  refused (`contract_generator.py:246-250`; `src/nornyx_forge/development_flow.py:293-306`).
  The issuer renders the same empty table (`produced_app_handoff.py:251-262`).
- **The gated stage carries the same empty contract, with a prose
  instruction.** `stage_inputs` stages `contract/runtime-contract.json`
  (`gate_handoff.py:129`) rendered with no declarations (`gate_handoff.py:396-403`),
  and Forge's instructions tell the provider in prose to "Respect" it
  (`gate_handoff.py:149-153`). The stage is read-only and the provider writes
  only in its own run directory (`gate_handoff.py:146-147`).
- **The classification source is closed.** `OPERATION_REGISTRY` is a read-only
  table of eight exact spellings (`src/nornyx_forge/nornyx_runtime.py:557-583`);
  `classify_operation` refuses anything else with `UnknownOperation`
  (`nornyx_runtime.py:608-637`). Its own comment says a generated application
  does not inherit it as a runtime boundary (`nornyx_runtime.py:506-510`).
- **The contract is not part of a shipped build's application.** It is written
  to `.nornyx/generated/runtime-contract.json` (`contract_generator.py:259`), and
  `.nornyx` is a directory both the verifier and the manifest's reader skip
  (`src/nornyx_forge/greenfield_verifier.py:348-352`;
  `produced_app_handoff.py:79-82`). Only Forge's test specimen copies it into
  the application, as `app/runtime_contract.json`
  (`tests/runtime_boundary_specimen.py:276-289`), and only that specimen has an
  enforcement point (`tests/runtime_boundary_specimen.py:125-145`). That
  boundary is handed its table by its caller (`load_table(path)`, `:101`;
  `Boundary(table)`, `:128-129`) and trusts each entry's `disposition` (`:139`).
- **"Side-effect module" is a naming convention enforced for two kinds of
  effect.** The verifier refuses process, network and reflective capability
  outside the side-effect directories and suffixes
  (`greenfield_verifier.py:386-387`, `2030-2046`); an ordinary `os` import is
  allowed anywhere (`greenfield_verifier.py:461-466`). The verifier refuses
  `setattr` and `delattr` calls, plain and through `builtins`
  (`greenfield_verifier.py:487-511`, plain `setattr` at `:503`), not
  attribute assignment. It already refuses a set of interpreter-control
  attributes anywhere in the subject (`greenfield_verifier.py:513-542`,
  applied at `:1273-1277`); W8 below builds on that refusal.

Absent: (a) any way for a person to declare an operation, so a requirement
such as "the application must refuse to delete records without approval"
produces no table entry; (b) any check that a produced application carries the
contract or routes its acts through a boundary; (c) any surface that shows the
person what was produced. A-035 item 6 still holds: "no route or command opens
it" (`docs/requirements/ASSUMPTIONS.md:5109`).

## 2. The entry point

Proposed. The entry point stays a Forge constant and is never declared by the
provider: a provider-supplied command line is a free value of exactly the kind
the operation registry replaced.

1. **Layout, version 3 of the manifest.** `application.start` becomes a
   constant Forge writes: `{"argv": ["python", "-m", "app"], "working_directory":
   "project_root", "interface": "console"}`. `interface` is a closed vocabulary
   with one value in this design; `loopback_http` is reserved and not designed
   here (question 7).
2. **The composition root.** `app/__main__.py` defines a top-level function
   `build_boundary()` that takes no parameters at all -- none required, none
   optional, no `*args` or `**kwargs` -- and returns the boundary of section 3
   with the application's permitted acts registered in it. It calls `main()`
   only under `if __name__ == "__main__":`.
3. **What Forge checks, statically.** `static_findings` already runs in three
   places: at issue (`produced_app_handoff.py:331`), at the handoff gate
   (`produced_app_handoff.py:470`) and at gated issue (`gate_handoff.py:1002`).
   The rules W1-W9 of section 3.4 run beside it in the same three places.
   Nothing is run. Whether `python -m app` starts stays unchecked, as A-051
   records.
4. **Where it lives.** In the subject, under `app/`, so the files are covered
   by the manifest's per-file digests and the seal, unchanged in kind.

## 3. The runtime contract

### 3.1 Declaration: a person chooses, Forge never infers

Proposed. A new authoritative capsule field, `operations`, holds rows
`{"requirement": "RQ-<n>", "requirement_digest": "<sha256 of that row's
text>", "operation": "<exact registered spelling>"}`. It is proposed and
confirmed like `requirements`, through the closed field registry
(`src/nornyx_forge/capsule.py:246-258`), and refused at entry in plain language,
as A-048 refuses a requirement row. Refused: a spelling not in the registry
(with the registered list in the reason), a requirement that is not a confirmed
row, and an operation declared twice. The page offers a closed select of
registered spellings, never a text box.

Where the check lives. `capsule` is a pure domain component that depends on
nothing (`.nornyx/contracts/architecture_governance.nyx:514`, `:913`), so its
validator checks shape only. The registered-spelling refusal belongs in
`brd_authoring`'s entry refusal (`src/nornyx_forge/brd_authoring.py:432`), but
that module may not import the registry as declared today:
`module.brd_authoring` depends only on `module.project_capsule` and
`module.requirements_model` (`architecture_governance.nyx:1004-1008`), and
`contract_generator` is `module.contract_authoring`
(`architecture_governance.nyx:1107-1108`), which imports `yaml` and
`nornyx_runtime` (`contract_generator.py:9`, `:11`) -- dependencies a pure
domain component (`architecture_governance.nyx:744`) does not carry.
Recommended: `brd_authoring` holds a pinned copy of the registered spellings,
held equal to `OPERATION_REGISTRY`'s keys by a test, the pattern the manifest
uses for the verifier's identity (`produced_app_manifest.py:96-99`). The
alternative is that the implementing cycle declares the module dependency in
the architecture contract. Either way the renderer refuses the same spellings
again (`contract_generator.py:309-315`).

Requirement identity. Requirement numbers are reused: a new row takes the
smallest unused `RQ-<n>` (`brd_authoring.py:306-323`). So a declaration names
its row by identifier and by the digest of the row's text, and the derivation
refuses a declaration whose row is gone or whose text no longer has that
digest, naming the row. The mapping from `RQ-<n>` to `BRD-F-<nnn>` is
positional inside `brd_from_capsule`, which numbers the headings in row order
(`brd_authoring.py:111-113`); it is computed there, so the renderer still never
reads a requirement's title or statement (`contract_generator.py:240-244`). A
row whose prose says "delete" and which declares nothing contributes nothing
to the table; the page says, before scope confirmation, how many requirements
carry a declaration.

The development flow passes the confirmed declarations to
`generate_runtime_contract` and to the digest it records
(`development_flow.py:298-299`); the issuer renders with the same declarations
taken from the sealed capsule, whose chain tip the manifest already binds
(`produced_app_manifest.py:213`). The contract schema stays
`nornyx.forge.runtime_contract.v1` (`contract_generator.py:258`).

### 3.2 Classification: operation plus capability, never a label

Every consequence, risk, capability and disposition in an entry comes from
`OPERATION_REGISTRY` through the existing renderer; no field of a declaration
carries a risk word. `validate_runtime_contract` already refuses a contract
whose fields differ from the registry's (`contract_generator.py:397-441`).
The boundary of 3.3 does not read a disposition from any file: it derives it
from the entry's capability and consequence. Nothing in this design
reintroduces a caller-declared risk level. A-047's statement that its boundary
is not a validated runtime boundary for a generated application
(`docs/requirements/ASSUMPTIONS.md:7290-7294`) still stands: the template
boundary below is not one either.

### 3.3 The enforcement point and the refusal

Proposed. Forge, not the provider, writes three files into the workspace
before any worker runs, beside the files the flow already generates:

- `app/runtime_contract.json`: the renderer's exact text.
- `app/boundary.py`: a Forge template, standard library only.
- `tests/test_runtime_contract_conformance.py`: a Forge template, below.

The template boundary differs from the specimen's in four ways, each closing
a route by which a caller chose the decision:

1. `Boundary(acts)` takes the acts and nothing else. It loads
   `runtime_contract.json` from its own sibling path, with no path parameter,
   and accepts only the contract's exact shape.
2. It computes each entry's disposition itself -- permitted only when the
   capability is `execute_low_risk_action` and the consequence is not one of
   the two in `ALWAYS_REFUSED_CONSEQUENCES` (`contract_generator.py:264`) --
   and never reads the `disposition` field.
3. Construction refuses an act for an operation that is not a permitted entry,
   so the boundary holds no callable for a refused or unlisted operation.
4. It keeps its table and its permitted set immutable (a read-only mapping and
   a frozen set) under private names.

`perform(operation, **fields)` decides first and calls the registered act only
for a permitted entry. A refusal is `Refused(reason_code, reason)`, as in the
specimen (`tests/runtime_boundary_specimen.py:92-98`), with two codes:
`OPERATION_UNREGISTERED` for an operation the table does not list, and
`NO_APPROVAL_MECHANISM` for an entry that is not permitted
(`tests/runtime_boundary_specimen.py:131-144`). How the application shows a
refusal to its own user is the application's.

### 3.4 How Forge verifies the contract exists and is wired

Proposed: a pure function beside `static_findings`, over bytes. Each rule is a
finding, never an exception. Every import is resolved to its full module name
whatever its form -- `import app.x`, `import app.x as y`, `from app import x`,
`from app.x import y`, `from .x import y`, `from . import x` -- and every
callee and attribute base is resolved through those bindings, never matched by
its spelling alone.

- **W1** `app/runtime_contract.json` is byte for byte the text Forge renders
  for the accepted BRD and the sealed declarations.
- **W2** `app/boundary.py` and the conformance test are byte for byte Forge's
  templates.
- **W3** `app/__main__.py` imports `app.boundary` and defines
  `build_boundary` with no parameters, as in section 2.
- **W4** Outside `app/__main__.py`, `app/boundary.py` and `tests/`, no module
  imports a side-effect module, and no package `__init__.py` re-exports one.
- **W5** The application's non-test code holds exactly one call that resolves
  to `app.boundary.Boundary`; it is inside `build_boundary`; the name it is
  called through is bound by an import from `app.boundary` and never rebound
  in the module; every name bound from a side-effect module appears only
  inside its `acts` argument; and every key of that mapping is a string
  literal naming an entry the boundary will permit.
- **W6** Every string constant in non-test application code that equals a
  registered spelling names an operation the table lists.
- **W7** A side-effect module imports only the standard library, and nothing
  in it runs application code at import. Its top level holds only imports,
  function and class definitions, and assignments of literal constants; no
  function or class carries a decorator; every default value and every
  annotation is a literal; and a class body holds only function definitions
  and assignments of literal constants.
- **W8** Outside `app/boundary.py` and `tests/`, no attribute is stored to or
  deleted from a base that resolves to `app.boundary` or to `Boundary`; no
  attribute named like one of the template's private names is referenced on
  any object; and no literal `getattr` or `hasattr` member names one.
- **W9** No produced top-level module -- the first segment of a path, and
  under `src/` the second, as `_local_modules` computes them
  (`produced_app_manifest.py:514-523`) -- is named like a standard-library
  module. Today only shadowing `nornyx_forge` is refused
  (`produced_app_manifest.py:574-575`), and the executor puts the subject
  first on the import path (`greenfield_verifier.py:208`).

Executed evidence, with no new execution surface: the conformance test calls
`build_boundary()` and asserts that every table entry the boundary does not
permit, and every registered spelling outside the table, is refused with its
code, and that no act ran. It names operations only and carries no `BRD-`
string, so the traceability gate, which counts any such string in a test file
(`greenfield_verifier.py:2003`, `2081-2085`), still needs the provider's own
tests for every requirement; a permitted operation is not exercised by the
template and must be by those tests. It runs in the trusted executor at BUILD,
as every subject test does, under the existing network guard and count (A-053
item 6).

Limits, stated now. The rules are static and over the spellings and forms
they name; computation at run time is beyond them, as A-051 and A-053 already
record. Outside W1-W9 by name:

- standard-library file and operating-system effects in any module --
  `os.remove`, `shutil.rmtree`, `Path.unlink`, `open(..., "w")` -- since
  "side-effect module" is enforced only for process and network;
- any application file rewritten at run time before it is loaded --
  `app/runtime_contract.json`, `app/boundary.py`, or a module imported after
  the write. A rewritten contract alone cannot release a refused adapter,
  because W5 fixes the `acts` keys to permitted entries, but a rewritten
  module can do anything. While a subject's tests run, the executor already
  refuses writes outside its private temporary root
  (`greenfield_verifier.py:136-150`); nothing refuses them when the
  application runs;
- the import-time side effects of the standard-library modules W7 allows;
- in-process state changes, which delete records without any effect a static
  rule can name; the specimen's own deletion is in a plain module
  (`tests/runtime_boundary_specimen.py:181-182`);
- an act registered under a permitted spelling, which can do anything: a name
  binds nothing to behaviour (A-047, "What it does NOT establish" 2);
- a reference to a boundary attribute computed some other way than the
  spellings W8 names, and a native extension the subject ships.

The conformance test shows the boundary refuses; it does not show that the
application has no other path to an effect. Binding is not enforcement
(`docs/requirements/ASSUMPTIONS.md:8387`).

## 4. The access link at GOVERN and READY

Proposed.

1. **Computed on request, never on a state poll.** `/api/state` deliberately
   reads no disk while a build runs (`onboarding_app.py:598-603`), and the gate
   reads up to `MAX_TOTAL_BYTES` of produced files
   (`produced_app_handoff.py:86`), parses every Python file and starts the
   store's `git` (`capsule_store.py:1834-1853`). So readiness is computed only
   in a bearer-gated `GET /api/application`, which calls
   `open_application_readiness` and refuses while a build runs. It is computed
   in the composition, never in the journey: `produced_app_handoff` already
   depends on `experience_journey`
   (`.nornyx/contracts/architecture_governance.nyx:572`).
2. **What the journey shows.** A separate field, `application_check`, never
   an `actions` entry: every `actions` entry is derived from the contract's
   transition table (`src/nornyx_forge/experience_journey.py:840-842`), and
   checking the application is no transition. The field is `None` before
   GOVERN, a fixed line saying that readiness is checked on request from
   GOVERN onward, and that line plus the route to ask at READY. The journey
   reads nothing new (`experience_journey.py:830-836` is unchanged in what it
   takes).
3. **What the route returns.** `offered`, `reasons` (the gate's own words),
   `manifest` (`pam/<hex>`); and, only when offered, `start` (the constant of
   section 2), the table's operations with their requirement and the
   boundary's derived disposition, and a fixed claim limit.
4. **What opening does.** The page shows the project's path, the start
   command and the table. Forge starts nothing (question 5).
5. **Evidence that must exist first.** A sealed version-3 manifest; the gate's
   file re-read and static check, W1-W9 included, finding nothing; the
   Provider Contract's eligibility, both the row at issue and asked now
   (`produced_app_handoff.py:443-456`); READY recorded, which already needs
   `gate_results` and `governance_validation` (`src/nornyx_forge/experience.py:184`).
6. **What it must not claim.** Not deployment, not production approval, not
   an independent inspection -- the words READY already uses
   (`experience_journey.py:717-722`). Not that the application runs, not that
   it is confined to its contract or kept off the network when it runs, not
   that a permitted operation does what its name says, and not that anyone
   authenticated read it. The fixed text: "Forge sealed these files and found
   the runtime contract and its boundary in place. Forge has not run this
   application and does not confine it. This is not deployment, not production
   approval and not an independent inspection."

## 5. Evidence and gates

Proposed additions, each additive:

- Manifest version 3 (`nornyx.forge.produced_application_manifest.v3`):
  `application.start`, and `runtime_wiring` naming the three Forge-written
  files with their digests and the wiring rules' version. `validate_pam`
  refuses a contract-file digest that differs from `runtime_contract.digest`.
  Both `issue_manifest` and `issue_gate_manifest` render version 3.
- Rules W1-W9 in the three places `static_findings` runs. A build they find
  fault with is recorded exactly as before and gets no manifest, and
  `GET /api/build` says why, as A-051 item 3 does for the existing check.
- The conformance test, run by the existing executor under the existing
  test-execution gate.

A manifest sealed as version 2 stays readable by the store: `validate_pam`
runs at save (`capsule_store.py:1459`) and in the gate
(`produced_app_handoff.py:428`), not on the seal read. The gate then refuses it
with the schema reason, so it is not offered and the store is not reported
tampered.

Unchanged, and to be held unchanged by the tests of each stage: the verifier's
gates, profile and digest (version 5, `src/nornyx_forge/gates.py:25`) in stages
1-6; the closed evidence vocabulary (`experience.py:156-163`) and READY's
requirements (`experience.py:184`); eligibility, decided by
`governed_build_eligibility` alone; gated builds never offered; the network
guard; the registry, which is widened only by its own reviewed change. No new
lifecycle evidence kind is proposed.

## 6. Out of scope, and why

- **Provider execution.** No provider is eligible, and this design changes no
  eligibility row.
- **The runtime lock.** It is consulted by the demonstration's action
  boundary (`nornyx_runtime.py:3284`) and prepared by `nornyx-forge
  prepare-runtime` (`src/nornyx_forge/cli.py:108-113`); no build-path module
  consults it, and nothing here touches it.
- **Executing produced code outside the executor.** Forge starting `python -m
  app` would run provider-written code under the person's own account. It needs
  an execution context with its own observer (A-053, "What it does NOT
  establish" 1), which is a separate design.
- **An approval mechanism for a produced application.** None exists, so every
  consequential operation stays refused (`contract_generator.py:252-255`).
- **Release and deployment.** READY is a lifecycle record, not either.
- **Authenticating the human actor.** The surface admits a session holder,
  never a person (A-030); the link inherits that bound.
- **Carrying the three files through a gated stage** is stage 6, not stages
  1-5 (question 10). Until stage 6, a gated build lacks them, W1-W3 find it,
  and `issue_gate_manifest` issues nothing for it.

## 7. Staged implementation

Each stage is testable under simulation with the test-only simulated provider
and an injected eligibility verdict, as A-035 and A-051 already do, and each
holds that the production composition still offers nothing.

1. **Declarations.** Capsule field, entry refusal, page select, positional
   RQ-to-BRD mapping, flow and issuer rendering with declarations. Tests: an
   unregistered spelling, an unconfirmed requirement and a repeated operation
   are refused at proposal; a declaration whose row was removed, or whose text
   changed under a reused number, is refused at derivation; a prose row saying
   "delete" with no declaration yields the empty table; the flow's recorded
   digest equals the issuer's; the simulated journey with one declared refusal
   row reaches GOVERN with a non-empty table bound. Serves BRD-F-004 and A-047.
2. **Forge-written boundary, contract file and conformance test.** Tests: the
   files are written before any worker runs and equal their templates; the
   boundary template passes `static_findings` and the verifier's architecture
   gate; it permits only what it derives, ignores a forged `disposition`,
   takes no table or path, and refuses an act for a non-permitted operation at
   construction; the conformance test carries no `BRD-` string and fails when
   the boundary is weakened.
3. **Wiring rules W1-W9.** Tests: the updated specimen passes; and each of
   these is named: one byte changed in either file; `build_boundary` with a
   parameter or default; a second `Boundary(...)` call; a local alias or class
   named `Boundary`; an adapter imported outside the root by `from app import
   adapters`, by a relative import, or re-exported through `app/__init__.py`;
   an adapter name outside `acts`; a computed `acts` key; an unlisted registered
   spelling; in an adapter, top-level code, a store into another module, a
   decorator, a class body statement other than a definition or literal, and
   a non-literal default or annotation;
   `app.boundary.ALWAYS_REFUSED = frozenset()`, `Boundary.decide = ...` and a
   reference to a private boundary name; a top-level module named `json`. A
   whole-class challenge of alias and binding forms in the manner of
   `tests/network_class_challenge.py`.
4. **Manifest version 3 and the gate.** Tests: render and validate refuse a
   wiring digest that disagrees with the runtime contract's; the gate names a
   changed boundary file; a sealed version-2 manifest is not offered and the
   store is not tampered; `issue_gate_manifest` renders version 3; with
   production eligibility nothing is offered.
5. **The route and the journey.** Tests: `application_check` is present in
   every journey shape, offers the route only at READY, and adds nothing to
   `actions`; `/api/state` computes no readiness; `GET /api/application` refuses
   while a build runs and is offered only with an injected verdict; the
   claim-limit text passes `find_overclaims` (`tests/test_documented_claims.py`);
   the route and the panel start no process other than the store's `git`, and
   none on a produced file, recorded as A-051 item 5 records children.
6. **The gated stage.** Forge stages the three files and instructs the provider
   to copy them unchanged, as it instructs for `BRD.md` (`gate_handoff.py:154`);
   W1-W9 run at gated issue. Tests: a release that omits or alters one gets no
   manifest; the stage's runtime contract carries the declarations.

## 8. Open questions, each with a recommended answer

1. **Where do declarations live?** Recommended: the capsule's confirmed
   region, bound by the chain tip the scope binding and the manifest already
   carry. Not BRD markup, which would change the requirement-identity rule
   (A-045) that the verifier holds its own copy of
   (`greenfield_verifier.py:1336`).
2. **What of a requirement whose act the registry does not name** (deleting
   one record)? Recommended: allow declaring `execute_high_risk_action`
   (`nornyx_runtime.py:525`, refused), so it fails closed now; add specific
   operations later by a reviewed change to the registry.
3. **Forge-rendered boundary, or provider-written?** Recommended:
   Forge-rendered and byte-checked, so the decision logic is reviewed Forge
   code. This narrows A-051 item 6 ("Shipped Forge never generates it") for
   three template files, never for the application.
4. **Should a wiring finding fail the build?** Recommended: not at first; it
   withholds the manifest. A verifier gate, with a profile version change, is
   a later decision.
5. **Does opening start the application?** Recommended: no, until an
   observed execution context exists.
6. **GOVERN or READY?** Recommended: a line from GOVERN, the check offered
   only at READY, readiness computed only on request.
7. **Console or loopback HTTP?** Recommended: console only first; a server
   needs a bind policy and its socket under `adapters/`.
8. **Manifests sealed as version 2?** Recommended: leave them as the code
   already treats them -- readable, refused by the gate with its schema reason,
   never reported as tampering.
9. **How is the table keyed?** By operation (`contract_generator.py:336-358`):
   an operation serves one requirement, and a requirement may carry several
   operations. With question 2, only one requirement per build can use the
   `execute_high_risk_action` catch-all. Recommended: keep the keying for the
   first cycle and widen the registry rather than change the schema.
10. **The gated path?** Recommended: stage 6 as above, after stages 1-5, rather
    than leaving the gated stage on a prose instruction.

NOT VERIFIED: how the onboarding page renders the new journey field; and
whether any produced layout starts under `python -m app`, which nothing here
runs.
