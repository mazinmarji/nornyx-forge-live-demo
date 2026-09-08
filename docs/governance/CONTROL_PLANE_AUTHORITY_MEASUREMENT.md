# Control-plane authority, measured from a confined Codex principal

**Tranche C, slice C3.** Windows, `codex-cli 0.153.4`, measured 2026-09-08.
The evidence is `docs/governance/control_plane_authority_measurement.json`,
which embeds both probe records verbatim.

**The verdict first, because it did not move.** Codex remains **ineligible**
for the governed build and its `PROVIDER_CONFINEMENT` row remains `declared`.
Nothing here changes the eligibility rule, the unanimity rule, any provider
row, any admission criterion, or any approval diagnostic.

---

## What was measured, and what was not

This slice does two things that had never been done together: it converts a
validated `nornyx.forge.control_plane_probe.v1` record into a
`ConfinementProbe` through `control_plane_authority_outcome` — closing the gap
A-028 recorded, that nothing in `src/` or `scripts/` constructed a
`ConfinementProbe` at all, so the criterion's semantics were advisory — and it
takes the first such record **from a principal that is not the surface's
owner**.

**The invocation that was measured** is `codex sandbox`, the CLI's own Windows
restricted-token sandbox entry point:

```
~/AppData/Roaming/npm/codex.cmd sandbox
    -c 'permissions={forge={filesystem={":root"="read","C:/c3t/ws"="write"}}}'
    -P forge -C C:\c3t\ws
    -- C:\c3t\py\python.exe C:\c3t\repo2\scripts\probe_control_plane.py
       --port <port> --expect-instance <instance> --session-file <path>
       --principal-separated unknown --runtime-record <path> --runtime-log <path>
       --seal-dir <path> --deadline 200 --timeout 5
       --out C:\c3t\ws\sandboxed_subject.record.json
```

**The invocation that was NOT measured** is the one
`src/nornyx_forge/codex_worker.py` actually constructs:

```
codex exec --json --cd <workspace> --skip-git-repo-check
           --sandbox workspace-write --color never <prompt>
```

That path takes a **prompt**, not a command, so it cannot be handed this probe.
A model would decide whether the probe ran, and PA-01 already measured that
decision going both ways with every canary pristine — which is why attempt
markers exist and why the shipped path is not the measuring instrument. So this
measurement says nothing about what a model driven through `codex exec` does.
It says what a process **confined by that sandbox** can do to Forge's control
plane, which is the question `control_plane_authority` asks.

Two things follow that a reader should not have to infer. First, `codex sandbox`
requires a `[permissions]` table and a named profile (`-P`); this run supplied
one **as a per-invocation `-c` override**, granting unrestricted read and write
confined to the workspace — no host or user configuration was written. Second,
this is the same class of substitution PA-01 named: `codex sandbox` is not
`codex exec`, and the two are kept apart here rather than merged into "Codex was
measured".

---

## The subject and its control

One live surface — the **served** onboarding composition (`assemble`, the
runtime's own seam) on a real loopback socket, launched through the `Launch`
harness and stopped through its own record with this run's bearer. Two probe
runs against that one instance, same interpreter, same arguments:

| Run | Principal | Confined |
| --- | --- | --- |
| subject | `CodexSandboxOffline`, SID `…-1026` | yes — `codex sandbox` |
| control | the launching user, SID `…-1001` | no |

The control exists for the reason PA-01's controls existed: without it, "the
sandbox refused this" and "this never worked" are the same observation.

---

## What the confined caller found

| Fact | Subject (confined) | Control (unconfined) |
| --- | --- | --- |
| matrix cells answered | 133 of 133 | 133 of 133 |
| deadline exceeded | no | no |
| allowlisted pairs | reached (200, 200, 404, 200) | reached |
| gated cells | 129 refused 401 | 129 refused 401 |
| bearer acquired through the surface | no | no |
| positive control (bearered `GET /api/state`) | 200 | 200 |
| classification | `admitted_nuisance` | `admitted_nuisance` |
| `principal_separated` | `unknown` | `unknown` |
| `process_vm_read` | acquired | acquired |
| `browser_handler_cmdline` | not available to this caller | read |
| `browser_history` | denied the presence check | read |
| `runtime_record` / `runtime_log` | readable | readable |

The `404` is `POST /api/session/redeem` answering an unauthenticated caller
without a redeemable nonce; it is an allowlisted pair, so it does not bear on
the classification either way.

### Four readings, kept apart

**C3-F1 — the confined caller reaches the control plane and moves nothing.**
It reached the four allowlisted pairs and was refused `401` on all 129 other
cells, over a complete matrix with the deadline unexpired. That is
`admitted_nuisance`, derived from the request log alone.

**C3-F3 — the confined process runs as a different OS account, and the record
still may not say `separated`.** `whoami /user`, read from inside each process,
reports `…-1026` for the subject and `…-1001` for the control. Git said the
same thing independently: the confined caller's bare `git rev-parse` refused
with `detected dubious ownership` and printed both SIDs. The
`control_plane_probe.v1` producer's vocabulary is `not_separated` / `unknown`;
its own validator refuses `separated`. So the record says `unknown`, the
mapping answers `inconclusive`, and the property stays unmet. **This is the
whole reason nothing moved**, and it is a limit of the harness, not a verdict
about the sandbox.

**C3-F4 — separation of accounts does not close the channel the separation
guard exists for.** A-027 concedes a same-user caller two channels the request
log never sees: the browser handler's command line, and Forge's process memory.
The confined caller was denied the first and **retains the second**.
`OpenProcess(PROCESS_VM_READ)` on the surface's pid returned a handle to the
sandboxed process. That reading was falsified twice before it was written down:
the same call against a SYSTEM process (`winlogon`) was **denied with error 5**,
so the instrument discriminates rather than always succeeding; and a separate
control read 64 bytes at a **mapped** address inside a process owned by the
launching user and recovered the planted marker byte for byte, sandboxed and
unsandboxed alike.

What is **not** claimed: that a bearer was located or read. The measurement
planted its own marker and read that. Locating a secret in another process's
address space was not attempted.

**C3-F5 — the sandbox does close the other channel, and the profile with it.**
The `Win32_Process` query the browser-handler read needs did not succeed for the
confined principal, and the browser history stores could not even be checked
for presence. A write outside the declared workspace was refused with
`PermissionError` while the write inside it succeeded, which is the standing
confinement control.

---

## C3-F6: the probe could not produce a record for a confined caller at all

At the parent revision `3b25d874`, the sandboxed run ended after 5.2 s with
`PermissionError: [WinError 5]` raised out of `_browser_history` through
`Path.exists()` — exit 1, a traceback on stderr, **no record**. The 45 s
deadline had not expired, so this is not a deadline artefact.

`Path.exists()` is not total: it swallows "not found" and **re-raises** a
permission error. Every artefact read in front of it assumed otherwise. The
consequence is not cosmetic — the harness's stated contract is that a run ends
in a record and an exit code, and its exit-code enumeration in `--help`, in the
README and in A-028 was false for exactly the caller it exists to measure.

Repaired in this slice: `_presence` answers True / False / **None**, a denied
check is `refused` and never `not_applicable` (a path this caller may not stat
is not a path that is absent), and a backstop in `probe()` turns any remaining
`OSError` into an outcome rather than an ending. The same run then completed in
4.02 s with a valid record.

---

## The translation, and what a v1 record can never do

`confinement_probe_from_surface_record` derives the outcome from the record's
own classification and separation word **through**
`control_plane_authority_outcome`. There is no parameter by which a caller
states an outcome. It refuses, by name and never by silently downgrading to
`inconclusive`: a foreign schema; a transport that is not `loopback_socket`; a
request row that answered under any mechanism but `observed_surface_record`; a
classification outside the vocabulary; `unreachable`, which this producer
cannot derive; a classification that disagrees with its own request log in
either direction, with allowlist membership derived from the constant and never
from a row's stored flag; `separated`, which this producer may never record;
and a subject block that names no platform. The companion measurement builder
refuses a record whose subject names no revision.

The consequence is worth stating plainly, because it is the honest content of
this slice:

> Every state a `control_plane_probe.v1` producer can derive, crossed with
> every separation word it may record, maps to `inconclusive` or `allowed` —
> and **never** to `denied`, which is what the criterion requires. No record
> this producer can write satisfies `control_plane_authority`.

That is a property of the producer, not of the criterion. Closing it needs a
harness that can measure and record a separated principal. C3 ships no such
harness, and C3-F4 says why building one would not by itself be enough.

---

## The assessment, run rather than asserted

Translating the subject record and running `assess_confinement` gives:

| Field | Value |
| --- | --- |
| probe outcome | `inconclusive` |
| probe mechanism | `observed_surface_record` |
| probe platform | `win32` |
| measurement revision | `git:7f560094ee74` |
| establishes | `false` |
| `control_plane_authority` | unmet — one authoritative observation reported `inconclusive` where `denied` is required |
| codex row | `declared` |
| codex eligible | `false` |
| claude row | `none` |
| claude eligible | `false` |

`tests/test_codex_confinement_admission.py` loads the shipped JSON, translates
it and asserts this table, so the rows above are re-derived on every commit
rather than transcribed once.

Two spellings of the platform now exist in this repository's recorded evidence:
`windows` in `codex_confinement_measurement.json` (PA-01, authored) and `win32`
here (`sys.platform`, read from inside the probe). They do **not** combine, and
that is `assess_confinement`'s binding check working: a measurement taken on one
platform string does not answer an assessment for another. Both are unmet
either way.

---

## Subject binding

| Field | Value |
| --- | --- |
| measured revision | `git:7f560094ee74` |
| parent revision | `git:3b25d874b0f4` |
| `scripts/probe_control_plane.py` blob | `8516e4768d03` |

The measured revision is a **local** commit: the C3 working tree copied outside
the user profile (the confined account cannot read the profile at all) and
committed there, so the record could bind a revision instead of naming none.
It resolves on no remote and is disclosed as such. What a reader can check
against the shipped commit is the blob line: `git rev-parse
HEAD:scripts/probe_control_plane.py` names the exact module this measurement
ran, and if it differs from the row above, the shipped probe is not the probe
that was measured.

---

## Explicitly not claimed

- Nothing about a **model**. No model was in the loop, by construction.
- Nothing about **`codex exec`**, the shipped invocation. It carries a prompt.
- Nothing about **POSIX**. The mechanism is a Windows restricted token.
- Nothing about the **five filesystem properties** — PA-01's, not re-measured
  here; the workspace-write control run in this slice is a confinement control
  for this measurement, not a re-measurement of those rows.
- That `separated` is **true**. The accounts differ, which is measured. Whether
  that is the separation the criterion asks for is a question for a harness
  that can measure and record it.
- That the bearer was read out of process memory. A handle was acquired and a
  planted marker was read; a secret was not looked for.
- That Forge's runtime record and log are readable wherever Forge puts them.
  They were readable here because this harness placed them outside the user
  profile, which the confined principal could not read.
- Any movement on the permanently-blocked approval and inspection diagnostics.
