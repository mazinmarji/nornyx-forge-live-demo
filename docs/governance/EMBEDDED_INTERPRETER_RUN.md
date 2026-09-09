# The embedded-interpreter run: performed, and what it measured

**Result: the operator act was PERFORMED. The bundle smoke's recorded result is
`fail`, and the failure is worth more than a green would have been.**

`A-023` recorded this act as `NOT PERFORMED`, because no embeddable archive is
supplied by the repository and the builder fetches none. The founder called for
the act; it was carried out on 2026-09-09 on one host. The machine record behind
every claim below — including the full revision it was taken at, which belongs
in the record rather than in prose that goes stale on the next commit — is
`embedded_interpreter_run.json`, beside this file.

**The two design properties are unchanged, and both are still true.** The
repository still supplies no embeddable archive: nothing was added to the tree,
in any form. The builder still fetches none: no downloading code was added to
`scripts/build_windows_bundle.py` or anywhere else, and the archive stayed an
operator input passed on the command line. What changed is only that the act has
now been done once, on a named host, with a named and digest-checked archive.

---

## The host, and the archive

| Fact | Value |
|---|---|
| Host | `LAPTOP-EMF4NEOK` |
| Operating system | Microsoft Windows 11 Home |
| Windows version | 10.0.22000, build 22000, UBR 2538 (21H2), 64-bit |
| Archive URL | `https://www.python.org/ftp/python/3.13.15/python-3.13.15-embed-amd64.zip` |
| Archive size | 11009825 bytes |
| Archive sha256 | `d1f04d990aee1253d8569e8e5104e30fa9f5fa830899f14843448872d936a2cf` |

**The digest checks, separated by what each one establishes.** Four of the five
hash the SAME LOCAL FILE: twice by this agent with two different
implementations, once more immediately before the second extraction, and once by
the script itself. Those four are SELF-CONSISTENCY checks. They establish that
the bytes did not change between the checks and that two implementations agree
on them, and four of them add very little over one — none of them says anything
about where the file came from.

The check that carries the provenance is the fifth, and it is the one this list
used to leave out. The digest above is character for character the SHA-256 that
python.org publishes for `python-3.13.15-embed-amd64.zip` on the 3.13.15 release
page, at the same URL the archive was taken from. That comparison was made
against the published page, and it matched. It is the only one of the five that
ties the local bytes to the publisher.

The script's own check was confirmed by reading the function rather than
assuming it from its name — `install_python` computes the digest over the WHOLE
archive and compares it *before* `zipfile.ZipFile` is opened, so an archive that
does not match is never read as a zip at all. That is a good property of the
script, and it is still a self-consistency check: it holds the build to the
digest the operator typed on the command line, not to the publisher's.

**The interpreter version, obtained from the interpreter and not from the
filename.** The extracted `python.exe` was executed and asked:

`3.13.15 (tags/v3.13.15:4061bc4, Aug  5 2026, 13:05:39) [MSC v.1944 64 bit (AMD64)]`
— `version_info` `(3, 13, 15, 'final', 0)`, cache tag `cpython-313`.

---

## Run 1, as prescribed: the build failed before the smoke could run

The build was driven by the prepared environment's CPython 3.12.10. It got as
far as writing the marker and the launcher, and then `verify_bundle` refused it:

`ModuleNotFoundError: No module named 'pydantic_core._pydantic_core'`

**The cause, measured rather than inferred.** The dependency closure carried
`_pydantic_core.cp312-win_amd64.pyd`, whose wheel records the tag
`cp312-cp312-win_amd64`. Across the whole closure: 75 extension modules tagged
`cp312`, none tagged `cp313`, none tagged `abi3`. CPython 3.13 will not load
them.

**What those counts count.** The 75 counts FILENAMES carrying `cp312`, over the
dependency closure the builder installed into the bundle — not over the
embeddable archive, whose own standard-library extensions live in
`<bundle>/python` and were never in it. The same pass also recorded a raw total
of 133 `.pyd`, printed beside the 75 with 58 unexplained between them. The run
never stated which population that 133 was over; it is the closure, settled by
elimination below rather than by a note taken at the time. The 58 are now
accounted for, by re-counting the same closure in the builder's own CPython
3.12.10 environment at this revision:

| Over the dependency closure | Count |
|---|---|
| `.pyd` files altogether | 134 |
| filename carries `cp312` | 76 |
| filename carries no tag at all | 58 |
| of those 58, from a wheel declaring `cp312-cp312-win_amd64` | 51 |
| of those 58, from a wheel declaring a stable-ABI tag (`cp38`–`cp311`+`abi3`) | 7 |

They are third-party extension modules whose wheels do not put the ABI tag in
the FILENAME — `_bcrypt.pyd`, `_rust.pyd`, `tokenizers.pyd`,
`onnxruntime_pybind11_state.pyd`, `win32ui.pyd` and the like. Each one was
traced to the distribution that ships it and to that distribution's declared
`WHEEL` tag; none was left unowned.

The tempting decomposition is the wrong one, and it was checked rather than
waved away. The archive itself was opened and its members counted: it ships
exactly 20 `.pyd`, all of them untagged standard-library extensions
(`_asyncio`, `_bz2`, `_ctypes`, `_decimal`, `_elementtree`, `_hashlib`, `_lzma`,
`_multiprocessing`, `_overlapped`, `_queue`, `_socket`, `_sqlite3`, `_ssl`,
`_uuid`, `_wmi`, `_zoneinfo`, `pyexpat`, `select`, `unicodedata`, `winsound`).
Reading the 58 as "20 from the archive plus 38 unexplained" would require the
closure to hold 113, and the closure holds 134. Not one of those 20 names
appears in the closure. The remainder is third-party, all of it.

Two things follow, and the second is the one that matters. This re-count gives
134 and 76 where the run gave 133 and 75, so it is within one on both rather
than identical — the same closure in the same builder environment, counted
again later, offered as the STRUCTURE of the remainder and not as run 1's own
numbers. And counting filename tags UNDERSTATES the mismatch: 51 of the 58 are
locked to CPython 3.12 exactly as the 76 are, and only 7 would have loaded on
3.13.15. Run 1's diagnosis is weaker than the truth, not stronger.

`install_dependencies` resolves the closure with the **builder's** interpreter
(`sys.executable`); `install_python` extracts an operator-supplied interpreter of
**any** version; and nothing in the script requires the two to agree.
`requires-python` admits both. So the mismatch is possible by construction, and
this host had no CPython 3.13 for the builder to be.

**The smoke never ran.** `main()` raises at `verify_bundle` before the `--smoke`
branch is reached, and no smoke report was produced. There is therefore no run-1
smoke verdict, and none is offered here.

The right reading of run 1 is that `verify_bundle` did its job: the bundle
refused to claim it could run, instead of shipping a folder that would fail
later in front of a person.

---

## Run 2, one variable changed: the build succeeded and the smoke failed

Recording only run 1 would invite a reader to conclude that the bundle design
cannot work, when what run 1 measured is that *this builder-and-archive pairing*
cannot. So the builder's minor version — one named variable — was changed and
nothing else. The new builder was the **same operator-supplied archive**, extracted
stock with its unmodified path file to a separate directory, so no new
third-party artifact entered the picture.

The build succeeded. `verify_bundle` passed: the bundle's own embedded
interpreter imported the package set and resolved the bundle root as its own.
The closure now carried 75 `cp313`-tagged extensions and no `cp312` ones — all
75 flipped with the one variable, which settles the cause in both directions.

Both runs' tag counts are filename counts over that same population, so the
comparison is like for like. What is NOT symmetric between them is the raw
`.pyd` total: it was recorded for run 1 and not for run 2, and the untagged
remainder was decomposed for run 1 only. The machine record says so on both
runs rather than printing the field for one and omitting it from the other in
silence.

**The runtime really started, on its own embedded interpreter.** These facts
were written by that process, not by a test double: mode `self_contained`,
interpreter `<bundle>/python/pythonw.exe`, runtime schema
`nornyx.forge.windows_runtime.v1`, instance `2c26fb79119ba24d3f1c9ef6edb4d9f2`,
port 56189, recorded as ready three seconds after it started.

Then the smoke hung, and its recorded result is `fail`.

### What the smoke measures, and what it recorded

`--smoke` runs the built folder's own `Forge.cmd` and derives `result` from the
observations it records, by one verdict function and from nothing else. Its rule
is *"pass only when every required observation was made once and succeeded"*,
over eight named observations. It recorded six failures.

**Five of those six are consequences of this agent terminating the runtime to
end an unbounded hang, and are not evidence about the routes.** Separating them
is the whole point of writing this section:

| Observation | Recorded | Whose consequence |
|---|---|---|
| `launcher` | failed — *"the launcher did not return within its timeout"* | genuine; this is the finding |
| `runtime_record` | succeeded | genuine — the real runtime recorded itself ready |
| `session_file` | succeeded | genuine — the bearer was written and read |
| `get /api/runtime` | failed — connection refused | this agent's termination |
| `get /api/state` | failed — connection refused | this agent's termination |
| `get /` | failed — connection refused | this agent's termination |
| `stop` | failed — connection refused | this agent's termination |
| `stopped` | failed — *"no stopped record within the wait"* | this agent's termination |

### The launcher hang, which is the real finding

The smoke did not terminate. It sat in its launcher step for about four and a
half minutes beyond its own 120-second timeout, and resumed only when the
detached runtime process was terminated.

What was observed while it hung: no `cmd.exe` child of the builder survived; the
runtime port was in `LISTEN` with no established connection, so no exchange was
in flight; the builder had accumulated 1.28 seconds of CPU, so it was blocked
rather than spinning. It resumed at the instant the detached `pythonw.exe` was
terminated, and then finished in exactly its 60-second stopped-record poll.

The mechanism: `_observe_launch` runs `subprocess.run([cmd.exe, /c, Forge.cmd,
...], capture_output=True, timeout=120)`, and `Forge.cmd` ends by detaching the
runtime with `start ""`. `start` creates that grandchild with handle inheritance
ON, so the grandchild is handed DUPLICATES of the parent's capture-pipe handles
at `CreateProcess` — at the instant it is created, and regardless of where its
own standard handles are afterwards pointed. `cmd.exe` exits at once; those
duplicates hold the pipes open; `subprocess.run` waits for an EOF that cannot
arrive, times out at 120 seconds, kills the already-dead `cmd.exe`, and then
blocks in its post-kill drain, which carries no timeout of its own. The
120-second bound does not bound it.

**The repair this implies is NOT "add stdio redirection to `Forge.cmd`".**
Redirection was tried on this host, and it does not work. Five arms were run
against the same detaching shape, each driven exactly as `_observe_launch`
drives it, with a 6-second driver timeout and an external 20-second bound. The
detached grandchild wrote its own pid and a per-arm token, so the only process
killed was one proved to be the harness's own.

| Arm | The launcher's last line, and what the driver held | Outcome |
|---|---|---|
| Z | no `start` at all; driver holds pipes | returned rc 0 at 0.06 s — a known-negative control, so the instrument is not reporting hangs by construction |
| A | `start "" …`, the shipped shape; driver holds pipes | HUNG. `TimeoutExpired` surfaced at 20.8 s, 1.14 s after the grandchild was killed |
| B | `start "" … >nul 2>&1`; driver holds pipes | STILL HUNG. Surfaced at 19.4 s, 0.16 s after the kill |
| D | `start "" /b … >nul 2>&1`; driver holds pipes | STILL HUNG. Surfaced at 20.1 s, 0.22 s after the kill |
| E | `start "" …` byte for byte as arm A; driver holds FILES | returned rc 0 at 0.08 s — no hang at all |

Redirecting the grandchild's own standard handles, with or without `/b`, changes
nothing, because the duplication has already happened by the time the grandchild
could redirect anything. Changing what the PARENT holds removes the hang
outright, on a launcher line identical to arm A's. So the repair belongs on the
driving side: **do not hold captured pipes across a detaching launcher.** Give
`subprocess.run` files or a null sink for this call, or create the pipes without
inheritance, or bound the post-kill drain. Editing `Forge.cmd` is the one thing
measured NOT to help.

> **This has since been repaired, and this section is kept as the record of the
> run that found it, not as a description of the current driver.** The repair
> took the first of those options — `_observe_launch` hands the launcher two
> files under its own scratch and reads its output back from them — because a
> null sink would have terminated while recording nothing about the launcher,
> non-inheriting pipes are not reachable through `subprocess`, and bounding the
> drain treats the symptom while leaving the pipes held. `Forge.cmd` was not
> touched. The hang was reproduced on the parent through this same command and
> archive before the change, bounded at 600 s with no report produced; after it,
> the same command exits 0 in 39.36 s and the recorded verdict is `pass`.
> `A-023` in `docs/requirements/ASSUMPTIONS.md` carries what that `pass` does
> and does not establish — in particular that the stop observation succeeds
> because `SMOKE_ACTOR` DECLARES `kind: "human"`, which the route checks and
> does not authenticate.

Stated at the strength each part was established. The causal observation — the
smoke resumed at that termination and at nothing else — is measured. The LOCUS
is measured too, by A, B and D against E above: it is the parent's handles, not
the grandchild's. The standard-library half is read at source — on Windows,
`subprocess.run`'s `TimeoutExpired` branch calls `process.kill()` and then
`process.communicate()` with NO timeout argument, which is the drain that
blocks. What was NOT done is enumerating the grandchild's handle table:
inheritable-handle duplication at `CreateProcess` is the explanation that fits
all five arms, and the duplicated handle itself was never observed directly.

**Why nothing caught this before.** `smoke_bundle` is exercised only against a
scripted runtime: `tests/test_windows_bundle.py` replaces
`builder.subprocess.run`, `builder._get` and `builder._post_json`, so no real
process is started and no real socket is opened. CI runs `scripts/smoke_http.py`,
a different instrument; no workflow runs `build_windows_bundle.py --smoke`. The
real path had therefore never been executed — which is exactly what
`NOT PERFORMED` was concealing. Both launcher templates use `start ""`, so the
mechanism is not peculiar to the self-contained bundle; only the self-contained
launcher was actually run here, so the developer launcher's behaviour under the
smoke is inferred and not measured.

---

## A separate probe, so the run says something about the routes

Because the smoke hung before reaching them, this agent exercised the three read
routes directly against the live embedded runtime, before terminating it. **This
is not the smoke's verdict and does not stand in for one**; the smoke's result
remains `fail`.

| Route | HTTP | Content type | Bytes | Also observed |
|---|---|---|---|---|
| `/api/runtime` | 200 | `application/json` | 542 | schema `nornyx.forge.windows_runtime.v1`; instance token equals the recorded runtime's |
| `/api/state` | 200 | `application/json` | 52 | `initialized` is `false` |
| `/` | 200 | `text/html; charset=utf-8` | 13793 | non-empty page |

## What was not measured, and why

The **stop route and the stopped record were not exercised**. That route refuses
any actor whose kind is not human, because stopping Forge is a person's act at
that computer. This agent is not a person and would not assert that it was, so
the call was not made. The smoke, which does assert that actor, hung before
reaching it.

The developer bundle's smoke was not run on this host. No second host was used.

## What this does NOT establish

It does not establish an installer, code signing, release publication,
auto-update, or a Windows service. It does not establish provider confinement or
provider admission, A-018, or R3 monotonic anchoring. It creates no approval, no
READY state, and no production-approval readiness; it advances no Experience
stage, validates no contract, and is not an inspection of anything. It is not a
passing bundle smoke — the recorded result on this run is `fail`. And it is one
host, one Windows build, one CPU architecture and one archive: not a matrix, and
no basis for a claim about any other machine.

This is operator evidence about a folder on one computer. It decides nothing
about any project's governance.
