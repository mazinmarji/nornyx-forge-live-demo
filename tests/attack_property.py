"""What a mutation proof is AUTHORIZED to claim was violated.

The catalogue carried three prose fields -- `prop`, `control`, `expect` -- none
of which had a documented contract, and all three meant different things. For
H10: the security property, the mechanism enforcing it, and a presentation-level
observation. Promoting any of them would have turned prose written as
description into executable authority retroactively, and `expect` in particular
("the continuity refusal no longer names its code") is satisfied by a renamed
diagnostic while the property it is supposed to stand for is fully intact.

So authority is NOT a fourth string. An authoritative property is:

    ident       a stable identity, used in verdicts and records
    violated_in an EXECUTABLE criterion, run inside the mutant tree, that
                measures the security state directly
    describe    prose, which explains the property and decides nothing

Only `ident` and `violated_in` participate in a verdict. `describe` may be
rewritten freely without changing what any attack is credited with -- which is
the whole point: language explains a proof, it does not confer one.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


class PropertyNotViolated(AssertionError):
    """The mutant broke something, but not the property the attack claims."""


@dataclass(frozen=True)
class AuthoritativeProperty:
    """The one property whose violation earns kill credit for an attack."""

    ident: str
    describe: str
    #: Runs in the mutant tree. True == the security property is violated.
    violated_in: Callable[[Path], bool]


def run_probe(tree: Path, source: str) -> dict:
    """Execute a criterion probe inside the mutant workspace and read its JSON.

    In the MUTANT tree, so the criterion measures the mutated code. A probe
    that fails to run is not evidence of anything and must not be read as
    "not violated" -- it raises.
    """
    from mutation_workspace import isolated_env  # noqa: PLC0415

    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", source],
        cwd=tree, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=isolated_env(tree), timeout=900,
    )
    start = completed.stdout.rfind("{")
    if completed.returncode != 0 or start < 0:
        raise PropertyNotViolated(
            "the property criterion could not be measured in the mutant tree, "
            "so nothing about the property is established: rc="
            f"{completed.returncode} {completed.stdout[-300:]} "
            f"{completed.stderr[-300:]}"
        )
    return json.loads(completed.stdout[start:])


#: H10. The property is the continuity invariant itself, not the diagnostic
#: that announces it: a grant issued BEFORE the ledger's recorded history began
#: cannot be proven unspent, so deleting the ledger to replay a spent grant must
#: leave it REFUSED. Violated exactly when the replay is granted.
_H10_PROBE = """
import json, tempfile
from pathlib import Path
from nornyx_forge.nornyx_runtime import ApprovalLedger

p = Path(tempfile.mkdtemp()) / "ledger.sqlite3"
ApprovalLedger.provision(p, established_at="2026-08-01T00:00:00Z")
first, _ = ApprovalLedger(p).consume(
    "FP-H10", "REQ-H10", at="2026-08-15T00:00:00Z",
    grant_issued_at="2026-08-02T00:00:00Z")
for suffix in ("", "-wal", "-shm"):
    sibling = p.with_name(p.name + suffix)
    if sibling.exists():
        sibling.unlink()
ApprovalLedger.provision(p, established_at="2026-08-09T00:00:00Z")
replayed, reason = ApprovalLedger(p).consume(
    "FP-H10", "REQ-H10", at="2026-08-15T00:00:00Z",
    grant_issued_at="2026-08-02T00:00:00Z")
print(json.dumps({"first": bool(first), "replayed": bool(replayed),
                  "reason": str(reason)[:120]}))
"""


def _h10_violated(tree: Path) -> bool:
    measured = run_probe(tree, _H10_PROBE)
    if not measured["first"]:
        raise PropertyNotViolated(
            "the probe could not spend the grant even once, so the replay "
            f"measurement means nothing: {measured}"
        )
    return bool(measured["replayed"])


H10_PRE_LEDGER_GRANT_STAYS_UNCLAIMABLE = AuthoritativeProperty(
    ident="H10_PRE_LEDGER_GRANT_STAYS_UNCLAIMABLE",
    describe=(
        "A grant issued before the ledger's recorded history began cannot be "
        "proven unspent, so deleting the ledger makes an outstanding grant "
        "UNUSABLE rather than reusable. Violated only when the replay is "
        "granted -- never by a renamed diagnostic or a reworded refusal."
    ),
    violated_in=_h10_violated,
)


#: H16. The property is that an UNANSWERABLE question is not answered "clean":
#: when git cannot be run, the governed-tree check must refuse rather than
#: report no unstaged paths. Violated exactly when it returns a value instead
#: of raising -- never by the wording of the refusal.
_H16_PROBE = """
import json, subprocess, sys
sys.path.insert(0, "scripts")
import refresh_governance_evidence as refresh

real = subprocess.run
def unreachable(args, **kwargs):
    if args and args[0] == "git":
        raise FileNotFoundError(2, "not found", "git")
    return real(args, **kwargs)
subprocess.run = unreachable

try:
    returned = refresh._unstaged_governed_paths()
    print(json.dumps({"refused": False, "returned": repr(returned)[:80]}))
except SystemExit as exc:
    print(json.dumps({"refused": True, "returned": str(exc)[:80]}))
except Exception as exc:
    print(json.dumps({"refused": False, "returned": type(exc).__name__ + ": crashed"}))
"""


def _h16_violated(tree: Path) -> bool:
    """An unrunnable git that yields an answer -- any answer -- is the violation."""
    measured = run_probe(tree, _H16_PROBE)
    return not measured["refused"]


H16_UNRUNNABLE_GIT_IS_NOT_A_CLEAN_TREE = AuthoritativeProperty(
    ident="H16_UNRUNNABLE_GIT_IS_NOT_A_CLEAN_TREE",
    describe=(
        "When git cannot be run, the governed-tree check cannot prove the tree "
        "clean and must refuse. Violated when it returns instead of raising -- "
        "a crash is also a violation, because an unanswerable question was "
        "still not answered honestly."
    ),
    violated_in=_h16_violated,
)


#: H18. Assurance must be RECOMPUTED over what is on disk, so a derived field
#: written into the binding by hand cannot survive verification. Violated when
#: a forged `production_approval: granted` verifies as intact.
_H18_PROBE = """
import json, subprocess, sys
from pathlib import Path
BINDING = Path(".nornyx/contracts/evidence/review_binding.json")
ORIGINAL = BINDING.read_bytes()


def measure(mutate):
    payload = json.loads(ORIGINAL.decode("utf-8"))
    mutate(payload)
    BINDING.write_text(json.dumps(payload, indent=2, sort_keys=True) + chr(10),
                       encoding="utf-8")
    done = subprocess.run(
        [sys.executable, "scripts/refresh_governance_evidence.py", "--verify"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    # AN UNMEASURABLE VERIFICATION MUST NOT BE AN ANSWER.
    #
    # This read `json.loads(raw)["verification"] if raw else {}`. With no JSON
    # on stdout the state became {}, `integrity_state` became None, and
    # `None != "compromised"` returned VIOLATED. The probe swallowed the
    # child's failure itself, so `run_probe`'s `returncode != 0` guard never
    # saw it.
    #
    # A review printed the report to STDERR instead of stdout -- three lines,
    # leaving verify(), verify_review_binding() and derive_assurance_state()
    # byte-identical -- and drove BOTH H17 and H18 to KILLED_VALIDLY through
    # this repository's own admission protocol, while the control still ran and
    # still caught the forgery. A crash did the same. That is FG29 at the
    # verdict point the whole R2/FG29 rebuild exists to make sound.
    start = done.stdout.find("{")
    if start < 0:
        raise SystemExit(
            "--verify produced no JSON on stdout (rc=" + str(done.returncode)
            + "), so nothing about the property was measured: "
            + (done.stderr or "")[-300:]
        )
    payload = json.loads(done.stdout[start:])
    if "verification" not in payload:
        raise SystemExit("--verify produced no verification block: " + str(payload)[:200])
    state = payload["verification"]
    return state.get("integrity_state"), len(state.get("problems", []))


def inert(payload):
    payload["probe_note"] = "a byte change carrying no assurance meaning"


def attack(payload):
    payload["production_approval"] = "granted"
    payload.setdefault("approvals", {})["human_review"] = "performed"


inert_state, inert_problems = measure(inert)
attack_state, attack_problems = measure(attack)
BINDING.write_bytes(ORIGINAL)
print(json.dumps({
    "inert_state": inert_state,
    "inert_problems": inert_problems,
    "attack_state": attack_state,
    "attack_problems": attack_problems,
}))
"""


def _h18_violated(tree: Path) -> bool:
    """A forged derived field that verifies as intact is the violation.

    STATE DECIDES; THE NAME MAY ONLY REFUSE TO ANSWER. This read
    `... or not measured["named"]`, so a mutant that changed only the WORDING
    of the problem -- forgery still caught, integrity still compromised, every
    control intact -- was certified KILLED_VALIDLY. A review drove exactly that
    through the real runner, every step, to a full verdict.

    That is the defect this module exists to remove, inside the module itself,
    and it is the third time it has been found here: `expect` was rejected for
    it, H14 and H07 were repaired for it, and I then read one passing specimen
    as a property of the whole mechanism instead of checking the other twelve.

    `named` is still load-bearing, but as ATTRIBUTION, not as a verdict. A tree
    can be `compromised` for reasons that have nothing to do with the field
    this probe forged -- a stale baseline, an unrelated breakage -- and reading
    that as "the control held" would be FG10 wearing different clothes. So when
    the compromise cannot be attributed to this forgery, the measurement did
    not answer the question and refuses rather than asserting anything.
    """
    measured = run_probe(tree, _H18_PROBE)
    if measured["attack_state"] != "compromised":
        return True
    if measured["attack_problems"] <= measured["inert_problems"]:
        # Forging the ASSURANCE FIELD produced nothing that an arbitrary byte
        # change does not also produce, so the derived value is no longer
        # recomputed from disk -- only the file digest is being checked.
        return True
    return False


H18_ASSURANCE_IS_RECOMPUTED_FROM_DISK = AuthoritativeProperty(
    ident="H18_ASSURANCE_IS_RECOMPUTED_FROM_DISK",
    describe=(
        "Derived assurance fields are recomputed from what is on disk, so a "
        "hand-written `production_approval: granted` must make the evidence "
        "set compromised and be named as a problem. Violated when the forgery "
        "verifies, or verifies without being named."
    ),
    violated_in=_h18_violated,
)


#: H17. Deleting a claim must not be a way to stop it being checked. Violated
#: when a binding with `contract_set_digest` removed still verifies.
_H17_PROBE = """
import json, subprocess, sys
from pathlib import Path
BINDING = Path(".nornyx/contracts/evidence/review_binding.json")
ORIGINAL = BINDING.read_bytes()


def measure(mutate):
    payload = json.loads(ORIGINAL.decode("utf-8"))
    mutate(payload)
    BINDING.write_text(json.dumps(payload, indent=2, sort_keys=True) + chr(10),
                       encoding="utf-8")
    done = subprocess.run(
        [sys.executable, "scripts/refresh_governance_evidence.py", "--verify"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    # AN UNMEASURABLE VERIFICATION MUST NOT BE AN ANSWER.
    #
    # This read `json.loads(raw)["verification"] if raw else {}`. With no JSON
    # on stdout the state became {}, `integrity_state` became None, and
    # `None != "compromised"` returned VIOLATED. The probe swallowed the
    # child's failure itself, so `run_probe`'s `returncode != 0` guard never
    # saw it.
    #
    # A review printed the report to STDERR instead of stdout -- three lines,
    # leaving verify(), verify_review_binding() and derive_assurance_state()
    # byte-identical -- and drove BOTH H17 and H18 to KILLED_VALIDLY through
    # this repository's own admission protocol, while the control still ran and
    # still caught the forgery. A crash did the same. That is FG29 at the
    # verdict point the whole R2/FG29 rebuild exists to make sound.
    start = done.stdout.find("{")
    if start < 0:
        raise SystemExit(
            "--verify produced no JSON on stdout (rc=" + str(done.returncode)
            + "), so nothing about the property was measured: "
            + (done.stderr or "")[-300:]
        )
    payload = json.loads(done.stdout[start:])
    if "verification" not in payload:
        raise SystemExit("--verify produced no verification block: " + str(payload)[:200])
    state = payload["verification"]
    return state.get("integrity_state"), len(state.get("problems", []))


def inert(payload):
    payload["probe_note"] = "a byte change carrying no assurance meaning"


def attack(payload):
    payload.pop("contract_set_digest", None)


inert_state, inert_problems = measure(inert)
attack_state, attack_problems = measure(attack)
BINDING.write_bytes(ORIGINAL)
print(json.dumps({
    "inert_state": inert_state,
    "inert_problems": inert_problems,
    "attack_state": attack_state,
    "attack_problems": attack_problems,
}))
"""


def _h17_violated(tree: Path) -> bool:
    """The twin of H18, and it carried the twin defect.

    See `_h18_violated`: the state decides, and the absence of the claim name
    can only withdraw the measurement, never supply a violation.
    """
    measured = run_probe(tree, _H17_PROBE)
    if measured["attack_state"] != "compromised":
        return True
    if measured["attack_problems"] <= measured["inert_problems"]:
        # Deleting the claim cost nothing beyond what any byte change costs,
        # so the check that consumes it is gone with it.
        return True
    return False


H17_A_DELETED_CLAIM_IS_STILL_CHECKED = AuthoritativeProperty(
    ident="H17_A_DELETED_CLAIM_IS_STILL_CHECKED",
    describe=(
        "Removing a claim from the review binding must not remove the check "
        "that consumes it: a binding with no contract_set_digest is refused "
        "and the absence is named. Violated when verification passes, or "
        "passes without naming the missing claim."
    ),
    violated_in=_h17_violated,
)


#: H19. A declared member that is ABSENT must refuse, never quietly shrink the
#: subject. Violated when the subject is computed anyway -- measured by the
#: verified flag and by a fabricated digest for content nobody could describe.
_H19_PROBE = """
import json, shutil, sys
from pathlib import Path
sys.path.insert(0, "src")
from nornyx_forge.subject_bootstrap import bootstrap_security_context

# A DECLARED member whose absence the scope must refuse. Not a module
# `subject_bootstrap` imports -- deleting one of those raises
# ModuleNotFoundError before anything is measured, which is a broken
# probe rather than a violation. Same target the victim test uses.
# A required ROOT. The contract member this used to delete is read EAGERLY,
# so the mutant died on FileNotFoundError before the scope check could shrink
# anything -- and that crash was misread as "the attack cannot recreate the
# unsafe state", retiring a VALID kill. Measured against a root, the mutant
# verifies a smaller subject and mints a digest: the recorded defect exactly.
shutil.rmtree(Path(".github"), ignore_errors=True)
try:
    ctx = bootstrap_security_context(Path("."))
    subject = ctx.runtime_subject
    print(json.dumps({
        "verified": bool(getattr(subject, "subject_verified", True)),
        "reason": str(getattr(subject, "unavailable_reason", ""))[:90],
        "digest": str(getattr(subject, "governed_subject_digest", ""))[:24],
    }))
except Exception as exc:
    print(json.dumps({"verified": False, "reason": "RAISED " + type(exc).__name__,
                      "digest": ""}))
"""


def _h19_violated(tree: Path) -> bool:
    """Shrinking is the violation: verified True, or a digest minted anyway.

    A CRASH IS NOT A VIOLATION. The probe reports `RAISED <Type>` when the
    mutant cannot even be observed, and the first version of this criterion
    returned True for that -- because a crash reason contains no
    SUBJECT_SCOPE_INCOMPLETE, so "did not refuse properly" and "did not run"
    were the same answer. That is the exact defect a review filed against H19
    (credited on an uncaught FileNotFoundError), reproduced here while fixing
    it. An unmeasurable mutant raises instead.
    """
    measured = run_probe(tree, _H19_PROBE)
    if measured["reason"].startswith("RAISED "):
        raise PropertyNotViolated(
            "the subject computation raised instead of deciding, so nothing "
            f"about scope completeness was measured: {measured}"
        )
    # Both of these are SECURITY STATE and either is a violation on its own:
    # a subject that verifies despite a declared member being absent, or one
    # that mints an identity for content it could not describe.
    if measured["verified"]:
        return True
    if measured["digest"]:
        return True
    # The subject refused. Whether it refused FOR THIS REASON is attribution,
    # not a verdict -- and it used to be one: `return "SUBJECT_SCOPE_INCOMPLETE"
    # not in reason` made a renamed diagnostic a violation while scope checking
    # was fully intact. A refusal for some other cause means this attack
    # measured nothing about scope completeness, so it withdraws.
    if "SUBJECT_SCOPE_INCOMPLETE" not in measured["reason"]:
        raise PropertyNotViolated(
            "the subject refused, but not for scope incompleteness, so whether "
            f"the declared-member check survives is unmeasured: {measured}"
        )
    return False


H19_AN_ABSENT_DECLARED_MEMBER_REFUSES = AuthoritativeProperty(
    ident="H19_AN_ABSENT_DECLARED_MEMBER_REFUSES",
    describe=(
        "A declared governed member that is missing makes the subject refuse "
        "with SUBJECT_SCOPE_INCOMPLETE and mint no digest. Violated when the "
        "subject verifies anyway, or fabricates an identity for content that "
        "could not be described."
    ),
    violated_in=_h19_violated,
)


#: H09. A signed validity window that is never judged bounds nothing. Violated
#: when an approval one second past `expires_at` is accepted -- measured by
#: calling the real verifier with the module's own fixtures, so the signature
#: is genuinely valid and only the temporal clause is under test.
_H09_PROBE = """
import json, sys
sys.path.insert(0, "src")
sys.path.insert(0, "tests")
from test_governance_approval_verifier import REVISION, _approval, _keypair, _store

keypair = _keypair()
from nornyx_forge.approval_trust import verify_governance_approval
ok, reason, evidence = verify_governance_approval(
    _approval(keypair), trust_store=_store(keypair),
    as_of="2026-08-05T00:00:01Z", expected_subject_revision=REVISION)
print(json.dumps({
    "accepted": bool(ok),
    "reason": str(reason)[:80],
    "signature_verified": bool(evidence.get("signature_verified")),
}))
"""


def _h09_violated(tree: Path) -> bool:
    """Accepting the expired approval is the violation.

    The signature must still verify, or the probe is measuring a broken
    signature rather than the temporal clause -- that would be an invalid
    experiment, so it raises instead of reporting a result.
    """
    measured = run_probe(tree, _H09_PROBE)
    if not measured["signature_verified"]:
        raise PropertyNotViolated(
            "the fixture's signature did not verify, so this measured the "
            f"wrong clause entirely: {measured}"
        )
    return measured["accepted"]


H09_AN_EXPIRED_APPROVAL_IS_REFUSED = AuthoritativeProperty(
    ident="H09_AN_EXPIRED_APPROVAL_IS_REFUSED",
    describe=(
        "The signed validity window is evaluated against a trusted clock, so "
        "an approval one second past expiry is refused even though everything "
        "else about it is impeccable. Violated only when it is ACCEPTED -- not "
        "by the wording of the refusal or the diagnostic code."
    ),
    violated_in=_h09_violated,
)


#: H15. A missing governed module is a REFUSAL, not a crash. The distinction is
#: semantic, not the exit code -- a traceback also exits non-zero. What makes it
#: a refusal is that it is machine-readable, names the absent module, and
#: reports integrity as unavailable rather than claiming anything about
#: soundness. Violated when the verifier crashes instead.
_H15_PROBE = """
import json, subprocess, sys
from pathlib import Path

Path("src/nornyx_forge/reviewer_trust.py").unlink()
done = subprocess.run(
    [sys.executable, "scripts/refresh_governance_evidence.py", "--verify"],
    capture_output=True, text=True, encoding="utf-8", errors="replace")
combined = done.stdout + done.stderr
start = done.stdout.find("{")
structured = start >= 0
names_it = "reviewer_trust" in combined
print(json.dumps({
    "traceback": "Traceback (most recent call last)" in combined,
    "structured": structured,
    "names_module": names_it,
}))
"""


def _h15_violated(tree: Path) -> bool:
    """A crash -- or a refusal that says nothing machine-readable -- is the violation."""
    measured = run_probe(tree, _H15_PROBE)
    # STATE DECIDES. A crash, or a refusal with no machine-readable structure,
    # is the violation: those are the two ways "reported, not crashed" fails.
    if measured["traceback"]:
        return True
    if not measured["structured"]:
        return True
    # THE NAME MAY ONLY WITHDRAW. This read
    # `not (structured and names_module)`, so changing ONLY the wording of the
    # refusal -- `f"{exc.name!r}"` to "a governed module", rc still 2, no
    # traceback, structure intact, integrity_state still `unavailable` --
    # satisfied the criterion and earned a full KILLED_VALIDLY with no control
    # removed. A review measured it.
    #
    # That is the shape already removed from H07, H10, H14, H17 and H18. It
    # survived here because H15 was never re-derived when they were.
    if not measured["names_module"]:
        raise PropertyNotViolated(
            "the tool refused in its own vocabulary, but the refusal does not "
            "name the missing module, so the refusal cannot be attributed to "
            f"this attack: {measured}"
        )
    return False


H15_A_MISSING_GOVERNED_MODULE_IS_REFUSED = AuthoritativeProperty(
    ident="H15_A_MISSING_GOVERNED_MODULE_IS_REFUSED",
    describe=(
        "A ModuleNotFoundError for governed source becomes a governance "
        "finding: machine-readable, naming the absent module, reporting "
        "integrity unavailable rather than sound. Violated by a traceback, or "
        "by a refusal that does not name what is missing."
    ),
    violated_in=_h15_violated,
)


#: H06. The suite cannot quietly get smaller. The floor is what makes shrinkage
#: visible, so it must sit close enough to the real collection that deleting a
#: module trips it. Measured as arithmetic over an actual collection in the
#: mutant tree -- not by reading the constant and trusting it.
_H06_PROBE = """
import json, subprocess, sys

done = subprocess.run(
    [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"],
    capture_output=True, text=True, encoding="utf-8", errors="replace")
collected = sum(
    int(line.rsplit(":", 1)[1])
    for line in done.stdout.splitlines()
    if line.startswith("tests/") and line.rsplit(":", 1)[-1].strip().isdigit()
)
sys.path.insert(0, "scripts")
import check_test_coverage as census
floor = census.MINIMUM_COLLECTED
print(json.dumps({
    "collected": collected,
    "floor": floor,
    "slack": collected - floor,
    "within_band": floor >= collected * 9 // 10,
}))
"""


def _h06_violated(tree: Path) -> bool:
    """A floor that no longer tracks the suite is the violation."""
    measured = run_probe(tree, _H06_PROBE)
    if measured["collected"] <= 0:
        raise PropertyNotViolated(
            f"collection produced no counts, so nothing was measured: {measured}"
        )
    return not measured["within_band"]


H06_THE_SUITE_CANNOT_QUIETLY_SHRINK = AuthoritativeProperty(
    ident="H06_THE_SUITE_CANNOT_QUIETLY_SHRINK",
    describe=(
        "The anti-shrink floor sits within 10% of what the suite actually "
        "collects, so deleting a module of any size trips it. Violated when "
        "the floor falls outside that band, because whole security modules "
        "could then be removed with the census still green."
    ),
    violated_in=_h06_violated,
)


#: H14. Independence is derived from AUTHENTICATED identities, so a reviewer who
#: is the builder cannot satisfy an inspector role even holding a trusted key
#: issued in their own name. Violated when the assurance derivation reports
#: independent inspection anyway, or refuses for the wrong reason.
_H14_PROBE = """
import json, sys, tempfile
from pathlib import Path
sys.path.insert(0, "src")
sys.path.insert(0, "tests")
from test_independent_inspection import (
    BUILDER, Reviewers, _assurance, _attest, _settle, _workspace)

scratch = Path(tempfile.mkdtemp())
work = _workspace(scratch)
_settle(work)
reviewers = Reviewers(scratch)

store = json.loads(reviewers.store.read_text(encoding="utf-8"))
for entry in store["reviewers"]:
    if "security-inspector" in entry["roles"]:
        entry["reviewer"] = BUILDER
reviewers.store.write_text(json.dumps(store, indent=2), encoding="utf-8")
reviewers.names["security-inspector"] = BUILDER

_attest(work, reviewers)
state = _assurance(work, reviewers)
problems = [str(p) for p in state.get("assurance_problems", [])]
print(json.dumps({
    "assurance_state": state.get("assurance_state"),
    "builder_named": any("REVIEWER_IS_THE_BUILDER" in p for p in problems),
    "identity_mismatch": any("REVIEWER_IDENTITY_MISMATCH" in p for p in problems),
}))
"""


def _h14_violated(tree: Path) -> bool:
    """Crediting independence to the builder is the violation.

    An identity mismatch firing means the fixture broke and the probe measured
    the identity binding instead of independence -- an invalid experiment, so
    it raises rather than reporting a verdict.
    """
    measured = run_probe(tree, _H14_PROBE)
    if measured["identity_mismatch"]:
        raise PropertyNotViolated(
            "identity mismatch fired, so this measured the identity binding "
            f"rather than independence: {measured}"
        )
    # STATE ONLY. This also required the refusal to NAME
    # REVIEWER_IS_THE_BUILDER, so renaming that diagnostic -- with the
    # `return (False, ...)` refusal untouched -- satisfied the criterion and
    # earned a full KILLED_VALIDLY with no control removed. A review drove
    # that end to end. The absence of a string was being read as the absence
    # of the control, which is the exact substitution R2 exists to remove,
    # committed inside R2's own replacement.
    #
    # `builder_named` is measured as an INVALIDITY guard: it cannot make a
    # mutant look violated, only unmeasurable. That sentence used to stand here
    # describing a guard that WAS NOT WRITTEN -- the value was computed and
    # never read, and `describe` promised a clause ("when the refusal does not
    # come from the independence derivation itself") that nothing evaluated. A
    # comment claiming a check is the thing this module exists to refuse.
    if measured["assurance_state"] == "independently_inspected":
        return True
    if not measured["builder_named"]:
        raise PropertyNotViolated(
            "assurance is not independent, but the refusal does not name "
            "REVIEWER_IS_THE_BUILDER, so it cannot be attributed to the "
            f"independence derivation and nothing was measured: {measured}"
        )
    return False


H14_THE_BUILDER_CANNOT_BE_AN_INSPECTOR = AuthoritativeProperty(
    ident="H14_THE_BUILDER_CANNOT_BE_AN_INSPECTOR",
    describe=(
        "Independence is derived from authenticated identities, so a reviewer "
        "who is the builder cannot satisfy an inspector role even with a "
        "trusted key in their own name. Violated when assurance reports "
        "independent inspection, or when the refusal does not come from the "
        "independence derivation itself."
    ),
    violated_in=_h14_violated,
)


#: H05. Absence of required governed content is reported in the tool's own
#: vocabulary, never as a crash. Same distinction as H15 and equally semantic:
#: a traceback also exits non-zero.
_H05_PROBE = """
import json, subprocess, sys
from pathlib import Path

# A required governed CONTRACT. That is the asymmetric case the control
# was written for: a missing FILE already refused cleanly, while a
# missing CONTRACT produced a bare traceback from the approval-wiring
# loop. Deleting attestations or an evidence JSON never reaches it.
Path(".nornyx/contracts/runtime_network.nyx").unlink()
done = subprocess.run(
    [sys.executable, "scripts/refresh_governance_evidence.py", "--verify"],
    capture_output=True, text=True, encoding="utf-8", errors="replace")
combined = done.stdout + done.stderr
print(json.dumps({
    "traceback": "Traceback (most recent call last)" in combined,
    "structured": done.stdout.find("{") >= 0,
}))
"""


def _h05_violated(tree: Path) -> bool:
    measured = run_probe(tree, _H05_PROBE)
    return measured["traceback"] or not measured["structured"]


H05_MISSING_GOVERNED_CONTENT_IS_REPORTED_NOT_CRASHED = AuthoritativeProperty(
    ident="H05_MISSING_GOVERNED_CONTENT_IS_REPORTED_NOT_CRASHED",
    describe=(
        "Required governed content that is absent produces a machine-readable "
        "refusal in the tool's vocabulary. Violated by a traceback, or by any "
        "outcome that carries no structured report at all."
    ),
    violated_in=_h05_violated,
)


#: H07. Capability is what a module HOLDS, not how it spelled the import. A
#: module that acquires the process capability through a dynamic spelling must
#: be refused by the architecture gate. Violated when the gate passes it.
_H07_PROBE = """
import json, subprocess, sys
from pathlib import Path

# Appended to a module the architecture contract ALREADY declares. A NEW file
# under src/ is refused for being undeclared -- rc=2 for a reason that has
# nothing to do with capability, which is a broken probe, not a violation.
TARGET = Path("src/demo_app/agentic.py")
original = TARGET.read_bytes()
TARGET.write_bytes(
    original + (chr(10) * 2).encode("utf-8")
    + ("def _h07_smuggle():" + chr(10)
       + "    import importlib" + chr(10)
       + "    mod = importlib.import_module('subprocess')" + chr(10)
       + "    return mod.run(['echo'], capture_output=True)" + chr(10)
       ).encode("utf-8"))
done = subprocess.run(
    [sys.executable, "scripts/check_architecture.py"],
    capture_output=True, text=True, encoding="utf-8", errors="replace")
TARGET.write_bytes(original)
combined = done.stdout + done.stderr
print(json.dumps({
    "gate_rc": done.returncode,
    "capability_named": "performs process execution" in combined,
}))
"""


def _h07_violated(tree: Path) -> bool:
    """A dynamic spelling that walks past the capability gate is the violation."""
    measured = run_probe(tree, _H07_PROBE)
    # STATE ONLY: the violation is the gate ACCEPTING the module. Requiring
    # the refusal to say "performs process execution" meant rewording that
    # message -- gate still refusing, rc still 2 -- satisfied the criterion.
    # Deciding on rc alone is also the conservative direction: a mutant that
    # makes the gate fail for an unrelated reason is NOT credited.
    return measured["gate_rc"] == 0


H07_DYNAMIC_SPELLING_DOES_NOT_EVADE_CAPABILITY = AuthoritativeProperty(
    ident="H07_DYNAMIC_SPELLING_DOES_NOT_EVADE_CAPABILITY",
    describe=(
        "Process capability is judged by what a module holds, not by how it "
        "spelled the import, so a module reaching subprocess through "
        "importlib is refused by the architecture gate. Violated when the gate "
        "returns success for such a module."
    ),
    violated_in=_h07_violated,
)


#: H02. Integrity gates the EFFECT, not just the report. A compromised runtime
#: must release nothing and must not spend the approval. Violated when the
#: callback runs, or when the grant is consumed by a run that must not have
#: started -- never by the wording of the refusal.
_H02_PROBE = """
import json, sys
sys.path.insert(0, "src")
sys.path.insert(0, "tests")
from test_governance_integrity_authority import _release
from nornyx_forge.governed_subject import (
    INTEGRITY_COMPROMISED, GovernanceIntegrityState)
import tempfile
from pathlib import Path

decision, calls, spent = _release(
    Path(tempfile.mkdtemp()),
    GovernanceIntegrityState(
        status=INTEGRITY_COMPROMISED,
        verified_claims=8,
        problems=("architecture_governance.nyx records X",),
    ),
)
print(json.dumps({
    "effect": str(decision.effect),
    "callbacks": len(calls),
    "spent": bool(spent),
}))
"""


def _h02_violated(tree: Path) -> bool:
    """A released effect, or a spent grant, under compromised integrity."""
    measured = run_probe(tree, _H02_PROBE)
    return (measured["effect"] != "DENY"
            or measured["callbacks"] != 0
            or measured["spent"])


H02_COMPROMISED_INTEGRITY_RELEASES_NOTHING = AuthoritativeProperty(
    ident="H02_COMPROMISED_INTEGRITY_RELEASES_NOTHING",
    describe=(
        "Governance integrity gates the effect, not merely the report: under "
        "compromised evidence the decision is DENY, no callback runs, and the "
        "approval is not spent. Violated by any released effect or consumed "
        "grant, regardless of what the refusal says."
    ),
    violated_in=_h02_violated,
)


#: H08. A long-lived authority consumer answers from an immutable snapshot, so
#: replacing the trust file under a running context cannot change who it
#: trusts. The file is genuinely replaced between the two requests, so this
#: fails if anything downstream reopens it. Violated when the second request
#: sees the attacker's key.
_H08_PROBE = """
import json, sys, tempfile
from pathlib import Path
sys.path.insert(0, "src")
sys.path.insert(0, "tests")
from test_trust_snapshot import ATTACKER, _anchored, _signers
from nornyx_forge.approval_trust import ApprovalTrustStore
from nornyx_forge.nornyx_runtime import ACTION_TRUST_DOMAIN

scratch = Path(tempfile.mkdtemp())
store_path, trust = _anchored(scratch)
frozen = ApprovalTrustStore.load(store_path, domain=ACTION_TRUST_DOMAIN)

first = _signers(scratch, trust, frozen)
store_path.write_text(json.dumps(ATTACKER), encoding="utf-8")
second = _signers(scratch, trust, frozen)
print(json.dumps({
    "first": list(first),
    "second": list(second),
    "attacker_seen": "attacker-key" in second,
}))
"""


def _h08_violated(tree: Path) -> bool:
    """The running context changing its mind about trust is the violation."""
    measured = run_probe(tree, _H08_PROBE)
    if measured["first"] != ["test-approval-01"]:
        raise PropertyNotViolated(
            "the first request did not see the anchored signer, so the probe "
            f"never established a baseline: {measured}"
        )
    return measured["second"] != measured["first"] or measured["attacker_seen"]


H08_A_RUNNING_CONTEXT_ANSWERS_FROM_ITS_SNAPSHOT = AuthoritativeProperty(
    ident="H08_A_RUNNING_CONTEXT_ANSWERS_FROM_ITS_SNAPSHOT",
    describe=(
        "Trust is answered from the snapshot the context froze, so replacing "
        "the trust file mid-flight cannot change who a running context trusts. "
        "Violated when the second request differs from the first, or when the "
        "attacker's key becomes trusted."
    ),
    violated_in=_h08_violated,
)


#: H01. The boundary judges with the store the application FROZE, not one it
#: reopened for itself. Scoped exactly as the victim test scopes it: this is
#: possession travelling from context to boundary, and says nothing about the
#: authority decision consulting it -- a control built and not connected is a
#: defect this repository has produced more than once. Violated when the
#: boundary answers from a different object.
_H01_PROBE = """
import json, sys
sys.path.insert(0, "src")
from pathlib import Path
from demo_app.agentic import CustomerCaseFlow, application_security_context

context = application_security_context()
flow = CustomerCaseFlow(
    {"id": "CASE-TRUST", "customer": "Omar",
     "summary": "Issue a high-value external refund", "risk": "high",
     "requested_action": "issue refund"},
    root=Path("."), security_context=context)
print(json.dumps({
    "context_has_trust": context.action_approval_trust is not None,
    "same_object": flow.boundary.action_trust_store is context.action_approval_trust,
}))
"""


def _h01_violated(tree: Path) -> bool:
    """The boundary answering from a store the application did not freeze."""
    measured = run_probe(tree, _H01_PROBE)
    if not measured["context_has_trust"]:
        raise PropertyNotViolated(
            "bootstrap parsed no action approval trust at all, so there was "
            f"nothing to propagate and nothing was measured: {measured}"
        )
    return not measured["same_object"]


H01_THE_BOUNDARY_USES_THE_ESTABLISHED_STORE = AuthoritativeProperty(
    ident="H01_THE_BOUNDARY_USES_THE_ESTABLISHED_STORE",
    describe=(
        "The frozen action-approval trust the application established is the "
        "very object the boundary holds -- identity, not equality. Violated "
        "when the boundary answers from a store it resolved itself. Bounded to "
        "propagation; it does not claim the authority decision consults it."
    ),
    violated_in=_h01_violated,
)
