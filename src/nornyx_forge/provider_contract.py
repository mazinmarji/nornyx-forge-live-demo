"""The Forge Provider Contract: what an AI engineering provider is, as data.

WHAT THIS IS FOR. Forge is becoming usable through more than one AI provider,
and the differences between providers must never reach the things Forge means:
governance semantics, lifecycle position, evidence meaning, authority
boundaries, completion. This module is the seam. It defines, as data and typed
shapes, the whole of what Forge asks of a provider and the whole of what a
provider may answer — so a provider integrates by implementing THIS, and
everything above the seam is provider-blind by construction.

WHAT A PROVIDER MAY BE ASKED, in this slice: run one bounded engineering task
in a workspace and report what happened. That is deliberately the entire
surface. Providers do not see the capsule (content flows through the capsule's
own propose/confirm doors), do not see the Experience Contract (workflow
position moves only through its guards), and do not render governance. The
narrowness is the point: a seam this small can be conformance-tested, and a
second adapter has a page to implement rather than a product to reimplement.

FAILURE IS VOCABULARY, NOT PROSE. A provider run ends in exactly one of the
declared failure classes, derived deterministically from what happened —
never from how an adapter chose to phrase it. `unavailable` and `timeout`
keep the exact numeric conventions the existing Claude path has always used
(127 and 124, the shell's own), so wrapping it changes nothing observable.

NO EQUIVALENCE IS CLAIMED HERE. The contract makes provider equivalence
*testable*; it does not make it true. `PROVIDERS` names codex and claude
because the capsule already closed that set, but a name in the vocabulary is
not an adapter in the registry — and the registry refuses names it cannot
serve rather than pretending.

DECLARED IS NOT ELIGIBLE. A provider may be declared, registered, available
and selectable, and still not be eligible to execute on the GOVERNED
basic-user build. The governed path hands the provider a writable workspace
that holds Forge-owned authority state, and an independent review found
that a provider running as the same operating-system user with general
shell capability can replace that state and the anchor that validates it.
So the contract carries, as data, what Forge itself can ESTABLISH about each
adapter's confinement, and `governed_build_eligibility` decides from that
table alone -- never from the request, the capsule, the project directory,
or anything the provider says about itself. Today no adapter's confinement
is established: Claude runs with no filesystem confinement, and Codex's
workspace-write sandbox is a flag the adapter passes to a CLI, declared and
not independently established by Forge. Both are therefore ineligible, and
the governed build fails closed rather than executing either. That is a
deliberate outcome, not a gap in the table: promotion to "established"
requires Forge to verify a confinement, which is future work.

PURITY. `layer.domain`: no filesystem, no clock, no process. Validation and
normalization only; execution lives in adapters.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any, Mapping, Protocol, runtime_checkable

from .capsule import PROVIDERS, CapsuleValidationError

#: The closed failure vocabulary. An adapter maps what happened onto exactly
#: one of these; nothing downstream ever parses prose to learn what failed.
FAILURE_CLASSES = ("ok", "unavailable", "timeout", "error")

#: The numeric conventions the existing Claude path already uses — the shell's
#: own, kept so the contract wraps observed behaviour instead of changing it.
UNAVAILABLE_RETURNCODE = 127
TIMEOUT_RETURNCODE = 124

_ROLE = re.compile(r"^[A-Za-z][A-Za-z0-9 _-]{0,59}$")

#: What Forge can ESTABLISH about an adapter's confinement to the project
#: subject, as a closed vocabulary. `none`: general shell capability and no
#: filesystem confinement. `declared`: the adapter passes a confinement flag
#: to the provider's CLI, which Forge has not independently established.
#: `established`: Forge itself has verified the confinement. Eligibility for
#: the governed build requires `established`, and nothing reaches it today.
CONFINEMENT = ("none", "declared", "established")

#: The table the eligibility decision reads. One row per declared provider;
#: growing PROVIDERS without a row here is refused by the decision itself.
PROVIDER_CONFINEMENT: Mapping[str, str] = {
    "claude": "none",
    "codex": "declared",
}

_CONFINEMENT_REASON: Mapping[str, str] = {
    "none": (
        "runs with general shell capability and no filesystem confinement, as the "
        "same operating-system user that holds Forge's authority store and its seal"
    ),
    "declared": (
        "passes a workspace-write sandbox flag to its CLI, which is declared by the "
        "provider and not independently established by Forge"
    ),
    "established": "Forge has established that it is confined to the project subject",
}


class ProviderError(CapsuleValidationError):
    """A request the provider layer refuses. Nothing was executed."""


@dataclass(frozen=True)
class ProviderTask:
    """One bounded engineering task, provider-neutrally stated.

    The shape mirrors what the Claude path has always been given, because the
    contract exists to wrap observed behaviour: a role, a bounded goal, a
    workspace path, an allowlist of tools, and the two bounds. The workspace
    is a string here — the domain does not touch the filesystem; adapters
    resolve it.
    """

    role: str
    goal: str
    workspace: str
    allowed_tools: tuple[str, ...]
    max_turns: int = 30
    timeout_seconds: int = 900

    def validate(self) -> None:
        if not isinstance(self.role, str) or not _ROLE.match(self.role):
            raise ProviderError(f"task role {self.role!r} is not acceptable")
        if not isinstance(self.goal, str) or not self.goal.strip():
            raise ProviderError("task goal must be a non-empty string")
        if len(self.goal) > 8000:
            raise ProviderError("task goal exceeds 8000 characters")
        if not isinstance(self.workspace, str) or not self.workspace.strip():
            raise ProviderError("task workspace must be a non-empty path string")
        if not isinstance(self.allowed_tools, tuple) or not self.allowed_tools:
            raise ProviderError("allowed_tools must be a non-empty tuple")
        for tool in self.allowed_tools:
            if not isinstance(tool, str) or not tool.strip() or "," in tool:
                raise ProviderError(f"allowed tool {tool!r} is not acceptable")
        if not isinstance(self.max_turns, int) or not 1 <= self.max_turns <= 200:
            raise ProviderError("max_turns must be an int in 1..200")
        if not isinstance(self.timeout_seconds, int) or not 1 <= self.timeout_seconds <= 7200:
            raise ProviderError("timeout_seconds must be an int in 1..7200")


@dataclass(frozen=True)
class ProviderResult:
    """What one provider run reported, normalized — never improved.

    `success`, `returncode` and `output` are the adapter's raw observations
    passed through; `failure_class` is DERIVED from them by `classify_result`,
    the one deterministic mapping, so two adapters that observed the same
    events report the same class regardless of phrasing.
    """

    provider: str
    role: str
    goal: str
    success: bool
    output: str
    failure_class: str
    returncode: int
    session_id: str | None = None
    command: tuple[str, ...] = ()

    def validate(self) -> None:
        if self.provider not in PROVIDERS:
            raise ProviderError(f"provider {self.provider!r} is not one of {PROVIDERS}")
        if self.failure_class not in FAILURE_CLASSES:
            raise ProviderError(
                f"failure_class {self.failure_class!r} is not one of {FAILURE_CLASSES}"
            )
        if not isinstance(self.success, bool):
            raise ProviderError("success must be a bool")
        if self.success != (self.failure_class == "ok"):
            raise ProviderError(
                "success and failure_class disagree: success must be True exactly "
                "when the failure_class is 'ok'"
            )
        if not isinstance(self.returncode, int):
            raise ProviderError("returncode must be an int")
        if not isinstance(self.output, str):
            raise ProviderError("output must be a string")


@dataclass(frozen=True)
class GovernedEligibility:
    """The decision, as data: whether a declared provider may execute on the
    governed basic-user build, what Forge established about its confinement,
    and the reason in words a person can read."""

    provider: str
    eligible: bool
    confinement: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider, "eligible": self.eligible,
            "confinement": self.confinement, "reason": self.reason,
        }


def governed_build_eligibility(provider: str) -> GovernedEligibility:
    """THE eligibility decision for the governed build. Forge-owned and
    deterministic: it reads the confinement table and nothing else -- not the
    request, not the capsule, not the project directory, not the provider's
    own account of itself. A provider is eligible only when Forge has
    ESTABLISHED its confinement; a declared or absent confinement fails
    closed, and no other provider is tried in its place."""
    if provider not in PROVIDERS:
        raise ProviderError(f"provider {provider!r} is not one of {PROVIDERS}")
    confinement = PROVIDER_CONFINEMENT.get(provider)
    if confinement not in CONFINEMENT:
        raise ProviderError(
            f"provider {provider!r} has no confinement row; the table must cover "
            "every declared provider before eligibility can be decided"
        )
    eligible = confinement == "established"
    if eligible:
        reason = f"provider {provider!r} is eligible: {_CONFINEMENT_REASON[confinement]}"
    else:
        reason = (
            f"provider {provider!r} is declared but not eligible for the governed build: "
            f"it {_CONFINEMENT_REASON[confinement]}; the build is refused and no other "
            "provider is tried"
        )
    return GovernedEligibility(
        provider=provider, eligible=eligible, confinement=confinement, reason=reason,
    )


def classify_result(success: bool, returncode: int) -> str:
    """THE mapping from observation to vocabulary. One place, no phrasing.

    Kept deliberately dumb: the existing Claude path signals unavailability as
    127 and timeout as 124, and everything else nonzero is an error. An
    adapter with richer knowledge still routes through this so the vocabulary
    cannot fork per provider.
    """
    if success:
        return "ok"
    if returncode == UNAVAILABLE_RETURNCODE:
        return "unavailable"
    if returncode == TIMEOUT_RETURNCODE:
        return "timeout"
    return "error"


@runtime_checkable
class ProviderAdapter(Protocol):
    """The whole of what an adapter implements. A page, on purpose."""

    name: str

    def available(self) -> bool:
        """Can this provider be invoked here at all? Never raises."""
        ...

    def run_task(self, task: ProviderTask) -> ProviderResult:
        """Execute one validated task and report. Never raises for task
        failure — failure is a ProviderResult with its class; raising is
        reserved for contract violations (an invalid task)."""
        ...


def validate_adapter_identity(adapter: Any) -> None:
    """An adapter must be what it says: a declared provider name and the
    contract's surface. Called by the registry before an adapter is ever
    handed to a caller."""
    if not isinstance(adapter, ProviderAdapter):
        raise ProviderError(
            f"{type(adapter).__name__} does not implement the provider contract"
        )
    if adapter.name not in PROVIDERS:
        raise ProviderError(
            f"adapter name {adapter.name!r} is not a declared provider; the "
            f"declared set is {PROVIDERS} and growing it is a capsule diff"
        )


def result_from_worker(provider: str, worker_result: Mapping[str, Any] | Any) -> ProviderResult:
    """Normalize a worker-shaped result into the contract, verbatim.

    Accepts either the WorkerResult dataclass or its dict form, reads exactly
    the fields the existing Claude path has always produced, and passes them
    through: `success` stays the worker's own verdict, `output` is untouched,
    `returncode` is untouched, and the class is derived — never authored.

    Field access is static on purpose: a dataclass is converted through
    `dataclasses.asdict` and read as a mapping, because reflective access with
    computed names is a construct the architecture gate refuses outright —
    refusal being decidable where resolution is not.
    """
    if isinstance(worker_result, Mapping):
        fields: Mapping[str, Any] = worker_result
    elif is_dataclass(worker_result) and not isinstance(worker_result, type):
        fields = asdict(worker_result)
    else:
        raise ProviderError(
            "a worker result must be a mapping or a dataclass instance"
        )

    success = fields.get("success")
    returncode = fields.get("returncode", 0)
    if not isinstance(success, bool) or not isinstance(returncode, int):
        raise ProviderError("a worker result needs boolean success and int returncode")
    result = ProviderResult(
        provider=provider,
        role=str(fields.get("role", "")),
        goal=str(fields.get("goal", "")),
        success=success,
        output=str(fields.get("output", "")),
        failure_class=classify_result(success, returncode),
        returncode=returncode,
        session_id=fields.get("session_id"),
        command=tuple(fields.get("command", ()) or ()),
    )
    result.validate()
    return result
