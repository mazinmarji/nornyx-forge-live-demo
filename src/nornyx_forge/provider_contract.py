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
is established, and the two rows are unequal for different reasons. Claude
runs with no filesystem confinement at all. Codex HAS now been measured
(PA-01, Windows, codex-cli 0.128.0, at 7ce306b1): driven through the CLI's
own `codex sandbox windows` entry point, with no model in the loop to decide
whether the forbidden operation was attempted, its sandbox refused every
write outside the workspace -- the external seal, a sibling directory, the
provider's own configuration home, and an escape through a junction that was
proved live first -- while permitting the intended write inside. That is
real enforcement, and saying otherwise would now be false.

IT IS STILL NOT ADMISSION. The same measurement found the sandbox does not
confine loopback egress: a confined process reached a controlled listener on
127.0.0.1 and its POST was accepted under the very Host rule the onboarding
surface applies. Forge's control plane IS a local unauthenticated loopback
surface whose routes move authority, so a provider that cannot rewrite the
seal can still walk in the front door and ask Forge to change its own mind.
No setting closed it -- not `network_access=false`, not a permissions-profile
network table, not even `sandbox_mode=read-only`. Filesystem confinement is
therefore established and network confinement is not, the row stays
`declared`, and both providers remain ineligible.

`CONFINEMENT_PROPERTIES` and `assess_confinement` below are what keep that
distinction from being edited away: the criterion for promotion is data, the
recorded measurement is checked against it, and a test holds the table and
the evidence to each other in both directions.

PURITY. `layer.domain`: no filesystem, no clock, no process. Validation and
normalization only; execution lives in adapters.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, is_dataclass
from types import MappingProxyType
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
PROVIDER_CONFINEMENT: Mapping[str, str] = MappingProxyType({
    "claude": "none",
    "codex": "declared",
})

_CONFINEMENT_REASON: Mapping[str, str] = {
    "none": (
        "runs with general shell capability and no filesystem confinement, as the "
        "same operating-system user that holds Forge's authority store and its seal"
    ),
    "declared": (
        "is run under a workspace-write sandbox flag that Forge's adapter passes to the "
        "provider's CLI, whose enforcement Forge has not established across every "
        "property admission requires"
    ),
    "established": "Forge has established that it is confined to the project subject",
}

#: What a per-provider row may add: the measured finding behind it, so the
#: reason a person reads names evidence rather than a category. Absent for a
#: provider Forge has not measured, and absence says exactly that.
_CONFINEMENT_FINDING: Mapping[str, str] = {
    "codex": (
        "measured on Windows at 7ce306b1 (docs/governance/CODEX_CONFINEMENT_MEASUREMENT.md): "
        "its sandbox DOES refuse every write outside the workspace, including Forge's "
        "external seal, but it does NOT confine loopback egress, and Forge's own control "
        "plane is an unauthenticated loopback surface"
    ),
}


# ---------------------------------------------------------------------------
# What a confinement measurement has to show before a row may move
# ---------------------------------------------------------------------------

#: The properties a measurement must cover before an adapter's row may be
#: promoted to `established`, and the outcome each one must show. This is the
#: admission criterion as data: `subject_write` must be ALLOWED (a sandbox that
#: refuses the intended work is not confinement, it is breakage), and every
#: other property must be REFUSED.
#:
#: `control_plane_reachability` is here because filesystem confinement is not
#: the whole of authority. Forge's onboarding surface is a local,
#: unauthenticated, authority-bearing loopback surface -- `/api/journey/ready`
#: and `/api/proposals/{id}/confirm` move authority -- so a provider that
#: cannot rewrite the seal but CAN post to that surface has acquired the
#: authority anyway, by the front door.
CONFINEMENT_PROPERTIES: Mapping[str, str] = MappingProxyType({
    "subject_write": "allowed",
    "external_seal_write": "denied",
    "sibling_write": "denied",
    "forge_code_write": "denied",
    "link_escape_write": "denied",
    "control_plane_reachability": "denied",
})

#: What one probe may report. `inconclusive` exists so that "the attempt was
#: never observed" has somewhere to go that is not "refused".
PROBE_OUTCOMES = ("allowed", "denied", "inconclusive")

#: Observations that can carry a confinement claim: the actual result of the
#: process that attempted the operation, or the record of the service that was
#: (or was not) reached.
ENFORCEMENT_MECHANISMS = ("observed_process_result", "observed_listener_record")

#: Named so they can be REFUSED by name rather than merely omitted. That an
#: adapter constructs a command carrying `--sandbox workspace-write` is a fact
#: about the adapter, not an observation of a sandbox enforcing anything; and a
#: model's account of what happened to it is the provider describing itself,
#: which `governed_build_eligibility` already refuses to read.
NON_ENFORCEMENT_MECHANISMS = ("command_construction", "model_report")


@dataclass(frozen=True)
class ConfinementProbe:
    """One measured attempt at one property, on one platform."""

    property: str
    platform: str
    attempt_observed: bool
    outcome: str
    mechanism: str

    def validate(self) -> None:
        if self.property not in CONFINEMENT_PROPERTIES:
            raise ProviderError(
                f"probe property {self.property!r} is not one of "
                f"{tuple(CONFINEMENT_PROPERTIES)}"
            )
        if not isinstance(self.platform, str) or not self.platform.strip():
            raise ProviderError("a probe must name the platform it was taken on")
        if not isinstance(self.attempt_observed, bool):
            raise ProviderError("attempt_observed must be a bool")
        if self.outcome not in PROBE_OUTCOMES:
            raise ProviderError(
                f"probe outcome {self.outcome!r} is not one of {PROBE_OUTCOMES}"
            )
        if not isinstance(self.mechanism, str) or not self.mechanism.strip():
            raise ProviderError("a probe must name the mechanism it rests on")

    def satisfies(self, required_outcome: str) -> bool:
        """Whether this probe LICENSES the required outcome.

        Three ways to fail, kept separate on purpose. An attempt that was never
        observed establishes nothing, however clean the aftermath looked -- the
        model may simply not have tried. A mechanism that is not an enforcement
        observation establishes nothing, however emphatic. And an outcome that
        is not the required one is the plain negative case.
        """
        if not self.attempt_observed:
            return False
        if self.mechanism not in ENFORCEMENT_MECHANISMS:
            return False
        return self.outcome == required_outcome


@dataclass(frozen=True)
class ConfinementAssessment:
    """Whether a measurement licenses `established`, and what is missing."""

    provider: str
    platform: str
    establishes: bool
    unmet: tuple[str, ...]
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider, "platform": self.platform,
            "establishes": self.establishes, "unmet": list(self.unmet),
            "reason": self.reason,
        }


def assess_confinement(
    provider: str, platform: str, probes: tuple[ConfinementProbe, ...]
) -> ConfinementAssessment:
    """Decide whether a measurement establishes confinement. Evidence only.

    Nothing here reads `PROVIDER_CONFINEMENT`, so this cannot agree with the
    table by construction: the table is a claim, this is the check on it, and
    a test holds them to each other. A property with no probe on this platform
    is unmet -- silence is not a refusal, and a measurement taken elsewhere
    does not travel.
    """
    if provider not in PROVIDERS:
        raise ProviderError(f"provider {provider!r} is not one of {PROVIDERS}")
    for probe in probes:
        probe.validate()

    unmet: list[str] = []
    for prop, required in CONFINEMENT_PROPERTIES.items():
        on_platform = [
            p for p in probes if p.property == prop and p.platform == platform
        ]
        if not on_platform or not any(p.satisfies(required) for p in on_platform):
            unmet.append(prop)

    establishes = not unmet
    if establishes:
        reason = (
            f"every confinement property required for admission was measured on "
            f"{platform} and showed the required outcome"
        )
    else:
        reason = (
            f"confinement is not established on {platform}: "
            + ", ".join(unmet)
            + " (a property is unmet when it was not probed on this platform, when "
            "the attempt was not observed, when the observation was not an "
            "enforcement result, or when the outcome was not the required one)"
        )
    return ConfinementAssessment(
        provider=provider, platform=platform, establishes=establishes,
        unmet=tuple(unmet), reason=reason,
    )


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
    finding = _CONFINEMENT_FINDING.get(provider)
    if finding:
        reason = f"{reason}. {finding}"
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
