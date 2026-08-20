"""Authentication for action-specific consequential approvals.

A review minted its own grant for ``wire $10,000,000 to attacker``, wrote
``approver_type: "human"`` into it, and the boundary released the effect. That
field was never evidence of anything: a grant cannot authenticate itself, any
more than a letter is signed by the sentence "this letter is genuine".

Authority now comes from a detached Ed25519 signature over the complete
canonical grant, verified against a trust store that lives **outside** the
governed repository. The direction matters:

    the grant says      "I am Mazin, operations_owner"
    the trust store says "this key belongs to Mazin, and may act as
                          operations_owner"

Only the second establishes authority. ``approver_type`` is retained as a claim
to be checked against the trusted record, never as security evidence.

SCOPE. This authenticates the Forge *action-specific* consequential approval
boundary. Nornyx network and architecture approval evidence retain their own,
separate assurance model; nothing here should be read as authenticating those.

WHY NOT A SHARED SECRET. An HMAC verifier holds the same key that creates
approvals, so the application could mint its own authority. Ed25519 gives
asymmetric verification with no certificate machinery: the verifier can check a
signature and cannot produce one.

WHY THE TRUST STORE IS EXTERNAL. Committing ``trusted_approvers.json`` into the
governed tree would make root authority editable by whoever edits the
repository — add a key, sign a grant with it, and the boundary agrees. The store
is therefore a runtime dependency supplied from outside: a path outside the
working tree locally, a read-only mount in a container.

WHERE SIGNING LIVES. Not here. The issuer-side utility is
``scripts/issue_action_approval.py``, which the Dockerfile does not copy into the
image. The property being protected is not "this module has no signer" but that
the verifier *process* cannot mint the artifact it accepts — a signer kept in the
package with a comment saying not to call it would leave that resting on nobody
calling it.

WHEN TRUST IS RESOLVED. Once, at startup, into an immutable
:class:`ApprovalTrustStore` that is then injected. Resolving the location per
decision would make the environment an ambient selector of the root of trust:
set a variable between two authorization calls and the second answers to a
different authority. Loading once means an action request cannot alter trust,
and a variable changed after startup has no effect at all.

The environment variable therefore remains a *deployment-time bootstrap*
mechanism. Control of process startup configuration is part of the trusted
deployment boundary, which is a materially narrower claim than saying the
environment is trusted during runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any

#: Where the trusted signer keys are read from. A location, never authority:
#: pointing this elsewhere selects a store, it cannot create a trusted key.
#: The only signer status that can authorize. Named once so the report and
#: the authenticator cannot drift onto different rules.
ACTIVE_SIGNER_STATUS = "active"

TRUST_STORE_ENV = "FORGE_APPROVER_TRUST_STORE"

#: Default location, deliberately outside any repository working tree.
DEFAULT_TRUST_STORE = Path.home() / ".nornyx-forge" / "trusted_approvers.json"

#: The fields a signature covers. Signing only the request digest would leave
#: the role, the window, the approver and the decision itself free to change
#: under a still-valid signature.
SIGNED_FIELDS = (
    "schema",
    "approval_id",
    "request_digest",
    "approver",
    "approver_role",
    "signer_key_id",
    "generated_at",
    "expires_at",
    "granted",
)

APPROVAL_SCHEMA = "nornyx.forge.action_approval.v1"

#: A governance approval is a different statement from an action approval, so it
#: is a different signed payload. An action approval says "this specific effect
#: may be released"; a governance approval says "this governed content is
#: approved". Signing one set of fields and checking the other would authenticate
#: nothing, which is how a verifier built for grants came to be pointed at
#: approval records during remediation — caught before it shipped, and the reason
#: these are separate rather than shared.
GOVERNANCE_APPROVAL_SCHEMA = "nornyx.forge.human_approval_record.v1"

#: Total and ordered, like SIGNED_FIELDS. `subject_revision` is here because an
#: approval of different content is a different approval; the window bounds are
#: here because an approval that can be re-dated is not bounded.
GOVERNANCE_SIGNED_FIELDS = (
    "schema",
    "approval",
    "status",
    "subject_revision",
    "generated_at",
    "expires_at",
    "producer_id",
    "signer_key_id",
)


def canonical_governance_payload(approval: "Mapping[str, Any]") -> bytes:
    """The exact bytes a human approver's signature covers.

    `producer_id` is flattened out of the nested `producer` object so the signed
    material is a flat, totally-ordered mapping — a nested structure invites two
    encoders that disagree, and a signature is only as good as the agreement
    about what was signed.
    """
    producer = approval.get("producer")
    material: dict[str, Any] = {}
    for field_name in GOVERNANCE_SIGNED_FIELDS:
        if field_name == "producer_id":
            material[field_name] = (
                producer.get("id") if isinstance(producer, Mapping) else None
            )
        else:
            material[field_name] = approval.get(field_name)
    return json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: The two authority domains, named so a refusal can say WHICH store did not
#: hold a key. "Unknown key" and "known key, wrong domain" send an operator in
#: opposite directions, and only one of them is a provisioning error.
GOVERNANCE_TRUST_DOMAIN = "governance"
ACTION_TRUST_DOMAIN = "action"

#: Roles a key may hold to approve GOVERNED CONTENT.
#:
#: These vocabularies are NOT disjoint, and a comment here used to claim they
#: were -- that a shared vocabulary "would let one key do both by accident", as
#: though the separation rested on the role names. It does not, and it must not:
#: `network_governance_owner` appears in this set and in ACTION_APPROVER_ROLES,
#: which is a legitimate operational fact rather than a defect to rename away.
#:
#: THE REAL INVARIANT. Authority requires BOTH clauses:
#:
#:     membership in the trust domain for THIS authority
#:     AND a role valid for THIS authority
#:
#: so the same principal, holding the same role name, resolves differently by
#: where it is provisioned:
#:
#:     network_governance_owner, trusted in governance only -> governance ALLOW,
#:                                                             action REFUSE
#:     network_governance_owner, trusted in action only     -> action ALLOW,
#:                                                             governance REFUSE
#:     network_governance_owner, trusted in both            -> both, deliberately
#:
#: A shared role name therefore bridges nothing. Renaming the role to make the
#: sets look disjoint would have removed the evidence for that property while
#: leaving the property itself unproven.
GOVERNANCE_APPROVER_ROLES = frozenset(
    {"network_governance_owner", "architecture_reviewer"}
)



#: Temporal refusals, distinct because the operator response differs: an expired
#: approval needs a new decision, an unreadable one needs a corrected artifact,
#: and an invalid window means the issuing tool is wrong.
APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
APPROVAL_NOT_YET_VALID = "APPROVAL_NOT_YET_VALID"
APPROVAL_TIME_UNREADABLE = "APPROVAL_TIME_UNREADABLE"
APPROVAL_WINDOW_INVALID = "APPROVAL_WINDOW_INVALID"

#: The same seven-day cap the agentic-network module applies to action approvals.
#: A governance approval that outlived it would be a standing authorisation.
GOVERNANCE_APPROVAL_MAX_AGE = timedelta(days=7)


def _aware_instant(value: object) -> datetime | None:
    """Parse to an aware UTC instant, or None when it cannot be read.

    Never a string comparison. `2026-08-10T23:00:00+02:00` is 21:00Z -- earlier
    than `2026-08-10T22:00:00Z` -- but sorts after it as text, so lexical
    comparison gets the dangerous direction wrong. A naive stamp has no instant
    at all, and guessing a zone would decide validity by assumption.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def verify_governance_approval(
    approval: "Mapping[str, Any] | None",
    *,
    trust_store: "ApprovalTrustStore | None" = None,
    as_of: str,
) -> "AuthorityDecision":
    """Decide whether GOVERNANCE authority was granted over the named subject.

    THE AUTHORITY EQUATION, with no clause standing in for another:

        cryptographic authentication of a trusted human key
        AND membership in the GOVERNANCE trust domain
        AND a role valid for governance approval
        AND that domain trusting this key to claim that role
        AND subject binding
        AND temporal validity

    Authentication is delegated to `_authenticate_signed_human_artifact`, which
    cannot answer any of the remaining clauses -- its result type refuses to be
    read as a boolean at all. What remains here is authorization.

    The previous version failed three clauses at once:

    - ``evidence["role_verified"] = True`` sat outside the ``if claimed_role:``
      guard, so an approval whose ``producer.id`` carried no role skipped the
      role check entirely AND reported that a role had been verified. The
      repository's own fixture used a role-less id, so that was the only path
      the suite ever executed.
    - There was no role vocabulary: any string a trusted key happened to list
      authenticated.
    - ``subject_type`` was never consulted, so a machine key signed an artifact
      saying ``producer.type: "human"`` and became a human approval.

    Evidence flags are set only after the check they describe passes. A flag
    that can be true while its check was skipped is a false statement in an
    audit record, which is worse than a missing one.
    """
    signer = _authenticate_signed_human_artifact(
        approval,
        trust_store=trust_store,
        trust_domain=GOVERNANCE_TRUST_DOMAIN,
        spec=_GOVERNANCE_ARTIFACT,
    )
    evidence: dict[str, Any] = {
        **signer.as_evidence(),
        "role_verified": False,
        "validity_verified": False,
    }

    def refuse(reason: str) -> AuthorityDecision:
        return AuthorityDecision(
            authority=GOVERNANCE_TRUST_DOMAIN,
            granted=False,
            reason=reason,
            evidence=evidence,
        )

    if not signer.signer_authenticated:
        return refuse(signer.reason)

    # PRESENCE, then authorization. A missing role is a refusal, not a skip:
    # "approved by someone" is not an approval, and omitting the capacity was
    # exactly how the previous version was bypassed.
    claimed_role = signer.claimed_role
    if not claimed_role:
        return refuse(
            "APPROVER_ROLE_MISSING: producer.id names no role. An approval must "
            "state the capacity it was given in, as 'subject:role'"
        )
    # BOTH clauses, neither sufficient alone. The first asks whether this role
    # carries governance authority at all; the second asks whether THIS trust
    # domain lets THIS key speak in it. A key trusted to hold the role in some
    # other domain satisfies neither.
    if claimed_role not in GOVERNANCE_APPROVER_ROLES:
        return refuse(
            f"APPROVER_ROLE_UNAUTHORIZED: {claimed_role!r} is not a governance "
            f"approver role {sorted(GOVERNANCE_APPROVER_ROLES)}"
        )
    if claimed_role not in signer.trusted_roles:
        return refuse(
            f"APPROVER_ROLE_UNAUTHORIZED: {signer.signer_subject!r} may not "
            f"approve as {claimed_role!r} in the {GOVERNANCE_TRUST_DOMAIN} "
            "trust domain"
        )
    evidence["role_verified"] = True
    evidence["approver_role"] = claimed_role

    # Temporal validity, last and mandatory.
    #
    # The window was SIGNED and never evaluated. Signing the bounds stops them
    # being re-dated; it does not bound anything. Measured against this
    # repository's own fixtures before this clause existed:
    #
    #     generated 2020-01-01 / expires 2020-01-08  -> (True, "authenticated")
    #     expires BEFORE generated                   -> (True, "authenticated")
    #     generated "not-a-time", expires null       -> (True, "authenticated")
    #
    # and the evidence returned `signature_verified`, `identity_verified`,
    # `role_verified` and `subject_type_verified` all true with nothing about
    # time -- the same "a flag can be true while its check was skipped" defect
    # this function's docstring says it removed.
    moment = _aware_instant(as_of)
    generated = _aware_instant(approval.get("generated_at"))
    expires = _aware_instant(approval.get("expires_at"))
    if moment is None:
        return refuse(
            f"{APPROVAL_TIME_UNREADABLE}: the evaluation instant {as_of!r} is not "
            "a timezone-aware ISO-8601 timestamp, so validity cannot be judged"
        )
    if generated is None or expires is None:
        return refuse(
            f"{APPROVAL_TIME_UNREADABLE}: the approval does not carry a readable "
            "timezone-aware validity interval, so it bounds nothing"
        )
    if expires <= generated:
        return refuse(
            f"{APPROVAL_WINDOW_INVALID}: the approval expires at "
            f"{expires.isoformat()}, at or before it was issued at "
            f"{generated.isoformat()}"
        )
    if expires - generated > GOVERNANCE_APPROVAL_MAX_AGE:
        return refuse(
            f"{APPROVAL_WINDOW_INVALID}: the approval claims a validity window "
            f"longer than {GOVERNANCE_APPROVAL_MAX_AGE.days} days"
        )
    # Half-open [generated, expires), stated rather than left to a reader of the
    # operators. The instant of issue is valid; the instant of expiry is not.
    if moment < generated:
        return refuse(
            f"{APPROVAL_NOT_YET_VALID}: the approval becomes valid at "
            f"{generated.isoformat()}, which is after {moment.isoformat()}"
        )
    if moment >= expires:
        return refuse(
            f"{APPROVAL_EXPIRED}: the approval expired at {expires.isoformat()}, "
            f"at or before {moment.isoformat()}"
        )
    evidence["validity_verified"] = True

    return AuthorityDecision(
        authority=GOVERNANCE_TRUST_DOMAIN,
        granted=True,
        reason="authenticated",
        evidence=evidence,
    )




class TrustStoreUnavailable(RuntimeError):
    """The trust store could not be read, so no signer can be trusted."""


@dataclass(frozen=True)
class TrustedSigner:
    key_id: str
    subject: str
    subject_type: str
    roles: frozenset[str]
    public_key: str
    status: str


def canonical_grant_payload(approval: Mapping[str, Any]) -> bytes:
    """The exact bytes a signature covers.

    Deterministic and total over :data:`SIGNED_FIELDS`: a missing field is
    rendered explicitly rather than dropped, so removing one cannot produce the
    same bytes as a grant that never had it.
    """

    material = {field: approval.get(field) for field in SIGNED_FIELDS}
    return json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")


def trust_store_path() -> Path:
    """Resolve the store location. Called once, at startup, never per decision."""
    override = os.getenv(TRUST_STORE_ENV)
    return Path(override) if override else DEFAULT_TRUST_STORE


def _assert_loadable_public_key(key_id: str, material: str) -> None:
    """A key that cannot be loaded is not a key, and the store is not usable.

    Refused at PARSE time so the failure names the store. Deferring it to the
    first signature check produced a refusal that named the ARTIFACT instead --
    `APPROVAL_NOT_AUTHENTICATED` -- for a fault that is entirely in the trust
    store, which is precisely the misdirection coded refusals exist to prevent.
    """
    try:
        from base64 import b64decode  # noqa: PLC0415

        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
            Ed25519PublicKey,
        )
    except ImportError:  # pragma: no cover - cryptography is a hard dependency
        return
    try:
        Ed25519PublicKey.from_public_bytes(b64decode(material, validate=True))
    except Exception as exc:  # noqa: BLE001 - any failure means unusable
        raise TrustStoreUnavailable(
            f"trusted signer {key_id!r} carries public key material that cannot "
            f"be loaded ({type(exc).__name__}), so this store cannot "
            "authenticate anything and must not report itself available"
        ) from exc


def _parse_signers(payload: Any, location: Path) -> Mapping[str, TrustedSigner]:
    entries = payload.get("signers") if isinstance(payload, dict) else payload
    if not isinstance(entries, list):
        raise TrustStoreUnavailable(
            f"approver trust store at {location} has no signers list"
        )
    signers: dict[str, TrustedSigner] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise TrustStoreUnavailable("each trusted signer must be an object")
        required = {"key_id", "algorithm", "subject", "subject_type", "roles", "public_key"}
        missing = required - set(entry)
        if missing:
            raise TrustStoreUnavailable(f"trusted signer is missing {sorted(missing)}")
        if entry["algorithm"] != "Ed25519":
            raise TrustStoreUnavailable(
                f"unsupported signature algorithm {entry['algorithm']!r}; only "
                "Ed25519 is accepted"
            )
        if not isinstance(entry["roles"], list) or not entry["roles"]:
            raise TrustStoreUnavailable("a trusted signer must list at least one role")
        # DUPLICATES ARE REFUSED, as `reviewer_trust._parse_reviewers` already
        # refuses them by name. This assigned into a dict, so a repeated key_id
        # resolved LAST-WINS: one file could list `K1` as
        # `subject: mazin, status: revoked` and again as
        # `subject: mallory, status: active`, and the store loaded without
        # complaint resolving K1 to mallory, active. A revocation earlier in the
        # list was silently overridden by a later duplicate.
        #
        # The lower-authority store -- reviewers, who cannot release an effect
        # -- refused exactly this shape while the store that authorises
        # consequential acts did not. That asymmetry is the wrong way round.
        if str(entry["key_id"]) in signers:
            raise TrustStoreUnavailable(
                f"the approver trust store lists key_id {entry['key_id']!r} "
                "twice; which signer it means, and which status applies, would "
                "depend on ordering"
            )
        # THE KEY MATERIAL IS LOADED HERE, not first used at a signature check.
        # `public_key` was carried as an opaque string, so a store whose every
        # key was unusable -- wrong length, not base64, empty -- reported
        # `available=True` with `active_signers=['K']`, and
        # `assurance_state()` published `consequential_authority: available`.
        # Every grant then refused as APPROVAL_NOT_AUTHENTICATED: ValueError,
        # which sends an operator to reissue the artifact when the STORE is
        # what needs fixing. This is the same defect the `active_signers`
        # docstring records as closed for revoked keys, recurring through a
        # second cause the `status == "active"` rule cannot see.
        _assert_loadable_public_key(str(entry["key_id"]), str(entry["public_key"]))
        signers[str(entry["key_id"])] = TrustedSigner(
            key_id=str(entry["key_id"]),
            subject=str(entry["subject"]),
            subject_type=str(entry["subject_type"]),
            roles=frozenset(str(role) for role in entry["roles"]),
            public_key=str(entry["public_key"]),
            status=str(entry.get("status", "active")),
        )
    # READ-ONLY. `ApprovalTrustStore` is `frozen=True`, which freezes the
    # REFERENCE and not what it points at -- a plain dict here meant the
    # 'immutable startup snapshot' could be re-pointed in place after
    # bootstrap. A review demonstrated it: inserting an attacker key into
    # `context.action_approval_trust.signers` turned a DENY
    # (APPROVER_NOT_TRUSTED) into an ALLOW with the effect executed, while
    # `store.digest` stayed unchanged -- so the audit projection could not see
    # it afterwards either.
    return MappingProxyType(signers)


@dataclass(frozen=True)
class ApprovalTrustStore:
    """The trusted signers of ONE authority domain, fixed when they were loaded.

    Immutable and injected, so an authorization decision consults an object
    rather than the filesystem or the environment. Two decisions in one process
    answer to the same authority by construction, and a variable changed after
    startup cannot re-point the root of trust.

    `domain` names which authority this membership is for. It is not decoration:
    the authenticator refuses a store whose domain does not match the authority
    asking, so handing the governance store to the action verifier is a refusal
    rather than a silent cross-domain grant.
    """

    signers: Mapping[str, TrustedSigner] = field(default_factory=dict)
    digest: str = "sha256:" + hashlib.sha256(b"").hexdigest()
    source: str = "<none>"
    available: bool = False
    domain: str = ""
    #: True when the store EXISTED and could not be used. Absence and
    #: malformation both authorize nothing, so `available` cannot tell them
    #: apart -- but "nobody is trusted here" and "the trust material is broken"
    #: mean different things to an operator, and a report that says the first
    #: when the second is true sends them looking for the wrong problem. Carried
    #: on the snapshot rather than re-derived, because the only other way to
    #: answer it later is to open the file again.
    unusable: bool = False

    @property
    def active_signers(self) -> dict[str, "TrustedSigner"]:
        """The signers that could actually authorize anything.

        Membership is not authority. A revoked or suspended key stays in the
        store -- deliberately, so a refusal can say "that key is revoked" rather
        than "unknown key" -- and `authenticate_action_grant` refuses it. But a
        report that counted the raw membership described a deployment as able to
        release consequential effects when every one of its keys was revoked.
        Measured: `consequential_authority: available` with the whole store
        revoked and the boundary refusing each key in turn.

        The authenticator remains the enforcement point. This exists so that
        what is REPORTED and what is ENFORCED answer to the same rule.
        """
        return {
            key: signer
            for key, signer in self.signers.items()
            if signer.status == ACTIVE_SIGNER_STATUS
        }

    @classmethod
    def load(cls, path: Path | None = None, *, domain: str) -> "ApprovalTrustStore":
        """Read one authority domain's membership, once, at startup.

        The domain is a required keyword. A default would be the whole defect
        this signature exists to prevent: every load site must say which
        authority it is provisioning, in the diff, where it can be reviewed.
        """
        return ApprovalTrustDomains.load(path).of(domain)

    @classmethod
    def for_test(
        cls, entries: list[dict[str, Any]], *, domain: str = ""
    ) -> "ApprovalTrustStore":
        payload = json.dumps({"signers": entries}, sort_keys=True).encode("utf-8")
        return cls(
            signers=_parse_signers({"signers": entries}, Path("<test>")),
            digest="sha256:" + hashlib.sha256(payload).hexdigest(),
            source="<test>",
            available=True,
            domain=domain,
        )


@dataclass(frozen=True)
class ApprovalTrustDomains:
    """Two independently provisioned memberships, read from one document.

    WHY TWO. Governance approval and consequential action release were one
    membership. The role vocabularies overlap on `network_governance_owner`, so
    provisioning a key to approve governed content also provisioned it -- as far
    as trust was concerned -- to release effects, and the separation survived
    only because each caller happened to check a role vocabulary afterwards.
    Membership in one trust domain must never imply authority in another.

    WHY ONE DOCUMENT. One file to provision, one file to mount read-only, one
    parser, one Ed25519 implementation. The separation is in the document's
    structure, not in the filesystem, so it cannot be half-deployed: a store
    that predates domains is refused outright rather than being read as both.

    The sections do not share a principal map. A key listed under `governance`
    is simply absent from `action` -- there is no set to subset, no wrapper over
    a common list, and nothing to relax into "trusted everywhere".
    """

    governance: ApprovalTrustStore
    action: ApprovalTrustStore
    source: str = "<none>"

    #: Named so a typo cannot open a third, ungoverned section.
    KNOWN = (GOVERNANCE_TRUST_DOMAIN, ACTION_TRUST_DOMAIN)

    def of(self, domain: str) -> ApprovalTrustStore:
        if domain == GOVERNANCE_TRUST_DOMAIN:
            return self.governance
        if domain == ACTION_TRUST_DOMAIN:
            return self.action
        raise TrustStoreUnavailable(
            f"{domain!r} is not an approval authority domain {list(self.KNOWN)}"
        )

    @classmethod
    def load(cls, path: Path | None = None) -> "ApprovalTrustDomains":
        """Read and validate both domains once, at startup.

        Absence, un-migration and malformation are three different facts.

        - The file is missing: no consequential authority is available here, an
          ordinary deployment state, and each domain says so in its own source.
        - The file exists but declares no domains: it cannot answer a per-domain
          question at all, and guessing would grant every governance approver
          the power to release effects. Refused, loudly, with the shape to fix
          it.
        - The file is unreadable: refused, rather than degrading into an empty
          mapping that quietly means "nobody is trusted".
        """
        location = path or trust_store_path()
        if not location.exists():
            return cls(
                governance=ApprovalTrustStore(
                    source=str(location), domain=GOVERNANCE_TRUST_DOMAIN
                ),
                action=ApprovalTrustStore(
                    source=str(location), domain=ACTION_TRUST_DOMAIN
                ),
                source=str(location),
            )
        try:
            raw = location.read_bytes()
            payload = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TrustStoreUnavailable(
                f"approver trust store at {location} is unreadable: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

        if not isinstance(payload, dict) or not isinstance(
            payload.get("domains"), dict
        ):
            raise TrustStoreUnavailable(
                f"approver trust store at {location} declares no authority "
                "domains. A store that lists signers without saying which "
                "authority they hold cannot answer 'may this key approve "
                "GOVERNANCE' and 'may this key release an ACTION' separately, "
                "and reading it as both would give every governance approver "
                "the power to release consequential effects. Provision it as "
                '{"domains": {"governance": {"signers": [...]}, '
                '"action": {"signers": [...]}}}'
            )
        domains = payload["domains"]
        unknown = sorted(set(domains) - set(cls.KNOWN))
        if unknown:
            # A misspelled section would otherwise sit in the file looking
            # provisioned while granting nothing, which is the failure mode
            # where an operator believes a key is trusted and it is not.
            raise TrustStoreUnavailable(
                f"approver trust store at {location} declares unknown authority "
                f"domains {unknown}; known domains are {list(cls.KNOWN)}"
            )

        def section(name: str) -> ApprovalTrustStore:
            if name not in domains:
                # Present-but-unprovisioned. Distinct from a missing file, and
                # named so the refusal tells an operator which section to add.
                return ApprovalTrustStore(
                    source=f"{location} declares no {name!r} approval domain",
                    domain=name,
                )
            body = domains[name]
            if not isinstance(body, dict):
                raise TrustStoreUnavailable(
                    f"the {name!r} approval domain in {location} is not an object"
                )
            material = json.dumps(body, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
            return ApprovalTrustStore(
                signers=_parse_signers(body, location),
                # Per DOMAIN, not per file. A digest shared between the two
                # would report the same trust identity for two different
                # memberships, and the evidence is meant to distinguish them.
                digest="sha256:" + hashlib.sha256(material).hexdigest(),
                source=str(location),
                available=True,
                domain=name,
            )

        return cls(
            governance=section(GOVERNANCE_TRUST_DOMAIN),
            action=section(ACTION_TRUST_DOMAIN),
            source=str(location),
        )


#: `load_trust_store()` -- a domain-less accessor returning the signer mapping
#: alone -- was removed here rather than given a domain parameter. It had no
#: production caller, and a way to obtain "the trusted signers" without saying
#: for which authority is the exact shape this split exists to remove.


# ---------------------------------------------------------------------------
# LAYER 1 -- the cryptographic primitive
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthenticatedSignerEvidence:
    """WHO signed a human artifact. Never WHAT that signer may do.

    This is deliberately not a decision, and the type enforces it: ``__bool__``
    raises, so ``if authenticate(...)`` -- the single most likely misuse -- is a
    TypeError at the call site rather than a silent grant. There is no field
    named ``authorized``, ``approved``, ``granted`` or ``authenticated``; the
    boolean it does carry is ``signer_authenticated``, which answers only
    "a trusted human key signed exactly these bytes".

    `trusted_roles` is reported as a FACT about the trust domain -- the roles
    that domain says this key may speak in -- not as a permission. Deciding
    whether a role carries an authority is the authority verifier's job, and it
    needs both clauses: the role must be valid FOR THAT AUTHORITY and the key
    must be trusted to claim it IN THAT DOMAIN.

    `claimed_role` is repeated here only because it is covered by the signature
    in both artifact schemas (``producer_id`` for governance, ``approver_role``
    for action grants), so it is an authenticated claim rather than a hint.
    """

    trust_domain: str
    trust_store_digest: str
    signer_authenticated: bool = False
    reason: str = ""
    signer_key_id: str | None = None
    signer_subject: str | None = None
    signer_subject_type: str | None = None
    trusted_roles: frozenset[str] = frozenset()
    claimed_role: str | None = None
    signature_verified: bool = False
    identity_verified: bool = False
    subject_type_verified: bool = False

    def __bool__(self) -> bool:
        raise TypeError(
            "AuthenticatedSignerEvidence is not an authority decision. It "
            "records that a trusted human key signed an artifact, which is "
            "authentication, not authorization. Call verify_governance_approval"
            "(...) or verify_action_approval(...) and test that result."
        )

    def as_evidence(self) -> "dict[str, Any]":
        """The audit projection, carrying no key material."""
        return {
            "trust_domain": self.trust_domain,
            "trust_store_digest": self.trust_store_digest,
            "signer_key_id": self.signer_key_id,
            "approver": self.signer_subject,
            "signature_verified": self.signature_verified,
            "identity_verified": self.identity_verified,
            "subject_type_verified": self.subject_type_verified,
        }


@dataclass(frozen=True)
class AuthorityDecision:
    """Whether a named authority was granted, and on what evidence.

    ``__bool__`` IS the grant here, which is the whole difference from
    :class:`AuthenticatedSignerEvidence`: an authority decision is a decision.
    """

    authority: str
    granted: bool
    reason: str
    evidence: "dict[str, Any]"

    def __bool__(self) -> bool:
        return self.granted

    def __iter__(self):
        # Migration affordance for `ok, reason, evidence = verify_...(...)`
        # call sites. Exactly the three fields, in the order they were returned
        # as a tuple before this type existed -- nothing is hidden behind it.
        yield from (self.granted, self.reason, self.evidence)


@dataclass(frozen=True)
class _SignedHumanArtifact:
    """How one artifact schema exposes the fields the primitive authenticates.

    Two schemas, one verifier. The alternative -- a second Ed25519 path for the
    second artifact type -- is how the governance verifier came to be missing
    the ``subject_type`` check its action twin already had: a control verified
    where it was written and absent where it was copied.
    """

    noun: str
    schema: str
    canonical: "Any"
    #: artifact -> (claimed subject, claimed role, self-described subject type)
    identity: "Any"


def _governance_identity(
    artifact: "Mapping[str, Any]",
) -> "tuple[str | None, str | None, object]":
    producer = artifact.get("producer")
    if not isinstance(producer, Mapping):
        return None, None, None
    claimed = producer.get("id")
    if not isinstance(claimed, str) or not claimed:
        return None, None, producer.get("type")
    subject, separator, role = claimed.partition(":")
    return subject, (role if separator and role else None), producer.get("type")


def _action_identity(
    artifact: "Mapping[str, Any]",
) -> "tuple[str | None, str | None, object]":
    approver = artifact.get("approver")
    role = artifact.get("approver_role")
    return (
        approver if isinstance(approver, str) and approver else None,
        role if isinstance(role, str) and role else None,
        artifact.get("approver_type"),
    )


def _authenticate_signed_human_artifact(
    artifact: "Mapping[str, Any] | None",
    *,
    trust_store: "ApprovalTrustStore | None",
    trust_domain: str,
    spec: _SignedHumanArtifact,
) -> AuthenticatedSignerEvidence:
    """Prove a trusted human key signed exactly these bytes. Nothing more.

    Every refusal is coded, and the code names the clause that failed, because
    an operator's response differs by clause: an untrusted key needs
    provisioning, an invalid signature needs a reissued artifact, and a
    machine-owned key needs a different approver entirely.

    The trust domain is named in the refusal. A key trusted for governance
    presenting an action grant must not read as "unknown key" -- it is a known
    key in the wrong domain, and hiding that would send an operator to add it
    to the very store that must not hold it.
    """

    # Labelled with the authority that is ASKING. A bare `ApprovalTrustStore()`
    # here carried no domain, and the domain clause below skips an unlabelled
    # store -- so the one store this function can construct for itself was also
    # the one store that would have satisfied any domain. It authenticates
    # nothing either way (no signers, so the availability clause refuses first),
    # but a fallback that is exempt from the separation rule is the wrong shape
    # to leave in an authenticator, and it was the only production site that
    # built one.
    store = (
        trust_store
        if trust_store is not None
        else ApprovalTrustStore(source="<none supplied>", domain=trust_domain)
    )
    blank = AuthenticatedSignerEvidence(
        trust_domain=trust_domain, trust_store_digest=store.digest
    )

    def refuse(reason: str, **fields: "Any") -> AuthenticatedSignerEvidence:
        return replace(blank, signer_authenticated=False, reason=reason, **fields)

    if not isinstance(artifact, Mapping):
        return refuse(f"no {spec.noun} was supplied")

    # Fail closed on absence. An empty store is "nothing can be authenticated
    # here", which is the opposite of "anything may pass".
    if not store.available or not store.signers:
        return refuse(
            f"APPROVER_TRUST_UNAVAILABLE: no {trust_domain} approver trust store, "
            f"so no human {spec.noun} can be authenticated ({store.source})"
        )

    # The store must belong to the authority asking. Handing the governance
    # membership to the action verifier is a cross-domain grant even though
    # every signature in it is valid, so it is refused here rather than being
    # left to whoever wired the call.
    #
    # NOT TOTAL, and that is a recorded decision rather than an oversight.
    # `store.domain and ...` lets an UNLABELLED store skip this clause, so
    # domain separation is opt-in for stores that decline to say which authority
    # they belong to. Production always labels -- `ApprovalTrustStore.load`
    # takes the domain as a required keyword with no default -- so no live path
    # reaches here unlabelled; the affordance exists for in-memory fixtures.
    #
    # Making it total was implemented and MEASURED, and reverted on the
    # evidence. It broke thirteen call sites across five test modules, and two
    # of those were security proofs whose MECHANISM it changed rather than whose
    # fixture it inconvenienced: `test_removing_the_frozen_store_changes_the_
    # consequential_decision` removes the frozen store precisely to show the
    # decision moves, and a domain refusal reaching it first means the test
    # stops measuring what it names.
    #
    # Trading a latent affordance for a real reduction in what two H01 proofs
    # measure is a bad trade. The property that actually matters -- production
    # stores are always labelled -- is asserted directly in
    # tests/test_authority_domains.py instead.
    if store.domain and store.domain != trust_domain:
        return refuse(
            f"TRUST_DOMAIN_MISMATCH: a {trust_domain!r} authority was asked to "
            f"decide against the {store.domain!r} approver trust store. "
            "Membership in one domain is not authority in another."
        )

    if artifact.get("schema") != spec.schema:
        return refuse(f"APPROVAL_SCHEMA_UNKNOWN: {artifact.get('schema')!r}")

    key_id = artifact.get("signer_key_id")
    if not isinstance(key_id, str) or not key_id.strip():
        return refuse("APPROVAL_UNSIGNED: names no signer key")
    signer = store.signers.get(key_id)
    if signer is None:
        return refuse(
            f"APPROVER_NOT_TRUSTED: signer key {key_id!r} is not in the "
            f"{trust_domain} approver trust store",
            signer_key_id=key_id,
        )
    if signer.status != ACTIVE_SIGNER_STATUS:
        return refuse(
            f"APPROVER_NOT_TRUSTED: signer key {key_id!r} is {signer.status}",
            signer_key_id=key_id,
        )
    known = replace(
        blank,
        signer_key_id=key_id,
        signer_subject=signer.subject,
        signer_subject_type=signer.subject_type,
        trusted_roles=frozenset(signer.roles),
    )

    def refuse_known(reason: str, **fields: "Any") -> AuthenticatedSignerEvidence:
        return replace(known, signer_authenticated=False, reason=reason, **fields)

    # The trust store decides what a key IS; the artifact only claims it.
    # Checked before the signature so a machine key is refused for being a
    # machine rather than for whatever it signed.
    if signer.subject_type != "human":
        return refuse_known(
            f"APPROVER_NOT_HUMAN: signer key {key_id!r} belongs to a "
            f"{signer.subject_type!r}, which cannot give a human {spec.noun} "
            "however the artifact describes itself"
        )
    claimed_subject, claimed_role, declared_type = spec.identity(artifact)
    if declared_type != "human":
        # An UNSIGNED self-description in both schemas, so it proves nothing on
        # its own and is checked only after the store has already established
        # the key is human. Kept because an artifact that describes itself as
        # machine-produced should not be adopted as a human approval whatever
        # key signed it.
        return refuse_known(
            f"APPROVAL_PRODUCER_NOT_HUMAN: the {spec.noun} describes its "
            f"producer as {declared_type!r}"
        )
    known = replace(known, subject_type_verified=True)

    signature = artifact.get("signature")
    if not isinstance(signature, str) or not signature.strip():
        return refuse_known("APPROVAL_UNSIGNED: no signature present")

    try:
        from base64 import b64decode

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:  # pragma: no cover - cryptography is a hard dependency
        return refuse_known("APPROVAL_VERIFIER_UNAVAILABLE")

    try:
        public_key = Ed25519PublicKey.from_public_bytes(b64decode(signer.public_key))
        public_key.verify(b64decode(signature), spec.canonical(artifact))
    except InvalidSignature:
        return refuse_known(
            "APPROVAL_NOT_AUTHENTICATED: signature invalid. Any change to the "
            "decision, approver, role, window or bound subject invalidates it."
        )
    except Exception as exc:
        return refuse_known(f"APPROVAL_NOT_AUTHENTICATED: {type(exc).__name__}")
    known = replace(known, signature_verified=True)

    # Identity AFTER the signature. Before it, a match only says the forged
    # artifact was internally consistent -- and recording `identity_verified`
    # at that point puts a statement in an audit record that the evidence does
    # not support.
    if not signer.subject:
        return refuse_known(
            f"APPROVER_NOT_TRUSTED: key {key_id!r} names no subject, so no "
            "identity can be matched against it",
            signature_verified=True,
        )
    if not claimed_subject:
        return refuse_known(
            "APPROVER_IDENTITY_MISSING: the artifact names no approver identity",
            signature_verified=True,
        )
    if claimed_subject != signer.subject:
        return refuse_known(
            f"APPROVER_IDENTITY_MISMATCH: signed as {claimed_subject!r}, key "
            f"belongs to {signer.subject!r}",
            signature_verified=True,
        )

    return replace(
        known,
        signer_authenticated=True,
        identity_verified=True,
        claimed_role=claimed_role,
        reason=f"signed by {signer.subject} using trusted key {key_id}",
    )


_GOVERNANCE_ARTIFACT = _SignedHumanArtifact(
    noun="governance approval",
    schema=GOVERNANCE_APPROVAL_SCHEMA,
    canonical=canonical_governance_payload,
    identity=_governance_identity,
)

_ACTION_ARTIFACT = _SignedHumanArtifact(
    noun="action approval",
    schema=APPROVAL_SCHEMA,
    canonical=canonical_grant_payload,
    identity=_action_identity,
)


def authenticate_action_grant(
    grant: "Mapping[str, Any] | None",
    *,
    trust_store: "ApprovalTrustStore | None",
) -> AuthenticatedSignerEvidence:
    """Authenticate an action grant's signer. NOT an authority to release.

    Exposed for the action authority verifier, which lives with `ActionRequest`
    in the runtime module. Its result cannot be used as a decision: see
    :class:`AuthenticatedSignerEvidence`.
    """
    return _authenticate_signed_human_artifact(
        grant,
        trust_store=trust_store,
        trust_domain=ACTION_TRUST_DOMAIN,
        spec=_ACTION_ARTIFACT,
    )
