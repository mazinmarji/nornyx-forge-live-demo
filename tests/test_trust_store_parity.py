"""Every trust store, judged by the same properties -- discovered, not listed.

R7-a. Three defects were found on the approver store, repaired there, and left
standing in the reviewer store beside it:

    a plain `dict` behind a `frozen=True` snapshot, so a key inserted after
    load authenticated a FORGED artifact with `store.digest` unchanged;

    key material never loaded at parse time, so a store holding unusable keys
    reported itself available and blamed the ARTIFACT when verification failed;

    a duplicate `key_id` accepted, so which principal a key meant depended on
    iteration order.

The third WAS ported. The first two were not, and nothing noticed for four
review rounds, because each repair was verified by a test named after the store
it was written against. That is the whole defect: the coverage was a table of
one, written by hand, and invisible because nothing enumerated what the table
SHOULD have contained.

So this module does not test "the reviewer store" or "the approver store". It
DISCOVERS every trust store in the package and requires each to satisfy the
same properties, and -- the part that actually closes the class --
`test_the_registry_covers_every_discovered_trust_store` fails when a store
exists that this module cannot exercise. A third store added tomorrow makes
that test red until someone teaches this module to build one; it cannot be
added silently and inherit nothing.

WHAT THE REGISTRY IS AND IS NOT. Building a valid store requires knowing its
schema, so the BUILDERS below are necessarily per-store and hand-written. The
registry is honest about being a table. What is not a table is its SCOPE: the
set of stores that must appear in it is computed from the package, so the
failure mode this module exists to prevent -- a store nobody remembered --
is a red test rather than a silence.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
from pathlib import Path
from typing import Any, Callable

import pytest

from nornyx_forge import approval_trust, reviewer_trust
from nornyx_forge.approval_trust import ACTION_TRUST_DOMAIN, ApprovalTrustStore
from nornyx_forge.reviewer_trust import ReviewerTrustStore

#: A key that is syntactically fine and cannot be loaded as key material by
#: either store's verifier. Deliberately not empty and not obviously absent:
#: an empty value is refused by the "reviewer without a key" clause, which is a
#: DIFFERENT control, and passing it would prove that control rather than this.
UNLOADABLE_KEY = "bm90IGEga2V5IGF0IGFsbA=="


def _ed25519_pem() -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    return (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode("utf-8")
    )


def _ed25519_b64() -> str:
    from base64 import b64encode

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    raw = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    return b64encode(raw).decode("ascii")


def _write_approver_store(path: Path, public_key: str) -> Any:
    entry = {
        "key_id": "parity-approver",
        "algorithm": "Ed25519",
        "subject": "parity@example.test",
        "subject_type": "human",
        "roles": ["production_approver"],
        "public_key": public_key,
        "status": "active",
    }
    path.write_text(
        json.dumps({"domains": {
            "governance": {"signers": [entry]},
            "action": {"signers": [entry]},
        }}),
        encoding="utf-8",
    )
    return ApprovalTrustStore.load(path, domain=ACTION_TRUST_DOMAIN)


def _write_reviewer_store(path: Path, public_key: str) -> Any:
    entry = {
        "key_id": "parity-reviewer",
        "reviewer": "parity reviewer",
        "roles": ["security"],
        "public_key": public_key,
        "status": "active",
    }
    path.write_text(
        json.dumps({
            "schema": "nornyx.forge.reviewer_trust_store.v1",
            "reviewers": [entry],
        }),
        encoding="utf-8",
    )
    return ReviewerTrustStore.load(path)


@dataclasses.dataclass(frozen=True)
class StoreUnderTest:
    """How to build one trust store, and where its membership lives."""

    class_name: str
    mapping_field: str
    valid_key: Callable[[], str]
    build: Callable[[Path, str], Any]


REGISTRY: tuple[StoreUnderTest, ...] = (
    StoreUnderTest("ApprovalTrustStore", "signers", _ed25519_b64,
                   _write_approver_store),
    StoreUnderTest("ReviewerTrustStore", "reviewers", _ed25519_pem,
                   _write_reviewer_store),
)


def _discovered_trust_stores() -> dict[str, type]:
    """Every trust store in the package, by structure rather than by name.

    A trust store here is a dataclass, defined in a `*_trust` module, holding a
    `Mapping` of principals and offering `load`. That is what makes it a root
    of trust read from disk -- which is the thing whose immutability and whose
    key material these properties are about.
    """
    found: dict[str, type] = {}
    for module in (approval_trust, reviewer_trust):
        for name, obj in vars(module).items():
            if not (inspect.isclass(obj) and dataclasses.is_dataclass(obj)):
                continue
            if getattr(obj, "__module__", "") != module.__name__:
                continue
            if not hasattr(obj, "load"):
                continue
            if any("Mapping" in str(f.type) for f in dataclasses.fields(obj)):
                found[name] = obj
    return found


def test_the_registry_covers_every_discovered_trust_store() -> None:
    """The anti-omission guard, and the reason this module exists.

    Every property below is parametrised over `REGISTRY`. A store missing from
    it is therefore a store nobody checks -- silently, and with every named
    test green. That is not a hypothetical: the reviewer store sat outside
    every one of these checks through four review rounds while the approver
    store beside it had all three, and the only reason nobody saw it is that
    no test ever asked which stores existed.
    """
    discovered = set(_discovered_trust_stores())
    covered = {store.class_name for store in REGISTRY}
    assert discovered == covered, (
        "the set of trust stores in the package and the set this module "
        f"exercises disagree. Not exercised: {sorted(discovered - covered)}. "
        f"Listed but no longer present: {sorted(covered - discovered)}. A "
        "store that is not exercised here inherits none of the properties "
        "below, which is exactly how the reviewer store came to accept a "
        "forged independent inspection."
    )
    assert len(discovered) >= 2, (
        f"only {len(discovered)} trust stores were discovered; the structural "
        "criterion above has stopped matching, and a sweep that finds nothing "
        "passes every parametrised test in this module"
    )


@pytest.mark.parametrize("store", REGISTRY, ids=lambda s: s.class_name)
def test_a_loaded_store_exposes_a_read_only_mapping(
    store: StoreUnderTest, tmp_path: Path
) -> None:
    """`frozen=True` freezes the REFERENCE, not what it points at.

    Measured on the reviewer store before this: inserting an attacker key into
    the "immutable startup snapshot" made a forged independent inspection --
    signed with a key present in no store on disk -- authenticate, while
    `store.digest`, the value an audit compares, stayed unchanged.

    This drives the mutation rather than asserting the type name, because
    `MappingProxyType` is not the property; being unable to re-point the root
    of trust after startup is.
    """
    loaded = store.build(tmp_path / "store.json", store.valid_key())
    mapping = getattr(loaded, store.mapping_field)
    assert mapping, "the store loaded no principals; this measures nothing"

    victim = next(iter(mapping.values()))
    with pytest.raises(TypeError):
        mapping["forged-key-id"] = victim
    with pytest.raises(TypeError):
        del mapping[next(iter(mapping))]

    assert "forged-key-id" not in getattr(loaded, store.mapping_field), (
        "the insertion raised and landed anyway, so the mapping is a proxy "
        "over something the caller still holds a writable reference to"
    )


@pytest.mark.parametrize("store", REGISTRY, ids=lambda s: s.class_name)
def test_a_store_whose_key_material_cannot_be_loaded_refuses_at_load(
    store: StoreUnderTest, tmp_path: Path
) -> None:
    """The failure must name the STORE, and must arrive before it is used.

    Deferred to first use, a store full of unusable keys reports itself
    available and then refuses the ARTIFACT -- `ATTESTATION_NOT_AUTHENTICATED:
    ValueError` for a fault entirely in the store. That is the misdirection
    coded refusals exist to prevent, and it is why this is checked at parse
    time on every store rather than on the one where it was noticed.
    """
    with pytest.raises(RuntimeError) as raised:
        store.build(tmp_path / "broken.json", UNLOADABLE_KEY)

    message = str(raised.value)
    # BOTH halves, because either alone is satisfiable by the wrong refusal.
    # A store can reject this entry for a reason that has nothing to do with
    # key material -- an unknown field, a missing role -- and still name the
    # key, which would leave this test green while parse-time key loading was
    # absent. Requiring the key-material clause pins WHICH control fired.
    assert "public key material that cannot" in message, (
        "the store refused, but not because the key material could not be "
        f"loaded, so parse-time key loading is unmeasured here: {message}"
    )
    assert "parity-" in message, (
        "the refusal does not name the offending key, so an operator cannot "
        f"tell which principal makes the store unusable: {message}"
    )
