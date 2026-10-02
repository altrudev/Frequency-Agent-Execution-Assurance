from __future__ import annotations

import base64
import json
from copy import deepcopy
from typing import Any, AbstractSet

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .evaluator import digest, evaluate_run

BUNDLE_SCHEMA = "frequency.portable-evidence-bundle.v1"


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _signature_payload(bundle: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": bundle.get("schema"),
        "bundle_id": bundle.get("bundle_id"),
        "issuer_id": bundle.get("issuer_id"),
        "issued_at": bundle.get("issued_at"),
        "nonce": bundle.get("nonce"),
        "adapter_id": bundle.get("adapter_id"),
        "source_commit": bundle.get("source_commit"),
        "run_digest": bundle.get("run_digest"),
        "run": bundle.get("run"),
    }


def _identity_payload(
    *,
    issuer_id: str,
    issued_at: int,
    nonce: str,
    adapter_id: str,
    source_commit: str,
    run_digest: str,
) -> dict[str, Any]:
    return {
        "issuer_id": issuer_id,
        "issued_at": issued_at,
        "nonce": nonce,
        "adapter_id": adapter_id,
        "source_commit": source_commit,
        "run_digest": run_digest,
    }


def _valid_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def create_bundle(
    run: dict[str, Any],
    *,
    issuer_id: str,
    issued_at: int,
    nonce: str,
    adapter_id: str,
    source_commit: str,
    signing_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    if not isinstance(run, dict):
        raise ValueError("run must be a JSON object")
    for label, value in (
        ("issuer_id", issuer_id),
        ("nonce", nonce),
        ("adapter_id", adapter_id),
        ("source_commit", source_commit),
    ):
        if not _valid_text(value):
            raise ValueError(f"{label} must be non-empty")
    if not isinstance(issued_at, int):
        raise ValueError("issued_at must be an integer")

    frozen_run = deepcopy(run)
    run_digest = digest(frozen_run)
    bundle_id = digest(
        _identity_payload(
            issuer_id=issuer_id,
            issued_at=issued_at,
            nonce=nonce,
            adapter_id=adapter_id,
            source_commit=source_commit,
            run_digest=run_digest,
        )
    )

    bundle = {
        "schema": BUNDLE_SCHEMA,
        "bundle_id": bundle_id,
        "issuer_id": issuer_id,
        "issued_at": issued_at,
        "nonce": nonce,
        "adapter_id": adapter_id,
        "source_commit": source_commit,
        "run_digest": run_digest,
        "run": frozen_run,
    }
    signature = signing_key.sign(digest(_signature_payload(bundle)).encode("ascii"))
    bundle["signature"] = {
        "algorithm": "Ed25519",
        "value": base64.b64encode(signature).decode("ascii"),
    }
    return bundle


def _verify_bundle_signature(
    bundle: dict[str, Any],
    trusted_public_key: bytes | None,
) -> bool:
    if trusted_public_key is None:
        return False
    signature = bundle.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "Ed25519":
        return False
    value = signature.get("value")
    if not isinstance(value, str) or not value:
        return False

    try:
        signature_bytes = base64.b64decode(value, validate=True)
        Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(
            signature_bytes,
            digest(_signature_payload(bundle)).encode("ascii"),
        )
    except (ValueError, InvalidSignature):
        return False
    return True


def verify_bundle(
    bundle: dict[str, Any],
    *,
    trusted_issuer_id: str,
    trusted_bundle_public_key: bytes,
    trusted_observer_id: str,
    trusted_observer_public_key: bytes,
    trusted_closure_public_key: bytes,
    expected_nonce: str | None = None,
    expected_adapter_id: str | None = None,
    expected_source_commit: str | None = None,
    seen_bundle_ids: AbstractSet[str] | None = None,
) -> dict[str, Any]:
    findings: list[dict[str, str]] = []

    def add(code: str, detail: str) -> None:
        findings.append({"code": code, "detail": detail})

    if not isinstance(bundle, dict):
        add("INVALID_BUNDLE", "bundle must be a JSON object")
        return _result(findings, False, None)

    allowed_fields = {
        "schema",
        "bundle_id",
        "issuer_id",
        "issued_at",
        "nonce",
        "adapter_id",
        "source_commit",
        "run_digest",
        "run",
        "signature",
    }
    unexpected = sorted(set(bundle) - allowed_fields)
    if unexpected:
        add(
            "UNEXPECTED_BUNDLE_FIELD",
            "bundle contains unsupported fields: " + ", ".join(unexpected),
        )

    if bundle.get("schema") != BUNDLE_SCHEMA:
        add("UNSUPPORTED_BUNDLE_SCHEMA", "unsupported portable evidence bundle schema")

    for field in (
        "bundle_id",
        "issuer_id",
        "nonce",
        "adapter_id",
        "source_commit",
        "run_digest",
    ):
        if not _valid_text(bundle.get(field)):
            add("MISSING_BUNDLE_FIELD", f"{field} must be non-empty")

    if not isinstance(bundle.get("issued_at"), int):
        add("INVALID_BUNDLE_TIME", "issued_at must be an integer")

    run = bundle.get("run")
    if not isinstance(run, dict):
        add("INVALID_BUNDLE_RUN", "run must be a JSON object")
        run = None

    if bundle.get("issuer_id") != trusted_issuer_id:
        add("BUNDLE_ISSUER_NOT_TRUSTED", "bundle issuer does not match trusted issuer")

    if expected_nonce is not None and bundle.get("nonce") != expected_nonce:
        add("BUNDLE_NONCE_MISMATCH", "bundle nonce does not match caller expectation")

    if expected_adapter_id is not None and bundle.get("adapter_id") != expected_adapter_id:
        add("BUNDLE_ADAPTER_MISMATCH", "bundle adapter does not match caller expectation")

    if (
        expected_source_commit is not None
        and bundle.get("source_commit") != expected_source_commit
    ):
        add(
            "BUNDLE_SOURCE_COMMIT_MISMATCH",
            "bundle source commit does not match caller expectation",
        )

    bundle_id = bundle.get("bundle_id")
    if isinstance(bundle_id, str) and seen_bundle_ids is not None and bundle_id in seen_bundle_ids:
        add("BUNDLE_REPLAY_DETECTED", "bundle ID was already seen by the caller")

    if run is not None:
        actual_run_digest = digest(run)
        if bundle.get("run_digest") != actual_run_digest:
            add("BUNDLE_RUN_DIGEST_MISMATCH", "bundle run digest does not bind current run")

        expected_bundle_id = digest(
            _identity_payload(
                issuer_id=bundle.get("issuer_id"),
                issued_at=bundle.get("issued_at"),
                nonce=bundle.get("nonce"),
                adapter_id=bundle.get("adapter_id"),
                source_commit=bundle.get("source_commit"),
                run_digest=bundle.get("run_digest"),
            )
        )
        if bundle.get("bundle_id") != expected_bundle_id:
            add("BUNDLE_ID_MISMATCH", "bundle ID does not bind current metadata")

    signature_ok = _verify_bundle_signature(bundle, trusted_bundle_public_key)
    if not signature_ok:
        add("BUNDLE_SIGNATURE_NOT_VERIFIED", "bundle signature is absent or invalid")

    blocking = {
        "INVALID_BUNDLE",
        "UNEXPECTED_BUNDLE_FIELD",
        "UNSUPPORTED_BUNDLE_SCHEMA",
        "MISSING_BUNDLE_FIELD",
        "INVALID_BUNDLE_TIME",
        "INVALID_BUNDLE_RUN",
        "BUNDLE_ISSUER_NOT_TRUSTED",
        "BUNDLE_NONCE_MISMATCH",
        "BUNDLE_ADAPTER_MISMATCH",
        "BUNDLE_SOURCE_COMMIT_MISMATCH",
        "BUNDLE_REPLAY_DETECTED",
        "BUNDLE_RUN_DIGEST_MISMATCH",
        "BUNDLE_ID_MISMATCH",
        "BUNDLE_SIGNATURE_NOT_VERIFIED",
    }
    if run is None or any(f["code"] in blocking for f in findings):
        return _result(findings, signature_ok, None)

    conformance = evaluate_run(
        run,
        trusted_observer_id=trusted_observer_id,
        trusted_observer_public_key=trusted_observer_public_key,
        trusted_closure_public_key=trusted_closure_public_key,
    )

    if conformance["status"] != "VERIFIED":
        add(
            "BUNDLE_CONTENT_NOT_VERIFIED",
            "bundle integrity verified but underlying execution evidence did not",
        )

    return _result(findings, signature_ok, conformance)


def _result(
    findings: list[dict[str, str]],
    signature_ok: bool,
    conformance: dict[str, Any] | None,
) -> dict[str, Any]:
    content_verified = (
        conformance is not None and conformance.get("status") == "VERIFIED"
    )
    status = "VERIFIED" if signature_ok and content_verified and not findings else "NOT VERIFIED"

    return {
        "schema": BUNDLE_SCHEMA,
        "status": status,
        "bundle_signature_verified": signature_ok,
        "content_conformance": conformance,
        "findings": findings,
    }
