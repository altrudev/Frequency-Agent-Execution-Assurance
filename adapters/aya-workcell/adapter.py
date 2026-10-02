from __future__ import annotations

from datetime import datetime
from typing import Any

from conformance import digest

PROFILE_SCHEMA = "frequency.aya-workcell-profile.v1"
RUN_SCHEMA = "frequency.aya-workcell-run.v1"


class AyaProfileError(ValueError):
    pass


def _epoch(value: str) -> int:
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except Exception as exc:
        raise AyaProfileError("invalid AYA timestamp") from exc


def validate_profile(profile: dict[str, Any]) -> None:
    if profile.get("schema") != PROFILE_SCHEMA:
        raise AyaProfileError("unsupported profile schema")
    if profile.get("aya_commit") != "bfa6019f1b5ad6a5c45ed32d799f4634bf5368ce":
        raise AyaProfileError("unexpected AYA source commit")
    if profile.get("runtime_status") != "research-frozen":
        raise AyaProfileError("AYA runtime status must remain research-frozen")
    if profile.get("production_execution_enabled") is not False:
        raise AyaProfileError("public reference adapter must remain non-executing")


def score_digest(score: dict[str, Any]) -> str:
    if score.get("schema") != "aya.score/v0":
        raise AyaProfileError("unsupported AYA Score")
    return digest(score).removeprefix("sha256:")


def lease_digest(lease: dict[str, Any]) -> str:
    if lease.get("schema") != "aya.lease/v0":
        raise AyaProfileError("unsupported AYA Lease")
    return digest(lease).removeprefix("sha256:")


def validate_capability_report(
    capability_report: dict[str, Any],
    lease: dict[str, Any],
) -> None:
    if capability_report.get("schema") != "aya.capability-report/v0":
        raise AyaProfileError("unsupported AYA CapabilityReport")
    if capability_report.get("runtimeId") != lease.get("workerId"):
        raise AyaProfileError("CapabilityReport runtime does not match Lease worker")

    levels = {"contract_only": 0, "process_isolated": 1, "os_enforced": 2}
    required = lease.get("isolationRequired")
    reported = capability_report.get("isolationLevel")
    if required not in levels or reported not in levels or levels[reported] < levels[required]:
        raise AyaProfileError("CapabilityReport isolation is weaker than Lease requirement")

    modes = capability_report.get("networkModes")
    if not isinstance(modes, list) or lease.get("network") not in modes:
        raise AyaProfileError("CapabilityReport does not admit the Lease network mode")


def candidate_effect_digest(receipt: dict[str, Any]) -> str:
    if receipt.get("schema") != "aya.receipt/v0":
        raise AyaProfileError("unsupported AYA Receipt")
    if receipt.get("status") != "candidate_ready":
        raise AyaProfileError("AYA receipt is not candidate_ready")
    candidate = receipt.get("candidate")
    if not isinstance(candidate, dict):
        raise AyaProfileError("candidate_ready receipt requires a candidate")

    sources = candidate.get("sources")
    if not isinstance(sources, list) or not sources:
        raise AyaProfileError("candidate must carry source verification")
    for source in sources:
        if (
            not isinstance(source, dict)
            or source.get("beforeSha256") != source.get("afterSha256")
        ):
            raise AyaProfileError("source mutation prevents candidate promotion")

    return digest(candidate)


def build_conformance_run(
    *,
    profile: dict[str, Any],
    score: dict[str, Any],
    lease: dict[str, Any],
    capability_report: dict[str, Any],
    receipt: dict[str, Any],
    principal: str,
    target: str,
    observer_id: str,
    observed_at: int,
    observation_effect_digest: str,
    receipt_anchor_ref: str,
    observation_receipt_ref: str,
) -> dict[str, Any]:
    validate_profile(profile)

    expected_score = score_digest(score)
    expected_lease = lease_digest(lease)
    validate_capability_report(capability_report, lease)

    if lease.get("scoreSha256") != expected_score:
        raise AyaProfileError("lease does not bind the supplied Score")
    if receipt.get("scoreSha256") != expected_score:
        raise AyaProfileError("receipt does not bind the supplied Score")
    if receipt.get("leaseSha256") != expected_lease:
        raise AyaProfileError("receipt does not bind the supplied Lease")

    required_isolation = score.get("isolationRequired")
    if lease.get("isolationRequired") != required_isolation:
        raise AyaProfileError("lease isolation does not satisfy the Score requirement")

    created_at = _epoch(lease["createdAt"])
    expires_at = _epoch(lease["expiresAt"])
    sealed_at = _epoch(receipt["sealedAt"])
    if expires_at < created_at:
        raise AyaProfileError("lease expiry precedes creation")
    if not (created_at <= sealed_at <= expires_at):
        raise AyaProfileError("receipt was sealed outside the lease window")

    effect = candidate_effect_digest(receipt)
    receipt_sha256 = receipt.get("receiptSha256")
    if (
        not isinstance(receipt_sha256, str)
        or len(receipt_sha256) != 64
        or any(c not in "0123456789abcdef" for c in receipt_sha256)
    ):
        raise AyaProfileError("AYA receiptSha256 must be a lowercase SHA-256 hex digest")

    request = {
        "aya_score_sha256": expected_score,
        "aya_lease_sha256": expected_lease,
        "aya_capability_report_digest": digest(capability_report),
        "aya_receipt_sha256": receipt_sha256,
        "worker_id": lease.get("workerId"),
        "isolation_required": required_isolation,
        "network": lease.get("network"),
        "allow_raw_code": lease.get("allowRawCode"),
    }

    return {
        "schema": RUN_SCHEMA,
        "intent": {
            "principal": principal,
            "target": target,
            "operation": "workcell.execute",
        },
        "authority": {
            "principal": principal,
            "target": target,
            "operation": "workcell.execute",
            "request_digest": digest(request),
            "valid_from": created_at,
            "valid_until": expires_at,
        },
        "execution": {
            "principal": principal,
            "target": target,
            "operation": "workcell.execute",
            "request": request,
            "started_at": sealed_at,
            "effect_digest": effect,
        },
        "observation": {
            "observer_id": observer_id,
            "independent": True,
            "target": target,
            "operation": "workcell.execute",
            "effect_digest": observation_effect_digest,
            "observed_at": observed_at,
        },
        "evidence": {
            "required_refs": ["aya_receipt_anchor", "observation_receipt"],
            "refs": {
                "aya_receipt_anchor": receipt_anchor_ref,
                "observation_receipt": observation_receipt_ref,
            },
        },
        "claims": {"external_effect_verified": True},
    }
