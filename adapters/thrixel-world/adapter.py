from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from conformance import digest

PROFILE_SCHEMA = "frequency.thrixel-world-profile.v1"
RUN_SCHEMA = "frequency.thrixel-world-run.v1"


class ThrixelProfileError(ValueError):
    pass


def load_profile(path: str | Path) -> dict[str, Any]:
    profile = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(profile, dict):
        raise ThrixelProfileError("profile must be a JSON object")
    validate_profile(profile)
    return profile


def validate_profile(profile: dict[str, Any]) -> None:
    if profile.get("schema") != PROFILE_SCHEMA:
        raise ThrixelProfileError("unsupported profile schema")

    transport = profile.get("transport")
    operations = profile.get("operations")
    if not isinstance(transport, dict) or not isinstance(operations, dict):
        raise ThrixelProfileError("transport and operations are required")

    if transport.get("package") != "thrixel-mcp":
        raise ThrixelProfileError("unexpected transport package")
    if transport.get("server_name") != "thrixel":
        raise ThrixelProfileError("unexpected MCP server name")
    if transport.get("production_execution_enabled") is not False:
        raise ThrixelProfileError("public reference transport must remain non-executing")

    version = transport.get("version")
    wheel_sha256 = transport.get("wheel_sha256")
    if not isinstance(version, str) or not version or version == "latest":
        raise ThrixelProfileError("transport version must be exact and immutable")
    if (
        not isinstance(wheel_sha256, str)
        or len(wheel_sha256) != 64
        or any(c not in "0123456789abcdefABCDEF" for c in wheel_sha256)
    ):
        raise ThrixelProfileError("transport wheel_sha256 must be a 64-character hex digest")

    for name, operation in operations.items():
        if not isinstance(name, str) or not isinstance(operation, dict):
            raise ThrixelProfileError("invalid operation entry")
        if not isinstance(operation.get("mapped_operation"), str):
            raise ThrixelProfileError(f"{name}: mapped_operation is required")
        if operation.get("authority_requirement") not in {"Delegated", "OwnerRequired"}:
            raise ThrixelProfileError(f"{name}: invalid authority requirement")
        if not isinstance(operation.get("mutates_external_state"), bool):
            raise ThrixelProfileError(f"{name}: mutates_external_state must be boolean")
        if not isinstance(operation.get("requires_independent_observation"), bool):
            raise ThrixelProfileError(
                f"{name}: requires_independent_observation must be boolean"
            )
def canonical_arguments(arguments: dict[str, Any]) -> str:
    if not isinstance(arguments, dict):
        raise ThrixelProfileError("tool arguments must be an object")
    return json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def prepare_call(
    profile: dict[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    validate_profile(profile)

    operations = profile["operations"]
    operation = operations.get(tool_name)
    if not isinstance(operation, dict):
        raise ThrixelProfileError("unknown Thrixel tool")
    if operation.get("disabled") is True:
        raise ThrixelProfileError("operation is disabled by the public reference profile")

    canonical = canonical_arguments(arguments)
    transport = profile["transport"]

    return {
        "schema": "frequency.thrixel-prepared-call.v1",
        "vendor": profile["vendor"],
        "server_name": transport["server_name"],
        "transport_package": transport["package"],
        "transport_version": transport["version"],
        "transport_wheel_sha256": transport["wheel_sha256"],
        "tool_name": tool_name,
        "mapped_operation": operation["mapped_operation"],
        "arguments": json.loads(canonical),
        "arguments_digest": digest(json.loads(canonical)),
        "authority_requirement": operation["authority_requirement"],
        "mutates_external_state": operation["mutates_external_state"],
        "requires_independent_observation": operation[
            "requires_independent_observation"
        ],
        "production_execution_enabled": False,
    }


def validate_prepared_call(
    profile: dict[str, Any],
    prepared_call: dict[str, Any],
) -> None:
    if prepared_call.get("schema") != "frequency.thrixel-prepared-call.v1":
        raise ThrixelProfileError("invalid prepared call")

    tool_name = prepared_call.get("tool_name")
    arguments = prepared_call.get("arguments")
    if not isinstance(tool_name, str) or not isinstance(arguments, dict):
        raise ThrixelProfileError("prepared call is missing tool_name or arguments")

    rebuilt = prepare_call(profile, tool_name, arguments)
    if rebuilt != prepared_call:
        raise ThrixelProfileError("prepared call no longer matches the pinned profile")


def build_conformance_run(
    *,
    profile: dict[str, Any],
    prepared_call: dict[str, Any],
    principal: str,
    target: str,
    valid_from: int,
    valid_until: int,
    started_at: int,
    effect_digest: str,
    observer_id: str,
    observed_at: int,
    observation_effect_digest: str,
    execution_receipt: str,
    observation_receipt: str,
) -> dict[str, Any]:
    validate_prepared_call(profile, prepared_call)

    if prepared_call.get("production_execution_enabled") is not False:
        raise ThrixelProfileError("public adapter cannot enable production execution")
    if prepared_call.get("mutates_external_state") is not True:
        raise ThrixelProfileError("this run builder is for mutating external operations")
    if prepared_call.get("requires_independent_observation") is not True:
        raise ThrixelProfileError("mutating run must require independent observation")

    request = {
        "vendor": prepared_call["vendor"],
        "server_name": prepared_call["server_name"],
        "transport_package": prepared_call["transport_package"],
        "transport_version": prepared_call["transport_version"],
        "transport_wheel_sha256": prepared_call["transport_wheel_sha256"],
        "tool_name": prepared_call["tool_name"],
        "mapped_operation": prepared_call["mapped_operation"],
        "arguments": prepared_call["arguments"],
        "arguments_digest": prepared_call["arguments_digest"],
    }

    mapped_operation = prepared_call["mapped_operation"]
    run = {
        "schema": RUN_SCHEMA,
        "intent": {
            "principal": principal,
            "target": target,
            "operation": mapped_operation,
        },
        "authority": {
            "principal": principal,
            "target": target,
            "operation": mapped_operation,
            "request_digest": digest(request),
            "valid_from": valid_from,
            "valid_until": valid_until,
            "authority_requirement": prepared_call["authority_requirement"],
        },
        "execution": {
            "principal": principal,
            "target": target,
            "operation": mapped_operation,
            "request": request,
            "started_at": started_at,
            "effect_digest": effect_digest,
        },
        "observation": {
            "observer_id": observer_id,
            "independent": True,
            "target": target,
            "operation": mapped_operation,
            "effect_digest": observation_effect_digest,
            "observed_at": observed_at,
        },
        "evidence": {
            "required_refs": ["execution_receipt", "observation_receipt"],
            "refs": {
                "execution_receipt": execution_receipt,
                "observation_receipt": observation_receipt,
            },
        },
        "claims": {"external_effect_verified": True},
    }
    return run
