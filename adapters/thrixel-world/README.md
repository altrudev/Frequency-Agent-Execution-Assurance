# Frequency Agent Execution Assurance — Thrixel / World Adapter

This public adapter maps a pinned Thrixel MCP workload profile into the Frequency Agent Execution Assurance public conformance contract.

It is intentionally **non-executing**. It does not launch the Thrixel MCP server, read credentials, spend Cubes, publish games, or call a vendor API. Its job is to bind the exact intended tool call and produce a conformance envelope that can only reach an external-effect claim after independent observation and signed evidence closure.

## Current reference pin

- package: `thrixel-mcp`
- pinned version: `1.3.17`
- pinned wheel SHA-256: `cd61d32f173736b8cee7d4c68417f67d90ecc58832417b96d5159e5cc7ceec02`
- MCP server name: `thrixel`
- production execution: disabled

These values are a reproducible reference pin. They are not a claim that this is the vendor's newest release.

## Supported mutating reference operations

The current public profile maps model generation/refinement and project-organization operations into generic Frequency semantics such as:

- `artifact.generate`
- `artifact.transform`
- `project.create`
- `project.source.add`

Each mutating operation requires independent observation before the resulting external effect may be promoted to the highest public claim ceiling.

## Disabled boundaries

The public reference adapter fails closed for:

- `thrixel_publish_game`;
- `thrixel_buy_cubes`;
- `thrixel_upgrade_plan`;
- `thrixel_billing_portal`;
- unknown tools;
- mutable `latest` transport selection;
- changed or malformed transport pins;
- any profile that enables production execution.

This keeps owner-required publishing and financial actions outside the reference adapter.

## Evidence path

A prepared call binds:

`transport pin + tool + mapped operation + canonical arguments + argument digest`

A mutating workload is then represented as:

`Intent -> Authority -> Prepared Thrixel Call -> Execution -> Independent Observation -> Signed Closure`

The public conformance evaluator separately requires a trusted observer identity, a trusted observer signature, exact observed-effect correlation, required evidence references, and a trusted closing signature.

A Thrixel tool response by itself is therefore not sufficient to establish that an asset or world changed.

## Run tests

```bash
pytest -q adapters/thrixel-world/tests
```

The tests are synthetic interoperability/conformance tests. They do not contact Thrixel and do not claim vendor certification or production compatibility.

## Product boundary

This adapter exposes only public integration semantics. Frequency Core enforcement, credential custody, policy internals, production transports, and proprietary analysis remain outside this repository.
