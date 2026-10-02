# Generated Artifact / World Execution Assurance Profile

## Purpose

This profile covers agent workflows that generate or modify an artifact and then cause that artifact, or a transformation derived from it, to affect another system.

Examples include 3D/world generation, game-engine content, code generation followed by deployment, media pipelines, design-to-runtime workflows, and agent-driven publishing.

## Evidence chain

A governed run should be representable as:

`Intent -> Plan -> Authority -> Tool Call -> Artifact -> Transformation -> External Mutation -> Observation -> Receipt`

The profile keeps these stages distinct so a tool response cannot be silently promoted into a claim that the target system changed.

## Minimum correlation fields

A workload should preserve, where applicable:

- run and action identity;
- principal / agent identity;
- target system and bounded resource;
- capability and operation;
- tool or API identity;
- input digest;
- generated artifact digest and version;
- provenance reference;
- transformation identity;
- credential-binding reference without raw secret material;
- requested and observed effect class;
- external target identifier;
- independent observation reference;
- trusted observer-attestation reference when external-effect verification is claimed;
- signed closing commitment binding authority, execution, observation, and required evidence;
- drift or mismatch status.

## Fail-closed conditions

A mutating action should not be promoted as verified when any required binding is absent, including:

- missing authority for the exact target or operation;
- unbound credential use;
- artifact digest or provenance loss;
- tool-call identity mismatch;
- external target mismatch;
- missing required observer or unverified observer signature;
- observed state that cannot be correlated to the governed action;
- missing or invalid signed closing commitment;
- cumulative disclosure or resource-budget violation.

## Vendor boundary

The profile is vendor-neutral. Vendor-specific adapters should translate their operation vocabulary into the Frequency evidence contract without copying proprietary Frequency Core logic into the adapter.

A vendor integration can expose enough information for customers and reviewers to reproduce interoperability while keeping each party's private implementation separate.

## Current status

This is an integration profile and product boundary. Support for a specific vendor, engine, marketplace, or external execution target must be claimed only after a concrete adapter and reproducible test path exist.
