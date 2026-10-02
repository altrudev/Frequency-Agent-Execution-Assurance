# Frequency Agent Execution Assurance — AYA Workcell Reference Adapter

This public adapter maps the frozen AYA MCP v0 workcell protocol into the Frequency Agent Execution Assurance public conformance model.

Pinned AYA source commit:

`bfa6019f1b5ad6a5c45ed32d799f4634bf5368ce`

AYA describes the repository at that commit as completed research with runtime development frozen. Its Public/Worker runtime is synthetic and is not an operating-system sandbox or production DCC security boundary. This adapter preserves that boundary.

## Mapping

Frequency treats the AYA documents as distinct evidence stages:

- `Score` -> human intent and requested constraints;
- `Lease` -> temporary authority for a workcell;
- `CapabilityReport` -> runtime self-report bound into the execution request, but not treated as independent proof of enforcement;
- `Receipt` -> execution/candidate evidence;
- candidate artifact/evidence set -> resulting effect digest;
- separately trusted observer -> independent observation;
- Frequency signed closure -> closing evidence commitment.

An AYA receipt is not used as Frequency's independent observer.

AYA's v0 protocol states that its receipt event chain and final receipt digest establish internal consistency, but mutation protection requires the final digest to be anchored through a trusted external channel. The receipt digest is not an identity signature. Frequency therefore preserves the AYA receipt/anchor as execution evidence and still requires a separately trusted observer before an external-effect claim can reach `VERIFIED`.

## Fail-closed checks

The adapter rejects:

- a Lease that does not bind the supplied Score;
- a Receipt that does not bind the exact Score and Lease;
- a CapabilityReport that does not match the Lease worker or admits weaker isolation/network capability than required;
- a Lease that downgrades the Score's requested isolation level;
- a receipt sealed outside the lease validity window;
- a receipt that is not `candidate_ready`;
- a malformed native receipt digest;
- source mutation in the candidate source-verification set;
- a missing candidate;
- a mismatched independently observed candidate digest;
- any profile that changes the pinned AYA source commit, claims a live runtime, or enables production execution.

## What this does not claim

This adapter does not:

- execute an AYA workcell;
- authorize AYA Thin or any new AYA runtime;
- claim AYA provides an OS sandbox;
- claim production Blender, TouchDesigner, After Effects, or other DCC execution;
- reinterpret AYA's `contract_only` workcells as stronger isolation;
- treat an AYA worker receipt as an identity signature;
- treat AYA internal receipt consistency as independent external observation;
- expose Frequency Core.

The adapter is a public interoperability reference only.

## Run

```bash
pytest -q adapters/aya-workcell/tests
```
