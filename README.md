# Frequency Agent Execution Assurance

**Govern what an AI agent is allowed to do, observe what it actually did, and preserve evidence of the resulting external state.**

Frequency Agent Execution Assurance is the public product and integration surface for Frequency workloads that cross an agent boundary into tools, generated artifacts, APIs, engines, repositories, deployment systems, or other external state.

The Frequency Core implementation is proprietary. This repository publishes the product boundary, evidence contract, integration profiles, evaluation material, and commercial tier model without exposing private enforcement logic.

## Why this exists

Modern agent workflows are no longer limited to generating text. An agent can call MCP tools, generate assets, spend credits, modify projects, upload artifacts, trigger workflows, publish builds, and change remote state.

Frequency models that path as:

`Intent -> Authority -> Tool -> Artifact -> Transformation -> External Effect -> Observation -> Evidence`

The core distinction is between what was requested, what authority was granted, what action was attempted, what external state actually changed, and what can be established afterward from evidence.

## First workload profile

The first public workload profile is **Generated Artifact / World Execution Assurance**. It is designed for workflows where an agent generates or edits 3D assets, game/world content, media, code, or other artifacts and then imports, uploads, publishes, or deploys them into another system.

See [Generated Artifact Assurance](docs/GENERATED-ARTIFACT-ASSURANCE.md).

## What the public surface can describe

- agent and tool identity;
- requested operation and bounded target;
- authority and capability scope;
- MCP/API operation identity;
- input and output artifact digests;
- provenance references;
- data-handling class;
- expected effect class;
- independent observation requirements;
- external state correlation;
- drift between intended and observed outcomes;
- receipts and evidence references.

## What this repository does not claim

This public repository does not itself execute third-party tools, prove that an external effect occurred, certify a vendor, or expose Frequency Core. A workflow is not considered externally verified merely because it produced a Frequency-shaped record. External-effect claims require the evidence and observers required by the active profile.

## Commercial tiers

Frequency is offered in three product tiers: **Community**, **Pro**, and **Business**. The public integration/evaluation surface is intentionally narrower than the licensed enforcement product.

See [Commercial Tiers](docs/COMMERCIAL-TIERS.md).

## AgenTrust ecosystem

The intended AgenTrust marketplace integration is vendor-maintained and scoped to reproducible interoperability claims. Marketplace status, conformance level, or verification tier must be assigned by AgenTrust maintainers under their published rules; this repository does not self-declare those statuses.

## Ownership

Copyright © 2026 Valentyn Rukhaylo / Altru.dev. All rights reserved.

See [LICENSE.md](LICENSE.md).
