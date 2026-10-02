# Public Evidence Contract

Frequency separates five facts that are often collapsed in agent tooling:

1. **Intent** — what the user or upstream system asked for.
2. **Authority** — what the agent was actually permitted to attempt.
3. **Execution** — what operation crossed the governed boundary.
4. **Observation** — what an observer established about the resulting state.
5. **Verification** — what claims the available evidence is sufficient to support.

A successful request is not evidence of a successful effect. A successful tool response is not automatically evidence of durable external state. A generated artifact is not automatically evidence that the artifact was imported, published, deployed, or used.

Public integrations should therefore preserve explicit claim ceilings. When evidence is incomplete, the correct state is **NOT VERIFIED**, not an inferred success.
