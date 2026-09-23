# Tool-result admission boundary

Tool handlers are external trust boundaries. A successful HTTP request, database query, browser
operation or connector call can still return unexpectedly large, malformed or adversarial content.
Passing that content directly into traces, retry stores or a later model prompt makes resource use
and evidence identity difficult to reason about.

`src/tool_result_admission.py` adds a dependency-free, fail-closed admission step between handler
execution and successful runtime state.

## Contract

An admitted result must be a JSON object containing only JSON-native values. The boundary rejects:

- non-string object keys and Python-only values such as tuples, bytes or custom objects;
- `NaN` and infinite numbers;
- cyclic containers;
- excessive nesting, items per container or total nodes;
- oversized keys, strings or canonical serialized payloads.

Accepted results are encoded as canonical UTF-8 JSON with sorted keys. The runtime records the exact
byte count and SHA-256 digest in `ActionResult`, and the idempotency ledger retains the immutable
canonical representation. A replay is revalidated against the active policy before it is returned,
so sharing a ledger with a stricter runtime cannot bypass the stricter limits.

Defaults are intentionally conservative for control-plane style tools:

| Limit | Default |
| --- | ---: |
| Canonical payload | 32 KiB |
| Nesting depth | 8 |
| Items per container | 256 |
| Total JSON nodes | 2,048 |
| One string | 4 KiB |
| One object key | 128 bytes |

Configure a runtime-wide policy or override it for a specific tool:

```python
from src.governed_runtime import GovernedAgentRuntime, ToolRegistry, ToolSpec
from src.tool_result_admission import ToolResultPolicy

registry = ToolRegistry()
registry.register(
    ToolSpec(
        name="search",
        description="Return bounded search evidence",
        handler=lambda _args: {"documents": [{"id": "doc-1", "text": "evidence"}]},
        result_policy=ToolResultPolicy(max_serialized_bytes=16_384, max_container_items=50),
    )
)
runtime = GovernedAgentRuntime(registry)
```

Policy rejection produces `status="failed"`, no output, and a stable `error_code` such as
`depth_exceeded` or `serialized_size_exceeded`. Error details report only types and observed sizes;
they do not echo rejected content.

## Downstream model context

`AdmittedToolResult.context_envelope()` provides an explicit structured boundary:

```json
{
  "trust": "untrusted_tool_output",
  "tool": "search",
  "content_sha256": "...",
  "content": {"documents": []}
}
```

The envelope is a protocol marker for a prompt builder. It does **not** sanitize natural-language
content or detect prompt injection. Downstream code must keep `content` separate from system and
developer instructions, apply domain-specific schemas, and avoid granting authority based on text
inside tool output.

## Operational limits

- SHA-256 identifies exact admitted bytes; it does not establish source authenticity. Signed tool
  responses or transport attestations are a separate concern.
- Resource limits constrain the admitted representation, not bytes already buffered by an HTTP SDK.
  Network clients should also enforce response-size and timeout limits while streaming.
- The in-memory ledger is a reference implementation. Production replay stores need durable writes,
  retention controls and tenant isolation.
- Generic JSON validation does not replace tool-specific schemas, content filtering or authorization.

The next production step is a prompt builder that accepts only these envelopes and emits provenance
links from model claims back to admitted content digests.
