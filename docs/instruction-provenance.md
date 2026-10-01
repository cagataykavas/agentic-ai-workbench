# Instruction provenance gate

Tool-using agents routinely place retrieved pages, documents, memory and previous tool results into the same model context as trusted instructions. Text-level prompt-injection classifiers are useful signals, but they cannot establish whether untrusted content influenced tool selection or a sensitive argument.

`src/instruction_provenance.py` adds a framework-independent admission boundary before tool execution. It evaluates lineage metadata and content digests; raw prompts, retrieved text and arguments are not copied into the report.

## Security model

The producer records a bounded provenance DAG for each proposal:

- roots identify trusted control sources (`system`, `developer`, `user`) or untrusted sources (`retrieval`, `tool_result`, `memory`);
- derived nodes name their parents;
- `control_node_ids` identify evidence that influenced tool selection or control flow;
- JSON-pointer argument bindings identify evidence that influenced individual arguments;
- the proposal binds the exact canonical argument digest and policy digest.

Taint is monotonic: formatting, summarizing, parsing or model rewriting does not make an untrusted ancestor trusted. A tool rule may allow untrusted content at exact data-only paths, such as an email body, while requiring trusted lineage for sensitive paths such as the recipient. Exact matching prevents an allowance for `/body` from implicitly authorizing `/body/recipient`.

```python
rule = ToolRule(
    tool="send_email",
    required_lineage_paths=frozenset({"/recipient", "/body"}),
    allowed_untrusted_data_paths=frozenset({"/body"}),
)
```

An untrusted node may influence control or a sensitive argument only when a human approval receipt:

- binds the exact run, proposal digest and policy digest;
- names the exact tainted nodes being approved;
- is timezone-aware, active and within configured TTL/future-skew budgets;
- contains a hashed approver identity rather than a raw identifier.

Expired, future-dated, cross-run, stale-policy, unrelated or partially scoped receipts do not declassify evidence.

## Runtime placement

```text
context assembly -> planner -> provenance gate -> tool policy -> execution
```

The provenance gate complements the existing `ToolPolicy`; it does not replace authorization, argument validation, idempotency or side-effect reconciliation. A typical adapter should:

1. assign source IDs and digests when context enters the run;
2. preserve parent links through prompt construction and structured-output parsing;
3. build the proposal and argument bindings before calling a tool;
4. require `AdmissionReport.accepted` before passing the proposal to `GovernedAgentRuntime`;
5. store the report digest with the execution trace.

The API raises `MalformedEvidence` for structurally unsafe artifacts and returns stable policy reason codes for evaluable rejections. Reports contain counts, reason codes and a deterministic SHA-256 evidence identity, never raw source text or tool arguments.

## Fail-closed checks

- duplicate, missing, cross-run or cyclic graph nodes;
- invalid IDs, digests and JSON pointers;
- source nodes with parents or derived nodes without parents;
- node, parent and argument-binding budget breaches;
- duplicate tool rules and argument paths;
- missing required lineage and unknown tools;
- policy drift;
- untrusted control influence or sensitive-argument influence;
- malformed, expired, future-dated or incorrectly bound approvals.

## Limitations

The gate trusts the instrumentation that emits lineage. It cannot prove that a model adapter declared every influence, that a digest producer hashed the intended bytes, or that external content is semantically safe. A compromised orchestrator can lie about provenance; production systems should isolate the collector, sign evidence and bind the accepted proposal digest to the actual outbound tool request.

The default trusted-source set treats user instructions as authorized control input, still subject to the normal tool policy. Applications with delegated users or multi-tenant authority should narrow that set or add independently verified principal and capability evidence.

## Next step

Add an adapter that captures lineage from the concrete prompt/message builder and structured tool-call decoder, then sign the admission report and verify its proposal digest immediately before network dispatch.
