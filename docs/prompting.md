# Zero-shot, one-shot and few-shot prompting

This workbench treats prompting strategies as configurations that should be evaluated, not magic incantations.

## Zero-shot

The model receives an instruction and the task input but no worked example. It is cheap in context tokens and useful when the instruction and label semantics are already clear.

## One-shot

One demonstration is placed in context before the target input. It can establish the expected output format and show how an ambiguous instruction should be interpreted.

## Few-shot

Several demonstrations are provided in-context. This can improve task adaptation and label grounding without updating model weights, but consumes more context and can become sensitive to example selection, ordering and class balance.

## Important distinction

Few-shot prompting is **in-context learning**, not gradient-based fine-tuning. Model parameters are not updated. Fine-tuning changes parameters using training data; prompting changes the context supplied at inference time.

## What to measure

The included benchmark compares the same evaluation set under zero-, one- and few-shot templates. For a serious experiment, report accuracy/F1 as appropriate, token count, latency, cost, output-format compliance, variance across prompt/example orderings and the exact model/version used.

The examples use synthetic banking-support messages so the repository remains safe to publish.
