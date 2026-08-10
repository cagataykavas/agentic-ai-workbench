# Agentic AI Workbench

A small, inspectable playground for tool-using AI workflows. The goal is not to hide everything behind an agent framework, but to make planning, tool selection, state transitions, retries and evaluation visible in code.

## Public baseline

The first workflow uses deterministic local tools only:

- calculator
- small document search tool
- structured planner
- bounded execution loop
- trace logging
- simple task-success evaluation

No paid API key is required for the baseline. An LLM adapter can be added later behind the same planner interface.

## Architecture

```text
user task
   |
   v
planner ---> tool registry
   |             |
   v             v
execution <--- tool result
   |
   v
trace + evaluation
```

## Design principles

- explicit tool contracts;
- bounded step count;
- structured state instead of hidden conversation magic;
- deterministic baseline for tests;
- trace every plan/action/result;
- separate task success from model verbosity.

## Run

```bash
python -m src.demo
```
