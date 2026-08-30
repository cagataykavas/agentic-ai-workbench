from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Tool:
    name: str
    description: str
    fn: Callable[[str], Any]


@dataclass
class TraceEvent:
    step: int
    action: str
    input: str
    output: str


@dataclass
class AgentState:
    task: str
    trace: list[TraceEvent] = field(default_factory=list)
    answer: str | None = None


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def call(self, name: str, payload: str):
        if name not in self._tools:
            raise KeyError(f"unknown tool: {name}")
        return self._tools[name].fn(payload)

    @property
    def names(self) -> list[str]:
        return sorted(self._tools)


class DeterministicPlanner:
    """Small transparent baseline planner used before adding any LLM adapter."""

    def plan(self, state: AgentState, registry: ToolRegistry) -> tuple[str, str]:
        text = state.task.lower()
        if any(token in text for token in ["calculate", "sum", "multiply", "+", "*"]):
            return "calculator", state.task
        if any(token in text for token in ["search", "document", "what does", "find"]):
            return "search", state.task
        return "finish", "No tool required."


class Agent:
    def __init__(self, registry: ToolRegistry, planner=None, max_steps: int = 4) -> None:
        self.registry = registry
        self.planner = planner or DeterministicPlanner()
        self.max_steps = max_steps

    def run(self, task: str) -> AgentState:
        state = AgentState(task=task)
        for step in range(1, self.max_steps + 1):
            action, payload = self.planner.plan(state, self.registry)
            if action == "finish":
                state.answer = payload
                state.trace.append(TraceEvent(step, action, payload, payload))
                return state
            result = self.registry.call(action, payload)
            state.trace.append(TraceEvent(step, action, payload, str(result)))
            state.answer = str(result)
            return state
        state.answer = "Step budget exhausted."
        return state
