from __future__ import annotations

import ast
import operator

from .core import Agent, Tool, ToolRegistry

DOCS = {
    "rag": "RAG retrieves relevant context before generation and should evaluate retrieval independently from answer quality.",
    "xai": "Explainable AI includes attribution, representation analysis, counterfactuals and causal interventions.",
}

OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv, ast.Pow: operator.pow}


def safe_calculator(text: str):
    expression = text.lower().replace("calculate", "").replace("what is", "").strip().rstrip("?")
    tree = ast.parse(expression, mode="eval")

    def visit(node):
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in OPS:
            return OPS[type(node.op)](visit(node.left), visit(node.right))
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -visit(node.operand)
        raise ValueError("unsupported expression")

    return visit(tree)


def search(text: str):
    query = set(text.lower().split())
    scored = []
    for key, body in DOCS.items():
        score = len(query & set((key + " " + body).lower().split()))
        scored.append((score, key, body))
    score, key, body = max(scored)
    return {"document": key, "score": score, "text": body}


def main() -> None:
    registry = ToolRegistry()
    registry.register(Tool("calculator", "Evaluate bounded arithmetic expressions", safe_calculator))
    registry.register(Tool("search", "Search a tiny local knowledge base", search))
    agent = Agent(registry)

    for task in ["calculate 12 * 7 + 3", "find what does RAG evaluate"]:
        state = agent.run(task)
        print(f"TASK: {task}\nANSWER: {state.answer}")
        for event in state.trace:
            print(f"  step={event.step} action={event.action} output={event.output}")
        print()


if __name__ == "__main__":
    main()
