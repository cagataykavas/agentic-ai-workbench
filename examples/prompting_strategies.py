"""Zero-shot, one-shot and few-shot prompting examples with a small evaluation harness.

The module is provider-agnostic: pass any callable that accepts a prompt and returns
text. This keeps the benchmark useful with local Hugging Face models or hosted LLMs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Example:
    text: str
    label: str


TRAIN_EXAMPLES = [
    Example("The transfer appeared twice on my statement.", "duplicate_transaction"),
    Example("I do not recognize this card purchase.", "card_fraud"),
    Example("My salary arrived but the balance has not updated.", "balance_issue"),
    Example("The ATM charged me but gave no cash.", "cash_withdrawal_issue"),
]

EVAL_SET = [
    Example("This payment is listed two times.", "duplicate_transaction"),
    Example("Someone used my card and it was not me.", "card_fraud"),
    Example("Cash machine debited me without dispensing money.", "cash_withdrawal_issue"),
]

LABELS = sorted({example.label for example in TRAIN_EXAMPLES})


def instruction(text: str) -> str:
    labels = ", ".join(LABELS)
    return f"Classify the banking support message into exactly one label: {labels}. Return only the label.\nMessage: {text}\nLabel:"


def zero_shot(text: str) -> str:
    return instruction(text)


def one_shot(text: str) -> str:
    demo = TRAIN_EXAMPLES[0]
    return f"{instruction(demo.text)} {demo.label}\n\n{instruction(text)}"


def few_shot(text: str, n: int = 3) -> str:
    demos = "\n\n".join(f"{instruction(example.text)} {example.label}" for example in TRAIN_EXAMPLES[:n])
    return f"{demos}\n\n{instruction(text)}"


def normalize(output: str) -> str:
    return output.strip().lower().splitlines()[0].strip(" .`\"")


def evaluate(generate: Callable[[str], str]) -> dict[str, float]:
    strategies = {
        "zero_shot": zero_shot,
        "one_shot": one_shot,
        "few_shot": few_shot,
    }
    scores: dict[str, float] = {}
    for name, builder in strategies.items():
        correct = 0
        for example in EVAL_SET:
            prediction = normalize(generate(builder(example.text)))
            correct += prediction == example.label
        scores[name] = correct / len(EVAL_SET)
    return scores


if __name__ == "__main__":
    for strategy in (zero_shot, one_shot, few_shot):
        print(f"\n--- {strategy.__name__} ---")
        print(strategy("The same transfer is showing twice."))
