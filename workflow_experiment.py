from __future__ import annotations

from dataclasses import dataclass
import math


@dataclass(frozen=True)
class WorkflowMetrics:
    cases: int
    correct_decisions: int
    automated_cases: int
    human_overrides: int
    total_seconds: float
    customer_dropoffs: int

    @property
    def accuracy(self) -> float:
        return self.correct_decisions / self.cases if self.cases else 0.0

    @property
    def automation_rate(self) -> float:
        return self.automated_cases / self.cases if self.cases else 0.0

    @property
    def override_rate(self) -> float:
        return self.human_overrides / self.cases if self.cases else 0.0

    @property
    def mean_time_seconds(self) -> float:
        return self.total_seconds / self.cases if self.cases else 0.0

    @property
    def dropoff_rate(self) -> float:
        return self.customer_dropoffs / self.cases if self.cases else 0.0


def utility(m: WorkflowMetrics) -> float:
    """Toy multi-objective utility for comparing service prototypes."""
    speed_score = math.exp(-m.mean_time_seconds / 120.0)
    return (
        0.45 * m.accuracy
        + 0.20 * m.automation_rate
        + 0.15 * speed_score
        - 0.10 * m.override_rate
        - 0.10 * m.dropoff_rate
    )


def compare(a: WorkflowMetrics, b: WorkflowMetrics) -> dict[str, float | str]:
    ua, ub = utility(a), utility(b)
    winner = "A" if ua > ub else "B" if ub > ua else "tie"
    return {
        "winner": winner,
        "utility_a": ua,
        "utility_b": ub,
        "accuracy_delta": b.accuracy - a.accuracy,
        "automation_delta": b.automation_rate - a.automation_rate,
        "mean_time_delta_seconds": b.mean_time_seconds - a.mean_time_seconds,
        "dropoff_delta": b.dropoff_rate - a.dropoff_rate,
    }


if __name__ == "__main__":
    baseline = WorkflowMetrics(1000, 930, 200, 90, 95_000, 75)
    prototype = WorkflowMetrics(1000, 948, 510, 55, 61_000, 42)
    print(compare(baseline, prototype))
