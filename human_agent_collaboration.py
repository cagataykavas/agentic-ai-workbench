from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class Decision(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    REVIEW = "review"


@dataclass(frozen=True)
class AgentAssessment:
    risk_score: float
    confidence: float
    rationale: list[str]
    evidence_ids: list[str]


@dataclass
class ReviewCase:
    case_id: str
    assessment: AgentAssessment
    decision: Decision = Decision.REVIEW
    reviewer_notes: list[str] = field(default_factory=list)
    agent_recommendation: Decision | None = None


class HumanAgentPolicy:
    """Reference policy for deciding when AI may act and when a human must review."""

    def __init__(
        self,
        low_risk_threshold: float = 0.25,
        high_risk_threshold: float = 0.80,
        autonomous_confidence: float = 0.90,
    ) -> None:
        if not 0 <= low_risk_threshold < high_risk_threshold <= 1:
            raise ValueError("invalid risk thresholds")
        self.low_risk_threshold = low_risk_threshold
        self.high_risk_threshold = high_risk_threshold
        self.autonomous_confidence = autonomous_confidence

    def route(self, assessment: AgentAssessment) -> Decision:
        if assessment.confidence < self.autonomous_confidence:
            return Decision.REVIEW
        if assessment.risk_score <= self.low_risk_threshold:
            return Decision.APPROVE
        if assessment.risk_score >= self.high_risk_threshold:
            return Decision.REJECT
        return Decision.REVIEW


def resolve_case(
    case: ReviewCase,
    policy: HumanAgentPolicy,
    human_decider: Callable[[ReviewCase], tuple[Decision, str]] | None = None,
) -> ReviewCase:
    recommendation = policy.route(case.assessment)
    case.agent_recommendation = recommendation

    if recommendation is not Decision.REVIEW:
        case.decision = recommendation
        return case

    if human_decider is None:
        case.decision = Decision.REVIEW
        return case

    decision, note = human_decider(case)
    case.decision = decision
    case.reviewer_notes.append(note)
    return case


if __name__ == "__main__":
    assessment = AgentAssessment(
        risk_score=0.61,
        confidence=0.94,
        rationale=["device changed recently", "transaction velocity elevated"],
        evidence_ids=["evt-17", "evt-21"],
    )
    case = ReviewCase(case_id="case-1001", assessment=assessment)
    policy = HumanAgentPolicy()

    result = resolve_case(
        case,
        policy,
        human_decider=lambda _: (Decision.APPROVE, "customer identity confirmed by reviewer"),
    )
    print(result)
