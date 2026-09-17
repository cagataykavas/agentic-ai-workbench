import json

import pytest

from src.trajectory_eval import (
    ExpectedStep,
    evaluate_suite,
    evaluate_trajectory,
    load_case,
    main,
)


def _trace():
    return {
        "task": "lookup record",
        "planned_actions": 1,
        "max_steps": 8,
        "stopped_reason": "plan_completed",
        "results": [
            {
                "action_id": "lookup-1",
                "tool": "lookup",
                "status": "succeeded",
                "output": {"record": {"id": "A-17", "active": True}},
                "error": None,
                "policy": {"decision": "allow", "reason": "tool may execute automatically"},
                "idempotency_key": "example",
            }
        ],
    }


def test_trajectory_evaluation_passes_with_nested_partial_output():
    result = evaluate_trajectory(
        "lookup contract",
        [ExpectedStep("lookup", "succeeded", {"record": {"id": "A-17"}})],
        _trace(),
    )

    assert result.passed
    assert result.assertion_rate == 1.0
    assert result.to_dict()["matched_outputs"] == 1


def test_trajectory_evaluation_reports_action_drift():
    trace = _trace()
    trace["results"].append({"tool": "publish", "status": "succeeded", "output": {}})

    result = evaluate_trajectory(
        "no surprise writes",
        [ExpectedStep("search", "denied", {"reason": "safe"})],
        trace,
    )

    assert not result.passed
    assert result.assertions == 0
    assert any("unexpected action 'publish'" in failure for failure in result.failures)


def test_suite_aggregates_case_and_assertion_rates():
    trace = _trace()
    suite = evaluate_suite(
        [
            ("passing", [ExpectedStep("lookup", "succeeded")], trace),
            ("failing", [ExpectedStep("lookup", "denied")], trace),
        ]
    )

    assert suite.cases == 2
    assert suite.passed_cases == 1
    assert suite.pass_rate == 0.5
    assert suite.assertion_rate == pytest.approx(5 / 6)


def test_load_case_validates_schema(tmp_path):
    expectation = tmp_path / "expectation.json"
    trace = tmp_path / "trace.json"
    expectation.write_text(json.dumps({"name": "case", "steps": [{"tool": "lookup"}]}))
    trace.write_text(json.dumps(_trace()))

    with pytest.raises(ValueError, match="status"):
        load_case(expectation, trace)


def test_cli_returns_nonzero_for_regression(tmp_path, monkeypatch, capsys):
    expectation = tmp_path / "expectation.json"
    trace = tmp_path / "trace.json"
    expectation.write_text(
        json.dumps({"name": "approval gate", "steps": [{"tool": "lookup", "status": "denied"}]})
    )
    trace.write_text(json.dumps(_trace()))
    monkeypatch.setattr("sys.argv", ["trajectory-eval", str(expectation), str(trace)])

    assert main() == 1
    assert '"passed": false' in capsys.readouterr().out
