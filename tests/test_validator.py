"""The Validator's TP/FP split is the only deterministic thing standing between
the orchestrator and a bogus FP curve. These tests pin the contract."""

from __future__ import annotations

from typing import Any

import pytest

from counterspell.agents.validator import Validator
from counterspell.schemas import AttackEvent, AttackScenario


class FakeMCP:
    """Returns whatever rows the test injects, ignoring SPL."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, str, str]] = []

    def run_query(self, spl: str, earliest: str = "-30d", latest: str = "now"):
        self.calls.append((spl, earliest, latest))
        return self.rows


class ExplodingMCP:
    """Simulates a search that fails to execute (malformed SPL, bad field)."""

    def run_query(self, spl: str, earliest: str = "-30d", latest: str = "now"):
        raise RuntimeError("Error in 'search' command: invalid field 'nope'")


def _scenario(**attacker: str) -> AttackScenario:
    return AttackScenario(
        scenario_id="brute-force-2026-05-29",
        attacker=attacker or {"user": "evil_user", "src_ip": "10.99.99.99",
                              "host": "victim-host"},
        window={"earliest": "2026-05-29T00:00:00Z",
                "latest": "2026-05-29T01:00:00Z"},
        events=[AttackEvent(sourcetype="cs:auth", fields={})],
    )


def test_tp_attributed_by_scenario_id():
    """A row carrying cs_scenario_id is a TP regardless of other fields."""
    scen = _scenario(user="evil_user", src_ip="10.99.99.99", host="victim-host")
    rows = [
        {"cs_scenario_id": "brute-force-2026-05-29", "count": 23},
        {"user": "alice", "src_ip": "10.0.0.1", "count": 4},
    ]
    v = Validator(FakeMCP(rows))
    r = v.backtest(1, 'search index="counterspell" ...', scen)
    assert r.tp_caught is True
    assert r.fp_count == 1
    assert r.sample_fps and r.sample_fps[0]["user"] == "alice"


def test_tp_attributed_by_attacker_identity_when_scenario_id_aggregated_out():
    """`stats by user` drops cs_scenario_id; attacker user value should still win."""
    scen = _scenario(user="evil_user", src_ip="10.99.99.99", host="victim-host")
    rows = [
        {"user": "evil_user", "count": 23},                # TP via user
        {"src_ip": "10.99.99.99", "count": 1},             # TP via src_ip
        {"host": "victim-host", "count": 1},               # TP via host
        {"user": "alice", "src_ip": "10.0.0.1", "count": 4},  # FP
    ]
    v = Validator(FakeMCP(rows))
    r = v.backtest(2, "spl", scen)
    assert r.tp_caught is True
    assert r.fp_count == 1


def test_tp_caught_false_when_no_marker_present():
    scen = _scenario(user="evil_user", src_ip="10.99.99.99", host="victim-host")
    rows = [
        {"user": "alice", "count": 4},
        {"user": "bob", "count": 9},
    ]
    v = Validator(FakeMCP(rows))
    r = v.backtest(1, "spl", scen)
    assert r.tp_caught is False
    assert r.fp_count == 2


def test_empty_rows_means_no_tp_no_fp():
    scen = _scenario()
    v = Validator(FakeMCP([]))
    r = v.backtest(1, "spl", scen)
    assert r.tp_caught is False
    assert r.fp_count == 0
    assert r.sample_fps == []


def test_sample_fps_capped_at_five():
    scen = _scenario()
    rows = [{"user": f"user{i}", "count": i} for i in range(20)]
    v = Validator(FakeMCP(rows))
    r = v.backtest(1, "spl", scen)
    assert r.tp_caught is False
    assert r.fp_count == 20
    assert len(r.sample_fps) == 5


def test_marker_matching_is_case_insensitive_substring():
    """`UserName=Evil_User` should still match attacker user=evil_user."""
    scen = _scenario(user="evil_user", src_ip="10.99.99.99", host="victim-host")
    rows = [
        {"UserName": "Evil_User"},          # TP (case-insensitive match)
        {"src": "request from 10.99.99.99"},  # TP (substring)
    ]
    v = Validator(FakeMCP(rows))
    r = v.backtest(1, "spl", scen)
    assert r.tp_caught is True
    assert r.fp_count == 0


def test_empty_attacker_values_do_not_match_everything():
    """Bug guard: an empty attacker value must not turn every row into a TP."""
    scen = AttackScenario(
        scenario_id="",
        attacker={"user": "", "src_ip": "", "host": ""},
        window={"earliest": "", "latest": ""},
        events=[],
    )
    rows = [
        {"user": "alice", "count": 4},
        {"user": "bob", "count": 9},
    ]
    v = Validator(FakeMCP(rows))
    r = v.backtest(1, "spl", scen)
    assert r.tp_caught is False
    assert r.fp_count == 2


def test_count_ending_in_attacker_ip_digits_is_not_a_false_tp():
    """Regression: the old blob-substring split flagged a benign `count=4799`
    as a TP because attacker src_ip ended in `99`. Value-exact matching must
    NOT match a number against an IP."""
    scen = _scenario(user="evil_user", src_ip="10.99.99.99", host="victim-host")
    rows = [
        {"user": "alice", "count": 4799},   # contains "99" but is NOT the attacker
        {"user": "bob", "count": 99},        # literally 99, still not the IP
    ]
    v = Validator(FakeMCP(rows))
    r = v.backtest(1, "spl", scen)
    assert r.tp_caught is False
    assert r.fp_count == 2


def test_attacker_ip_inside_multivalue_field_is_a_tp():
    """A `values(src_ip)` cell containing the attacker IP as a whole token
    should match, even alongside other IPs."""
    scen = _scenario(user="evil_user", src_ip="10.99.99.99", host="victim-host")
    rows = [
        {"src_ip": "10.0.0.5\n10.99.99.99\n10.0.0.6", "count": 3},
    ]
    v = Validator(FakeMCP(rows))
    r = v.backtest(1, "spl", scen)
    assert r.tp_caught is True
    assert r.fp_count == 0


def test_holdout_rows_excluded_from_fp_count():
    """cs_holdout=true rows are the generalization set — never counted as
    tuning FPs and never shown to the Architect."""
    scen = _scenario(user="evil_user", src_ip="10.99.99.99", host="victim-host")
    rows = [
        {"cs_scenario_id": "brute-force-2026-05-29", "count": 23},  # TP
        {"user": "alice", "count": 4},                              # real FP
        {"user": "svc_nightly_etl", "count": 12, "cs_holdout": "true"},  # holdout
        {"src_ip": "10.0.250.5", "count": 1, "cs_holdout": "true"},     # holdout
    ]
    v = Validator(FakeMCP(rows))
    r = v.backtest(1, "spl", scen)
    assert r.tp_caught is True
    assert r.fp_count == 1  # only alice; the two holdout rows are excluded
    assert all(row.get("cs_holdout") != "true" for row in r.sample_fps)


def test_search_failure_does_not_crash_and_is_recoverable():
    """A search that fails to execute must yield a recoverable result, not raise."""
    scen = _scenario()
    v = Validator(ExplodingMCP())
    r = v.backtest(3, 'search index="counterspell" badfield=nope', scen)
    assert r.tp_caught is False
    assert r.fp_count == 0
    assert r.error is not None and "invalid field" in r.error


@pytest.mark.parametrize("threshold,expected", [(0, False), (47, True)])
def test_runstate_passed_respects_threshold(threshold: int, expected: bool):
    from counterspell.schemas import RunState, ValidationResult
    s = RunState(threat_text="x")
    s.iterations.append(
        ValidationResult(iteration=1, spl="spl", tp_caught=True, fp_count=47)
    )
    assert s.passed(threshold) is expected


def test_runstate_fp_curve_is_in_order():
    from counterspell.schemas import RunState, ValidationResult
    s = RunState(threat_text="x")
    for i, fp in enumerate([47, 12, 0], start=1):
        s.iterations.append(
            ValidationResult(iteration=i, spl="x", tp_caught=True, fp_count=fp)
        )
    assert s.fp_curve == [47, 12, 0]
