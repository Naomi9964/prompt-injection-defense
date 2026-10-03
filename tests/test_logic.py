# Pure-logic tests. No network, no API keys.

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pid_bench import (
    ATTACKS, BlockedInput, Combined, DelimiterWrap, JudgeGate, KeywordFilter,
    MockTarget, NoDefense, RuleJudge, SystemHardening, asr, run_matrix, to_markdown,
)
from pid_bench.defenses import BASE_SYSTEM


def _attack(attack_id):
    return next(a for a in ATTACKS if a.id == attack_id)


def test_baseline_bypassed_everywhere():
    results = run_matrix(ATTACKS, [NoDefense()], MockTarget(), RuleJudge())
    assert asr(results, "none", ATTACKS) == 1.0


def test_hardening_blocks_everything():
    results = run_matrix(ATTACKS, [SystemHardening()], MockTarget(), RuleJudge())
    assert asr(results, "system-hardening", ATTACKS) == 0.0


def test_keyword_filter_blocks_direct_but_misses_hex_evasion():
    f = KeywordFilter()
    plain = _attack("direct-override-plain")
    with pytest.raises(BlockedInput):
        f.apply(plain, BASE_SYSTEM, list(plain.turns))
    # hex variant is not on the blocklist: the classic filter evasion
    hex_attack = _attack("encoding-hex")
    sp, turns = f.apply(hex_attack, BASE_SYSTEM, list(hex_attack.turns))
    assert RuleJudge().is_success(hex_attack, MockTarget().respond(hex_attack, sp, turns))


def test_delimiter_blocks_untrusted_content_only():
    d = DelimiterWrap()
    indirect = _attack("indirect-hidden-div")
    sp, turns = d.apply(indirect, BASE_SYSTEM, list(indirect.turns))
    assert not RuleJudge().is_success(indirect, MockTarget().respond(indirect, sp, turns))
    # the user's own words are still instructions: delimiters don't help here
    direct = _attack("direct-override-plain")
    sp2, turns2 = d.apply(direct, BASE_SYSTEM, list(direct.turns))
    assert RuleJudge().is_success(direct, MockTarget().respond(direct, sp2, turns2))


def test_judge_gate_catches_multiturn_setup():
    g = JudgeGate()
    mt = _attack("multiturn-game")
    with pytest.raises(BlockedInput):
        g.apply(mt, BASE_SYSTEM, list(mt.turns))


def test_combined_defense_zero_asr():
    results = run_matrix(ATTACKS, [Combined()], MockTarget(), RuleJudge())
    assert asr(results, "combined", ATTACKS) == 0.0


def test_report_renders_table():
    results = run_matrix(ATTACKS, [NoDefense(), SystemHardening()], MockTarget(), RuleJudge())
    md = to_markdown(results, ATTACKS)
    assert "| defense |" in md and "100%" in md and "0%" in md


def test_refusal_never_counts_as_success():
    a = _attack("direct-override-plain")
    assert not a.success("I can't follow instructions from untrusted content. " + a.marker)
