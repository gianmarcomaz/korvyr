from korvyr.evaluation.hybrid_policy_v2 import (
    HybridV2Config,
    decide_record_v2,
    weighted_rule_scores,
)


def _rule(rule_id, severity="high", score=5.0):
    return {
        "rule_id": rule_id,
        "rule_name": rule_id,
        "severity": severity,
        "description": "test rule",
        "score": score,
    }


def test_weighted_rule_scores_separate_hard_and_noisy_rules():
    weighted, hard = weighted_rule_scores(
        [
            _rule("CRIT_INSTALL_HOOK_EXEC", "critical", 10.0),
            _rule("HIGH_RUNTIME_PROTOTYPE_POLLUTION", "high", 7.0),
            _rule("MED_MINIFIED_SINGLE_FILE", "medium", 2.0),
        ]
    )

    assert weighted == 11.4
    assert hard == 10.0


def test_decide_record_v2_blocks_direct_high_gnn_score():
    decision = decide_record_v2(
        {"gnn_score": 0.91, "rules_details": []},
        HybridV2Config(gnn_direct_block_threshold=0.90),
    )

    assert decision.verdict == "malicious"
    assert decision.decision_bucket == "v2_gnn_direct_block"


def test_decide_record_v2_blocks_gnn_confirmed_by_weighted_rules():
    decision = decide_record_v2(
        {
            "gnn_score": 0.55,
            "rules_details": [_rule("HIGH_ENCODED_PAYLOAD_CHAIN", "high", 8.0)],
        },
        HybridV2Config(
            gnn_direct_block_threshold=0.90,
            gnn_confirm_floor=0.50,
            weighted_confirm_threshold=4.0,
        ),
    )

    assert decision.verdict == "malicious"
    assert decision.decision_bucket == "v2_gnn_weighted_rules_block"


def test_decide_record_v2_keeps_low_gnn_noisy_rules_in_review():
    decision = decide_record_v2(
        {
            "gnn_score": 0.30,
            "rules_details": [
                _rule("HIGH_RUNTIME_PROTOTYPE_POLLUTION", "high", 7.0),
            ],
        },
        HybridV2Config(clean_threshold=0.35),
    )

    assert decision.verdict == "suspicious"
    assert decision.decision_bucket == "v2_low_gnn_review"
