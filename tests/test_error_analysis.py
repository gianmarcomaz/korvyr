from supplyguard.evaluation.error_analysis import (
    categorize_error,
    rule_profile_bucket,
    score_band,
)


def test_score_band_groups_gnn_scores():
    assert score_band(-1.0) == "gnn_unavailable"
    assert score_band(0.20) == "low_<0.35"
    assert score_band(0.45) == "low_mid_0.35_0.50"
    assert score_band(0.60) == "mid_0.50_0.75"
    assert score_band(0.78) == "near_block_0.75_0.80"
    assert score_band(0.85) == "high_0.80_0.90"
    assert score_band(0.95) == "very_high_>=0.90"


def test_rule_profile_bucket_identifies_reliability_mix():
    assert rule_profile_bucket([]) == "no_rules"
    assert (
        rule_profile_bucket(["CRIT_INSTALL_HOOK_EXEC"])
        == "high_reliability_rules_only"
    )
    assert rule_profile_bucket(["HIGH_WEBHOOK_EXFIL"]) == "noisy_rules_only"
    assert (
        rule_profile_bucket(["CRIT_INSTALL_HOOK_EXEC", "HIGH_WEBHOOK_EXFIL"])
        == "mixed_reliability_rules"
    )


def test_categorize_false_positive_high_gnn_without_rules():
    record = {
        "gnn_score": 0.96,
        "rules_matched": [],
        "decision_bucket": "v2_gnn_direct_block",
    }

    assert categorize_error(record, "fp") == "fp_gnn_very_high_without_rules"


def test_categorize_false_negative_high_gnn_no_rules():
    record = {
        "gnn_score": 0.91,
        "rules_matched": [],
        "decision_bucket": "v2_gnn_review",
    }

    assert categorize_error(record, "fn") == "fn_high_gnn_no_rules"


def test_categorize_false_negative_low_gnn_weak_rules():
    record = {
        "gnn_score": 0.31,
        "rules_matched": ["MED_INSTALL_HOOK_EXISTS"],
        "decision_bucket": "v2_low_gnn_review",
    }

    assert categorize_error(record, "fn") == "fn_low_gnn_weak_rules"
