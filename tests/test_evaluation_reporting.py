from supplyguard.evaluation.reporting import (
    compute_binary_metrics,
    decision_bucket,
    gnn_score_bucket_calibration,
    per_rule_saved_hurt,
    summarize_records,
)


def test_compute_binary_metrics_counts_all_cells():
    metrics = compute_binary_metrics([1, 1, 0, 0], [1, 0, 1, 0])

    assert metrics["tp"] == 1
    assert metrics["fp"] == 1
    assert metrics["fn"] == 1
    assert metrics["tn"] == 1
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5


def test_decision_bucket_uses_production_path_text():
    assert (
        decision_bucket(
            "malicious",
            "GNN confident malicious (0.951) + confirming rules (score=28)",
        )
        == "gnn_rules_confirmed_block"
    )
    assert (
        decision_bucket(
            "suspicious",
            "GNN high malicious score (0.785) without strong static confirmation",
        )
        == "gnn_unconfirmed_review"
    )
    assert (
        decision_bucket(
            "malicious",
            "v2 install-hook recall block: score=0.500, rule=MED_INSTALL_HOOK_EXISTS",
        )
        == "v2_install_hook_recall_block"
    )
    assert (
        decision_bucket("malicious", "v2 direct GNN block: score=0.820")
        == "v2_gnn_direct_block"
    )


def test_per_rule_saved_hurt_tracks_hybrid_delta():
    records = [
        {
            "true_label": 1,
            "gnn_score": 0.2,
            "hybrid_verdict": "malicious",
            "rules_matched": ["CRIT_INSTALL_HOOK_EXEC"],
        },
        {
            "true_label": 0,
            "gnn_score": 0.2,
            "hybrid_verdict": "malicious",
            "rules_matched": ["HIGH_NOISY_RULE"],
        },
    ]

    contribution = per_rule_saved_hurt(records)

    assert contribution["CRIT_INSTALL_HOOK_EXEC"] == {"saved": 1, "hurt": 0}
    assert contribution["HIGH_NOISY_RULE"] == {"saved": 0, "hurt": 1}


def test_summarize_records_includes_required_sections():
    records = [
        {
            "package_name": "malicious-fixture",
            "true_label": 1,
            "gnn_score": -1.0,
            "gnn_error_type": "CPG_NONE",
            "cpg_status": "cpg_none",
            "rules_verdict": "malicious",
            "hybrid_verdict": "malicious",
            "rules_matched": ["CRIT_MANIFEST_CURL_PIPE"],
            "decision_bucket": "rules_only_block",
            "decision_path": "GNN unavailable + rules confirm",
        },
        {
            "package_name": "clean-fixture",
            "true_label": 0,
            "gnn_score": 0.1,
            "gnn_error_type": "",
            "cpg_status": "success",
            "rules_verdict": "clean",
            "hybrid_verdict": "clean",
            "rules_matched": [],
            "decision_bucket": "gnn_confident_clean",
            "decision_path": "GNN confident clean",
        },
    ]

    summary = summarize_records(records)

    assert summary["counts"]["total_packages"] == 2
    assert summary["coverage"]["gnn_failure_count"] == 1
    assert summary["coverage"]["cpg_none_count"] == 1
    assert summary["metrics"]["hybrid"]["precision"] == 1.0
    assert summary["decision_buckets"]["rules_only_block"] == 1
    assert summary["gnn_score_buckets"]["[0.10,0.20)"]["total"] == 1
    assert len(summary["false_positives"]) == 0
    assert len(summary["false_negatives"]) == 0


def test_gnn_score_bucket_calibration_tracks_observed_rate():
    records = [
        {"true_label": 0, "gnn_score": 0.05},
        {"true_label": 1, "gnn_score": 0.91},
        {"true_label": 0, "gnn_score": 0.92},
    ]

    buckets = gnn_score_bucket_calibration(records)

    assert buckets["[0.00,0.10)"]["total"] == 1
    assert buckets["[0.00,0.10)"]["observed_malicious_rate"] == 0.0
    assert buckets["[0.90,1.00]"]["total"] == 2
    assert buckets["[0.90,1.00]"]["observed_malicious_rate"] == 0.5
