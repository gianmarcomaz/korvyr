import json

from supplyguard.evaluation.context_signals import (
    CandidateSignal,
    enrich_record_context,
    evaluate_candidate,
    hard_examples,
    manifest_context,
)


def test_manifest_context_reads_package_shape(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "package.json").write_text(
        json.dumps(
            {
                "name": "@scope/demo",
                "description": "A normal looking package",
                "license": "MIT",
                "repository": {"type": "git", "url": "https://example.test/demo"},
                "scripts": {"postinstall": "node setup.js", "test": "node test.js"},
                "dependencies": {"left-pad": "1.3.0"},
                "devDependencies": {"vitest": "latest"},
            }
        ),
        encoding="utf-8",
    )
    record = {
        "package_path": str(package),
        "package_name": "@scope/demo",
        "rules_matched": ["MED_INSTALL_HOOK_EXISTS"],
        "gnn_score": 0.52,
        "metadata_risk": 0.25,
        "num_js_files": 2,
        "num_nodes": 50,
    }

    context = manifest_context(record)

    assert context["scoped"] is True
    assert context["has_repository"] is True
    assert context["has_license"] is True
    assert context["has_lifecycle_hook"] is True
    assert context["lifecycle_hooks"] == ["postinstall"]
    assert context["dependency_count"] == 1
    assert context["dev_dependency_count"] == 1
    assert context["has_med_install_hook_rule"] is True


def test_evaluate_candidate_suppressor_reports_saved_and_hurt():
    records = [
        {"true_label": 0, "hybrid_verdict": "malicious", "package_name": "fp"},
        {"true_label": 1, "hybrid_verdict": "malicious", "package_name": "tp"},
        {"true_label": 1, "hybrid_verdict": "suspicious", "package_name": "fn"},
        {"true_label": 0, "hybrid_verdict": "clean", "package_name": "tn"},
    ]
    candidate = CandidateSignal(
        "test_suppressor",
        "suppressor",
        "matches current positive predictions",
        lambda record: record["package_name"] in {"fp", "tp"},
    )

    result = evaluate_candidate(records, candidate)

    assert result["matched_cells"]["fp"] == 1
    assert result["matched_cells"]["tp"] == 1
    assert result["deltas"]["fp"] == -1
    assert result["deltas"]["tp"] == -1
    assert result["adjusted_metrics"]["fp"] == 0
    assert result["adjusted_metrics"]["fn"] == 2


def test_evaluate_candidate_confirmer_reports_saved_and_hurt():
    records = [
        {"true_label": 0, "hybrid_verdict": "malicious", "package_name": "fp"},
        {"true_label": 1, "hybrid_verdict": "malicious", "package_name": "tp"},
        {"true_label": 1, "hybrid_verdict": "suspicious", "package_name": "fn"},
        {"true_label": 0, "hybrid_verdict": "clean", "package_name": "tn"},
    ]
    candidate = CandidateSignal(
        "test_confirmer",
        "confirmer",
        "matches current negative predictions",
        lambda record: record["package_name"] in {"fn", "tn"},
    )

    result = evaluate_candidate(records, candidate)

    assert result["matched_cells"]["fn"] == 1
    assert result["matched_cells"]["tn"] == 1
    assert result["deltas"]["fn"] == -1
    assert result["deltas"]["tn"] == -1
    assert result["adjusted_metrics"]["tp"] == 2
    assert result["adjusted_metrics"]["fp"] == 2


def test_hard_examples_extracts_false_positives_and_false_negatives():
    records = [
        enrich_record_context(
            {"true_label": 0, "hybrid_verdict": "malicious", "package_name": "fp"}
        ),
        enrich_record_context(
            {"true_label": 1, "hybrid_verdict": "malicious", "package_name": "tp"}
        ),
        enrich_record_context(
            {"true_label": 1, "hybrid_verdict": "suspicious", "package_name": "fn"}
        ),
    ]

    result = hard_examples(records)

    assert [item["package_name"] for item in result["false_positives"]] == ["fp"]
    assert [item["package_name"] for item in result["false_negatives"]] == ["fn"]
