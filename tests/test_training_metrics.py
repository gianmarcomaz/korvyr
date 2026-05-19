from supplyguard.model.training import (
    _binary_metric_values,
    _compute_metrics,
    find_optimal_threshold,
)


def test_binary_metric_values_do_not_require_sklearn():
    labels = [1.0, 1.0, 0.0, 0.0]
    preds = [1.0, 0.0, 1.0, 0.0]

    accuracy, precision, recall, f1 = _binary_metric_values(labels, preds)

    assert accuracy == 0.5
    assert precision == 0.5
    assert recall == 0.5
    assert f1 == 0.5


def test_find_precision_threshold_uses_local_metric_math():
    labels = [1.0, 1.0, 0.0, 0.0]
    probs = [0.95, 0.80, 0.70, 0.10]

    threshold = find_optimal_threshold(labels, probs, strategy="precision99")
    metrics = _compute_metrics(labels, probs, 0.0, 1, threshold=threshold)

    assert threshold > 0.70
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
