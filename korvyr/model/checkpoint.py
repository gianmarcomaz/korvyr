"""Single place where a Korvyr GNN checkpoint is described and loaded.

The API server, the CLI, and the evaluation harness must all instantiate the
network with the exact architecture the checkpoint was trained with, so the
architecture constants and the loading rules live here rather than being
repeated at every call site.
"""

from __future__ import annotations

import logging
from pathlib import Path

import torch

from korvyr.model.gin_classifier import KorvyrGIN
from korvyr.parsing.ast_extractor import FEATURE_DIM

log = logging.getLogger(__name__)

#: Architecture of the released checkpoint. ``NODE_FEATURE_DIM`` is bound to the
#: parser's feature width: a checkpoint trained on a different width cannot be
#: loaded by this code.
NODE_FEATURE_DIM = FEATURE_DIM
METADATA_DIM = 8
HIDDEN_DIM = 128
NUM_GIN_LAYERS = 4
NUM_EDGE_TYPES = 4
DROPOUT = 0.3


class CheckpointError(RuntimeError):
    """Raised when a checkpoint is required but cannot be loaded."""


def build_model() -> KorvyrGIN:
    """Instantiate an untrained network with the released architecture."""
    return KorvyrGIN(
        node_feat_dim=NODE_FEATURE_DIM,
        metadata_dim=METADATA_DIM,
        hidden_dim=HIDDEN_DIM,
        num_gin_layers=NUM_GIN_LAYERS,
        num_edge_types=NUM_EDGE_TYPES,
        dropout=DROPOUT,
    )


def load_model(
    path: str | Path,
    device: str | torch.device = "cpu",
    *,
    required: bool = False,
) -> KorvyrGIN | None:
    """Load the checkpoint at *path* in eval mode.

    Returns ``None`` when the checkpoint is missing or unreadable and
    *required* is false — callers then run in static-only mode. When *required*
    is true the same conditions raise :class:`CheckpointError` with an
    actionable message instead of silently degrading.
    """
    checkpoint_path = Path(path)
    if not checkpoint_path.exists():
        message = (
            f"GNN checkpoint not found at '{checkpoint_path}'. Korvyr does not "
            "ship a trained checkpoint; train one with scripts/train.py or set "
            "KORVYR_MODEL_PATH to an existing checkpoint."
        )
        if required:
            raise CheckpointError(
                f"{message} Unset KORVYR_REQUIRE_GNN to run in static-only mode instead."
            )
        log.warning("%s Falling back to static-only scanning.", message)
        return None

    model = build_model()
    try:
        checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=False)
        model.load_state_dict(checkpoint["model_state_dict"])
    except Exception as exc:
        message = (
            f"Failed to load GNN checkpoint '{checkpoint_path}': {exc}. The "
            f"checkpoint must be a Korvyr training checkpoint with a "
            f"'model_state_dict' matching node_feat_dim={NODE_FEATURE_DIM}, "
            f"metadata_dim={METADATA_DIM}, hidden_dim={HIDDEN_DIM}."
        )
        if required:
            raise CheckpointError(message) from exc
        log.warning("%s Falling back to static-only scanning.", message)
        return None

    model.to(device)
    model.eval()
    log.info("Loaded GNN checkpoint %s on %s", checkpoint_path, device)
    return model


def resolve_device(preference: str = "auto") -> str:
    """Resolve ``auto``/``cpu``/``cuda`` to an available torch device string."""
    if preference == "auto":
        return "cuda" if torch.cuda.is_available() else "cpu"
    if preference == "cuda" and not torch.cuda.is_available():
        log.warning("CUDA requested but unavailable; falling back to CPU.")
        return "cpu"
    return preference
