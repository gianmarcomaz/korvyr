"""
Korvyr GIN (Graph Isomorphism Network) classifier.

Architecture
------------
1.  Linear projection: 35 → hidden_dim
2.  N stacked GINEConv layers (GIN with edge features) + BatchNorm + residual
3.  Jumping Knowledge: concatenate all layer representations for readout
4.  Triple global pooling (mean ∥ sum ∥ max) → 3·hidden_dim
5.  Edge-type distribution histogram (4 dims, normalized)
6.  Concatenate with 8 package-level metadata features
7.  MLP head → 1 logit (binary classification)

Edge types (ast_child / cfg_next / cfg_branch / dfg_def_use) are embedded
into learned vectors and injected via GINEConv's edge_attr mechanism.
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GINEConv, global_add_pool, global_max_pool, global_mean_pool


class KorvyrGIN(nn.Module):
    """GIN-based binary classifier for Code Property Graphs."""

    def __init__(
        self,
        node_feat_dim: int = 35,
        metadata_dim: int = 8,
        hidden_dim: int = 128,
        num_gin_layers: int = 4,
        num_edge_types: int = 4,
        dropout: float = 0.3,
        train_eps: bool = True,
    ) -> None:
        super().__init__()

        self.dropout = dropout
        self.node_feat_dim = node_feat_dim
        self.metadata_dim = metadata_dim
        self.hidden_dim = hidden_dim
        self.num_gin_layers = num_gin_layers
        self.num_edge_types = num_edge_types

        # --- node projection ---
        self.node_proj = nn.Sequential(
            nn.Linear(node_feat_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
        )

        # --- edge type embeddings ---
        self.edge_embedding = nn.Embedding(num_edge_types, hidden_dim)
        nn.init.xavier_uniform_(self.edge_embedding.weight)

        # --- GINEConv layers ---
        self.gin_layers = nn.ModuleList()
        self.batch_norms = nn.ModuleList()

        for _ in range(num_gin_layers):
            mlp = nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, hidden_dim),
            )
            self.gin_layers.append(
                GINEConv(nn=mlp, train_eps=train_eps, edge_dim=hidden_dim)
            )
            self.batch_norms.append(nn.BatchNorm1d(hidden_dim))

        # --- Jumping Knowledge projection ---
        # Concatenate all (num_layers + 1) layer outputs, project back to hidden
        jk_input_dim = hidden_dim * (num_gin_layers + 1)
        self.jk_proj = nn.Sequential(
            nn.Linear(jk_input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
        )

        # --- graph-level readout + classifier ---
        # triple pooling (mean ∥ sum ∥ max) = 3*hidden_dim
        # + edge type histogram = num_edge_types
        # + metadata features = metadata_dim
        readout_dim = hidden_dim * 3 + num_edge_types + metadata_dim

        self.classifier = nn.Sequential(
            nn.Linear(readout_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.LayerNorm(hidden_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, 1),
        )

    def _edge_type_histogram(
        self,
        edge_type: torch.Tensor,
        edge_index: torch.Tensor,
        batch: torch.Tensor,
        num_graphs: int,
    ) -> torch.Tensor:
        """Compute per-graph normalized edge-type distribution [B, num_edge_types]."""
        device = edge_type.device
        # Assign each edge to its graph (using the source node's batch ID)
        edge_batch = batch[edge_index[0]]

        hist = torch.zeros(num_graphs, self.num_edge_types,
                           device=device, dtype=torch.float32)
        for et in range(self.num_edge_types):
            mask = edge_type == et
            if mask.any():
                hist.scatter_add_(0,
                    edge_batch[mask].unsqueeze(1).expand(-1, 1),
                    torch.ones(mask.sum(), 1, device=device),
                )

        # Normalize per graph (total edges)
        total = hist.sum(dim=1, keepdim=True).clamp(min=1.0)
        return hist / total

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type: torch.Tensor,
        metadata: torch.Tensor,
        batch: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """
        Parameters
        ----------
        x : [N, node_feat_dim]
        edge_index : [2, E]
        edge_type : [E]
        metadata : [B, metadata_dim]  (B = number of graphs in the batch)
        batch : [N]  node-to-graph assignment (None → single graph)

        Returns
        -------
        logits : [B]  raw logits (apply sigmoid for probabilities)
        """
        if batch is None:
            batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)

        num_graphs = int(batch.max().item()) + 1

        # --- initial projection ---
        h = self.node_proj(x)

        # --- edge features ---
        edge_attr = self.edge_embedding(edge_type)

        # --- Jumping Knowledge: collect all layer outputs ---
        layer_outputs = [h]

        # --- message-passing layers with residual connections ---
        for gin, bn in zip(self.gin_layers, self.batch_norms):
            h_new = gin(h, edge_index, edge_attr)
            h_new = bn(h_new)
            h_new = F.relu(h_new)
            h_new = F.dropout(h_new, p=self.dropout, training=self.training)
            h = h + h_new  # residual skip
            layer_outputs.append(h)

        # --- JK aggregation: concatenate all layers, project ---
        h_jk = torch.cat(layer_outputs, dim=-1)  # [N, (L+1)*hidden]
        h = self.jk_proj(h_jk)                    # [N, hidden]

        # --- triple global pooling ---
        h_mean = global_mean_pool(h, batch)  # [B, hidden_dim]
        h_sum = global_add_pool(h, batch)    # [B, hidden_dim]
        h_max = global_max_pool(h, batch)    # [B, hidden_dim]

        # --- edge type distribution ---
        edge_hist = self._edge_type_histogram(
            edge_type, edge_index, batch, num_graphs,
        )  # [B, num_edge_types]

        # --- concatenate with package metadata ---
        graph_repr = torch.cat(
            [h_mean, h_sum, h_max, edge_hist, metadata], dim=-1,
        )

        # --- classify ---
        return self.classifier(graph_repr).squeeze(-1)

    def forward_from_data(self, data) -> torch.Tensor:
        """Convenience: accept a PyG ``Data`` / ``Batch`` object directly."""
        batch = data.batch if hasattr(data, "batch") and data.batch is not None else None
        meta = data.metadata
        if meta.dim() == 1:
            meta = meta.unsqueeze(0)
        return self.forward(
            x=data.x,
            edge_index=data.edge_index,
            edge_type=data.edge_type,
            metadata=meta,
            batch=batch,
        )

    def predict_proba(self, data) -> torch.Tensor:
        """Return probabilities (sigmoid of logits)."""
        self.eval()
        with torch.no_grad():
            return torch.sigmoid(self.forward_from_data(data))
