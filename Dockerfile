# Korvyr scanner API.
#
# The image contains no GNN checkpoint. Mount one and point KORVYR_MODEL_PATH at
# it to get hybrid verdicts; without it the service runs in static-only mode.
FROM python:3.11-slim

WORKDIR /app

# tree-sitter and PyTorch wheels need a small native build toolchain.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY korvyr ./korvyr

RUN pip install --no-cache-dir ".[server]"

ENV KORVYR_API_PORT=8000 \
    KORVYR_MODEL_PATH=/app/models/gnn_v2_cuda.pt \
    KORVYR_MAX_WORKERS=4 \
    KORVYR_REQUIRE_GNN=false

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "korvyr.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
