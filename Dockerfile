FROM python:3.11-slim

WORKDIR /app

# tree-sitter and PyTorch wheels need a small native build toolchain.
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY supplyguard ./supplyguard

RUN pip install --no-cache-dir -e ".[server]"

ENV PORT=8000
ENV MODEL_PATH=/app/checkpoints/best_model.pt
ENV MAX_WORKERS=4

EXPOSE 8000

CMD ["uvicorn", "supplyguard.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
