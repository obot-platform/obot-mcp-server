FROM python:3.13-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Install dependencies first for better layer caching
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

# Copy application code and install the project
COPY main.py ./
COPY obot_mcp/ ./obot_mcp/
RUN uv sync --frozen --no-dev

FROM python:3.13-slim

WORKDIR /app

# Copy the virtual environment from the builder
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/main.py /app/main.py
COPY --from=builder /app/obot_mcp /app/obot_mcp

ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT ["python", "main.py"]
