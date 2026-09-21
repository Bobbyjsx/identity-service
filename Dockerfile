FROM python:3.12-slim

WORKDIR /app

# Install uv from official binary image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    UV_COMPILE_BYTECODE=1 \
    PATH="/app/.venv/bin:$PATH"

# Install dependencies using uv sync
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy source code
COPY . .

# Pre-compile Python bytecode to speed up cold-start module loading
RUN python -m compileall -q /app

# Run Uvicorn. PORT and WEB_CONCURRENCY can be injected by environment.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8001} --workers ${WEB_CONCURRENCY:-2}"]
