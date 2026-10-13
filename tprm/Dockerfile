FROM python:3.11-slim

# Install system dependencies (Tesseract for OCR)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    libmagic1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install --no-cache-dir uv

WORKDIR /app

# Copy dependency declaration first for layer caching
COPY pyproject.toml ./
COPY README.md ./

# Install dependencies (without the app itself first)
RUN uv venv /app/.venv && \
    uv pip install --python /app/.venv/bin/python \
    presidio-analyzer presidio-anonymizer \
    pymupdf python-docx openpyxl pytesseract Pillow \
    fastapi uvicorn[standard] typer \
    pydantic pydantic-settings \
    structlog cryptography python-dotenv pyyaml \
    sqlalchemy asyncpg alembic \
    httpx python-magic python-multipart \
    langchain langchain-ollama langchain-core \
    json-repair

# Copy source
COPY src/ ./src/
COPY config/ ./config/
COPY alembic/ ./alembic/
COPY alembic.ini ./alembic.ini 2>/dev/null || true

# Install the app itself
RUN uv pip install --python /app/.venv/bin/python -e . --no-build-isolation

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/src"

EXPOSE 8000

CMD ["uvicorn", "tprm.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
