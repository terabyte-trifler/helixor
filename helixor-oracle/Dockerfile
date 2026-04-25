FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

# Non-root user
RUN useradd -r -u 1000 helixor && chown -R helixor:helixor /app
USER helixor

EXPOSE 8000

# Default command is the webhook receiver
CMD ["uvicorn", "indexer.webhook_receiver:app", "--host", "0.0.0.0", "--port", "8000"]
