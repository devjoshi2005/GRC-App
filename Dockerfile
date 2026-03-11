# ── GRC Compliance Engine ──────────────────────────────────────
# Multi-stage build to keep the image lean (~800MB with Prowler)
FROM python:3.12-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System deps required by chromadb (sqlite), cryptography, and general builds
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Install Python dependencies ───────────────────────────────
COPY requirements.txt .
# Remove vercel from requirements (not needed in Docker)
RUN grep -iv 'vercel' requirements.txt > requirements_docker.txt \
    && pip install --no-cache-dir -r requirements_docker.txt

# ── Copy application code ─────────────────────────────────────
COPY . .

# Outputs go to /tmp (ephemeral), not the app tree
RUN mkdir -p /tmp/grc_outputs /tmp/grc_uploads

# ── Runtime ────────────────────────────────────────────────────
# Railway/Render inject $PORT at runtime; default to 8080 for local use.
# Shell form (not exec form) so ${PORT:-8080} expands correctly.
EXPOSE ${PORT:-8080}

CMD gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 2 --threads 4 --timeout 1800 --chdir api app:app
