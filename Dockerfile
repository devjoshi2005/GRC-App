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

# Ensure output/upload directories exist
RUN mkdir -p /app/api/outputs /app/api/uploads

# ── Runtime ────────────────────────────────────────────────────
EXPOSE 8080

# Use gunicorn for production (2 workers, generous timeout for long scans)
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8080", \
     "--workers", "2", \
     "--threads", "4", \
     "--timeout", "1800", \
     "--chdir", "api", \
     "app:app"]
