FROM python:3.11-slim

LABEL maintainer="sanjoy.sghosh@gmail.com"
LABEL description="COMBATPAIR — Adversarial Co-Generation Engine"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps separately from source for layer caching
COPY pyproject.toml ./
RUN pip install --no-cache-dir click httpx anthropic "chromadb>=0.5" pyyaml rich

# Install source
COPY src/ ./src/
RUN pip install --no-cache-dir -e .

# Create reports and forge dirs
RUN mkdir -p .combatpair/reports .combatpair/forge .combatpair/brain

# Non-root user for security
RUN useradd --create-home combatpair
RUN chown -R combatpair:combatpair /app
USER combatpair

# Default: run validate to confirm environment health
CMD ["combatpair", "doctor"]
