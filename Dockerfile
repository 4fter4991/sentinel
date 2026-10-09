FROM node:20-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY server.js scan.py ./
ENV PORT=8000
# SOLANA_RPC_URL must be set at deploy time (Helius RPC URL with API key).
# Without it, scan.py falls back to the vault-backed helius CLI (local dev only).
EXPOSE 8000
CMD ["node", "server.js"]
