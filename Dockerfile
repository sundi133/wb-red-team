FROM node:20-slim AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

FROM node:20-slim
WORKDIR /app

# Install git (needed for codebaseRepo cloning) and tsx
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN npm i -g tsx

# Copy production dependencies
COPY --from=deps /app/node_modules ./node_modules

# Copy application source
COPY package.json ./
COPY tsconfig.json ./
COPY lib/ ./lib/
COPY attacks/ ./attacks/
COPY attacks-mcp/ ./attacks-mcp/
COPY dashboard/ ./dashboard/
COPY red-team.ts ./
COPY policies/ ./policies/
COPY lib/migrations/ ./lib/migrations/
COPY compliance/ ./compliance/
COPY config.example.json ./
COPY examples/ ./examples/

# Create report directory
RUN mkdir -p report

EXPOSE 4200

# Run the dashboard server (serves UI + run API)
CMD ["tsx", "dashboard/server.ts", "4200"]
