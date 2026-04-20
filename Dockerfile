FROM node:20-slim AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

FROM node:20-slim
WORKDIR /app

# Install tsx globally for running TypeScript
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
COPY config.example.json ./

# Create report directory
RUN mkdir -p report

EXPOSE 4200

# Run the dashboard server (serves UI + run API)
CMD ["tsx", "dashboard/server.ts", "4200"]
