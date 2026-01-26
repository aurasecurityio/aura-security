# aurasecurity - Security Scanner with 3D Visualization
# Multi-stage build for optimized image size

# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies with pinned versions
RUN apk add --no-cache python3=3.12.8-r1 make=4.4.1-r2 g++=14.2.0-r4

# Copy package files
COPY package*.json ./

# Install all dependencies (including dev)
RUN npm ci

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Production stage
FROM node:20-alpine AS production

WORKDIR /app

# Set shell to use pipefail
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

# Install runtime dependencies and security tools with pinned versions
RUN apk add --no-cache \
    python3=3.12.8-r1 \
    py3-pip=24.3.1-r0 \
    git=2.47.2-r0 \
    curl=8.12.0-r0 \
    && pip3 install --no-cache-dir --break-system-packages semgrep==1.102.0

# Install gitleaks
RUN wget -qO- https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz | tar xz -C /usr/local/bin gitleaks

# Install trivy
RUN wget -qO- https://github.com/aquasecurity/trivy/releases/download/v0.50.0/trivy_0.50.0_Linux-64bit.tar.gz | tar xz -C /usr/local/bin trivy

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --omit=dev

# Copy built files from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/visualizer ./visualizer
COPY --from=builder /app/schemas ./schemas

# Create directory for database
RUN mkdir -p /data/.aura-security

# Environment variables
ENV NODE_ENV=production
ENV AURA_PORT=3000
ENV WS_PORT=3001
ENV VISUALIZER_PORT=8080

# Expose ports
EXPOSE 3000 3001 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/info || exit 1

# Run as non-root user
RUN addgroup -g 1001 -S aura && \
    adduser -S aura -u 1001 -G aura && \
    chown -R aura:aura /app /data

USER aura

# Start the application
CMD ["node", "dist/index.js"]
