# SLOP Auditor - Security Scanner with 3D Visualization
# Multi-stage build for optimized image size

# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++

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

# Install runtime dependencies and security tools
RUN apk add --no-cache \
    python3 \
    py3-pip \
    git \
    curl \
    && pip3 install --break-system-packages semgrep

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
RUN mkdir -p /data/.slop-auditor

# Environment variables
ENV NODE_ENV=production
ENV SLOP_PORT=3000
ENV WS_PORT=3001
ENV VISUALIZER_PORT=8080

# Expose ports
EXPOSE 3000 3001 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/info || exit 1

# Run as non-root user
RUN addgroup -g 1001 -S slop && \
    adduser -S slop -u 1001 -G slop && \
    chown -R slop:slop /app /data

USER slop

# Start the application
CMD ["node", "dist/index.js"]
