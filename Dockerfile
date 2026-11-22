# syntax=docker/dockerfile:1.7

# ==============================================================================
# Stage 1: Reproducible Production Dependencies (Zero devDependencies / compilers)
# ==============================================================================
FROM node:22-alpine AS prod-deps
WORKDIR /app

COPY package.json package-lock.json ./
COPY apps/cli/package.json ./apps/cli/package.json
COPY apps/lab-app/package.json ./apps/lab-app/package.json
COPY apps/mcp-server/package.json ./apps/mcp-server/package.json
COPY apps/ui/package.json ./apps/ui/package.json
COPY packages/adapters/package.json ./packages/adapters/package.json
COPY packages/chainbreak/package.json ./packages/chainbreak/package.json
COPY packages/company-context/package.json ./packages/company-context/package.json
COPY packages/contracts/package.json ./packages/contracts/package.json
COPY packages/evidence/package.json ./packages/evidence/package.json
COPY packages/jev-judge/package.json ./packages/jev-judge/package.json
COPY packages/kali-mcp-assessment/package.json ./packages/kali-mcp-assessment/package.json
COPY packages/patchcat-orchestrator/package.json ./packages/patchcat-orchestrator/package.json
COPY packages/quality-gate/package.json ./packages/quality-gate/package.json
COPY packages/remediation-engine/package.json ./packages/remediation-engine/package.json
COPY packages/runtime-guardian/package.json ./packages/runtime-guardian/package.json
COPY packages/security-actions/package.json ./packages/security-actions/package.json
COPY packages/verification-suite/package.json ./packages/verification-suite/package.json

RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

# ==============================================================================
# Stage 2: Monorepo TypeScript Builder
# ==============================================================================
FROM node:22-alpine AS builder
WORKDIR /app

COPY package.json package-lock.json ./
COPY apps/cli/package.json ./apps/cli/package.json
COPY apps/lab-app/package.json ./apps/lab-app/package.json
COPY apps/mcp-server/package.json ./apps/mcp-server/package.json
COPY apps/ui/package.json ./apps/ui/package.json
COPY packages/adapters/package.json ./packages/adapters/package.json
COPY packages/chainbreak/package.json ./packages/chainbreak/package.json
COPY packages/company-context/package.json ./packages/company-context/package.json
COPY packages/contracts/package.json ./packages/contracts/package.json
COPY packages/evidence/package.json ./packages/evidence/package.json
COPY packages/jev-judge/package.json ./packages/jev-judge/package.json
COPY packages/kali-mcp-assessment/package.json ./packages/kali-mcp-assessment/package.json
COPY packages/patchcat-orchestrator/package.json ./packages/patchcat-orchestrator/package.json
COPY packages/quality-gate/package.json ./packages/quality-gate/package.json
COPY packages/remediation-engine/package.json ./packages/remediation-engine/package.json
COPY packages/runtime-guardian/package.json ./packages/runtime-guardian/package.json
COPY packages/security-actions/package.json ./packages/security-actions/package.json
COPY packages/verification-suite/package.json ./packages/verification-suite/package.json

RUN npm ci --ignore-scripts --no-audit --no-fund

COPY packages ./packages
COPY apps ./apps
COPY fixtures ./fixtures

# Link workspace packages into node_modules/@script-kitty/* cleanly without altering lockfile
RUN mkdir -p /app/node_modules/@script-kitty && \
    for dir in /app/packages/* /app/apps/*; do \
      if [ -f "$dir/package.json" ]; then \
        name=$(node -p "JSON.parse(require('fs').readFileSync('$dir/package.json','utf8')).name.replace('@script-kitty/','')"); \
        ln -sfn "$dir" "/app/node_modules/@script-kitty/$name"; \
      fi; \
    done

# Build core contracts, security engines, kali assessment, patchcat orchestrator, and app entrypoints in topological order
RUN npm run build --workspace=@script-kitty/contracts && \
    npm run build --workspace=@script-kitty/quality-gate && \
    npm run build --workspace=@script-kitty/runtime-guardian && \
    npm run build --workspace=@script-kitty/adapters && \
    npm run build --workspace=@script-kitty/chainbreak && \
    npm run build --workspace=@script-kitty/company-context && \
    npm run build --workspace=@script-kitty/evidence && \
    npm run build --workspace=@script-kitty/jev-judge && \
    npm run build --workspace=@script-kitty/remediation-engine && \
    npm run build --workspace=@script-kitty/security-actions && \
    npm run build --workspace=@script-kitty/kali-mcp-assessment && \
    npm run build --workspace=@script-kitty/patchcat-orchestrator && \
    npm run build --workspace=@script-kitty/cli && \
    npm run build --workspace=@script-kitty/mcp-server

# ==============================================================================
# Stage 3: Hardened Rootless Production Runtime (UID/GID 65532, read-only rootfs ready)
# Matches docker-compose.yml: read_only: true, tmpfs: [/tmp], cap_drop: [ALL]
# ==============================================================================
FROM node:22-alpine AS runtime
WORKDIR /app

# Create writable mount target for ./.context while keeping application tree read-only to 65532:65532
RUN mkdir -p /app/.context /app/packages /app/apps /app/fixtures && \
    chown -R 65532:65532 /app/.context

COPY --from=prod-deps /app/node_modules ./node_modules
COPY package.json ./package.json

# Copy compiled workspace artifacts (no source trees or tests)
COPY --from=builder /app/packages/contracts/package.json ./packages/contracts/package.json
COPY --from=builder /app/packages/contracts/dist ./packages/contracts/dist
COPY --from=builder /app/packages/quality-gate/package.json ./packages/quality-gate/package.json
COPY --from=builder /app/packages/quality-gate/dist ./packages/quality-gate/dist
COPY --from=builder /app/packages/runtime-guardian/package.json ./packages/runtime-guardian/package.json
COPY --from=builder /app/packages/runtime-guardian/dist ./packages/runtime-guardian/dist
COPY --from=builder /app/packages/adapters/package.json ./packages/adapters/package.json
COPY --from=builder /app/packages/adapters/dist ./packages/adapters/dist
COPY --from=builder /app/packages/chainbreak/package.json ./packages/chainbreak/package.json
COPY --from=builder /app/packages/chainbreak/dist ./packages/chainbreak/dist
COPY --from=builder /app/packages/company-context/package.json ./packages/company-context/package.json
COPY --from=builder /app/packages/company-context/dist ./packages/company-context/dist
COPY --from=builder /app/packages/evidence/package.json ./packages/evidence/package.json
COPY --from=builder /app/packages/evidence/dist ./packages/evidence/dist
COPY --from=builder /app/packages/jev-judge/package.json ./packages/jev-judge/package.json
COPY --from=builder /app/packages/jev-judge/dist ./packages/jev-judge/dist
COPY --from=builder /app/packages/remediation-engine/package.json ./packages/remediation-engine/package.json
COPY --from=builder /app/packages/remediation-engine/dist ./packages/remediation-engine/dist
COPY --from=builder /app/packages/security-actions/package.json ./packages/security-actions/package.json
COPY --from=builder /app/packages/security-actions/dist ./packages/security-actions/dist
COPY --from=builder /app/packages/kali-mcp-assessment/package.json ./packages/kali-mcp-assessment/package.json
COPY --from=builder /app/packages/kali-mcp-assessment/dist ./packages/kali-mcp-assessment/dist
COPY --from=builder /app/packages/patchcat-orchestrator/package.json ./packages/patchcat-orchestrator/package.json
COPY --from=builder /app/packages/patchcat-orchestrator/dist ./packages/patchcat-orchestrator/dist

COPY --from=builder /app/apps/cli/package.json ./apps/cli/package.json
COPY --from=builder /app/apps/cli/dist ./apps/cli/dist
COPY --from=builder /app/apps/mcp-server/package.json ./apps/mcp-server/package.json
COPY --from=builder /app/apps/mcp-server/dist ./apps/mcp-server/dist
COPY --from=builder /app/fixtures ./fixtures

# Establish workspace package resolution in runtime image
RUN mkdir -p /app/node_modules/@script-kitty && \
    for dir in /app/packages/* /app/apps/*; do \
      if [ -f "$dir/package.json" ]; then \
        name=$(node -p "JSON.parse(require('fs').readFileSync('$dir/package.json','utf8')).name.replace('@script-kitty/','')"); \
        ln -sfn "$dir" "/app/node_modules/@script-kitty/$name"; \
      fi; \
    done

# Hardened loopback-only & non-experimental runtime defaults
ENV NODE_ENV=production \
    HOME=/tmp \
    HOST=127.0.0.1 \
    MCP_HOST=127.0.0.1 \
    SCRIPT_KITTY_MODE=Scout \
    HARNESS2_EXPERIMENTS_ENABLED=false \
    KALI_MCP_SANDBOX_ENABLED=false \
    NO_PROXY=*

USER 65532:65532

STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["node", "-e", "import('@script-kitty/kali-mcp-assessment').then(m => { if (m.KALI_MODE !== 'LAB_SANDBOX_ONLY') process.exit(1); })"]

# Default safe non-mutating CLI entrypoint (override to apps/mcp-server/dist/index.js for MCP stdio)
CMD ["node", "apps/cli/dist/index.js", "--help"]
