# =============================================================================
# Stage 1 — dependency installer
#   Installs all node_modules on an Alpine Node image.
#   The result is cached as a separate layer; re-runs only when package-lock
#   changes.
# =============================================================================
FROM node:20-alpine AS deps

# libc6-compat is required by some native Node addons on musl-based Alpine.
RUN apk add --no-cache libc6-compat

WORKDIR /app

COPY package.json package-lock.json ./
# --ignore-scripts prevents postinstall hooks from running with network access.
# NPM_CONFIG_UPDATE_NOTIFIER=false suppresses the "new npm version" banner.
RUN NPM_CONFIG_UPDATE_NOTIFIER=false npm ci --ignore-scripts


# =============================================================================
# Stage 2 — Next.js builder
#   Compiles the application.  The standalone output mode writes a minimal
#   self-contained server to .next/standalone — no node_modules needed at
#   runtime.
# =============================================================================
FROM node:20-alpine AS builder

ENV NEXT_TELEMETRY_DISABLED=1 \
    NPM_CONFIG_UPDATE_NOTIFIER=false

WORKDIR /app

# Bring in installed node_modules from the deps stage.
COPY --from=deps /app/node_modules ./node_modules

# Copy all source files (excludes everything in .dockerignore).
COPY . .

RUN npm run build


# =============================================================================
# Stage 3 — production runtime
#   Copies only the standalone server bundle + static assets.  The final image
#   contains no node_modules, no source, and no build toolchain.
# =============================================================================
FROM node:20-alpine AS runtime

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME="0.0.0.0"

# ---- Non-root security context ----
RUN addgroup --system --gid 1001 nodejs \
    && adduser  --system --uid 1001 --ingroup nodejs nextjs

WORKDIR /app

# Copy the standalone server and the static output.
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static     ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public           ./public

USER nextjs

EXPOSE 3000

# ---- Health check ----
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO- http://localhost:3000 >/dev/null 2>&1 || exit 1

# The standalone build exposes a server.js entry point.
CMD ["node", "server.js"]
