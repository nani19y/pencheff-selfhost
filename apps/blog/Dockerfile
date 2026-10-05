# ── Stage 1: install deps ────────────────────────────────────────────────────
FROM node:25.9-alpine AS deps
WORKDIR /app
COPY package.json ./
# --legacy-peer-deps mirrors apps/docs — avoids peer-dep conflicts between
# Next 15, React 19 RC, and the markdown rendering packages.
RUN npm install --legacy-peer-deps --no-audit --no-fund

# ── Stage 2: build ───────────────────────────────────────────────────────────
FROM node:25.9-alpine AS builder
WORKDIR /app

ARG NEXT_PUBLIC_LANDING_URL
ENV NEXT_PUBLIC_LANDING_URL=${NEXT_PUBLIC_LANDING_URL}
ENV NEXT_TELEMETRY_DISABLED=1

COPY --from=deps /app/node_modules ./node_modules
COPY . .
# Guarantee public/ exists — standalone runner COPY is unconditional.
RUN mkdir -p public
RUN npm run build

# ── Stage 3: runner ──────────────────────────────────────────────────────────
FROM node:25.9-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3002
ENV HOSTNAME=0.0.0.0
ENV NEXT_TELEMETRY_DISABLED=1

COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

# Ensure the volume mount point exists in the image layer.
RUN mkdir -p /content

EXPOSE 3002
CMD ["node", "server.js"]
