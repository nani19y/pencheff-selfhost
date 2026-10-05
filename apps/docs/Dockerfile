FROM node:25.9-alpine AS deps
WORKDIR /app
COPY package.json ./
# --legacy-peer-deps mirrors apps/web — avoids any Nextra / Next 15 peer-dep mismatches.
RUN npm install --legacy-peer-deps --no-audit --no-fund

FROM node:25.9-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:25.9-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/theme.config.tsx ./theme.config.tsx
COPY --from=builder /app/next.config.mjs ./next.config.mjs
COPY --from=builder /app/pages ./pages
EXPOSE 3001
CMD ["npm", "run", "start"]
