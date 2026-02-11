# syntax=docker/dockerfile:1.7
ARG NODE_VERSION=22.12.0

FROM node:${NODE_VERSION}-alpine AS deps-prod
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM node:${NODE_VERSION}-alpine AS deps-build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci && npm cache clean --force

FROM node:${NODE_VERSION}-alpine AS build
WORKDIR /app
COPY --from=deps-build /app/node_modules ./node_modules

# WICHTIG: package.json für "npm run build"
COPY package.json package-lock.json ./
COPY tsconfig.json ./
COPY src ./src

RUN npm run build

FROM node:${NODE_VERSION}-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

COPY --chown=node:node --from=deps-prod /app/node_modules ./node_modules
COPY --chown=node:node --from=build /app/dist ./dist
COPY --chown=node:node package.json package-lock.json ./

# chmod direkt beim COPY (kein RUN nötig)
COPY --chown=node:node --chmod=0755 docker/entrypoint.sh /entrypoint.sh

USER node
EXPOSE 3000
ENTRYPOINT ["/entrypoint.sh"]
CMD ["node", "dist/server.js"]
