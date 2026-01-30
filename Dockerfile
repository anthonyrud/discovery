# syntax=docker/dockerfile:1
FROM node:22-alpine

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.js ./
COPY public ./public

ENV NODE_ENV=production
ENV PORT=5050
EXPOSE 5050

CMD ["node","server.js"]
