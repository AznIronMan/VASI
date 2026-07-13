FROM node:22-alpine3.22@sha256:cd7807368cf24826297cbad5dca1a44972ccfd770647db52a8c7589eb4599ac8

ENV NODE_ENV=production

WORKDIR /app

COPY --chown=node:node policy.mjs server.mjs trpc-procedures.json ./

USER node

EXPOSE 8080

CMD ["node", "server.mjs"]
