FROM node:22-alpine3.22@sha256:cd7807368cf24826297cbad5dca1a44972ccfd770647db52a8c7589eb4599ac8

ENV NODE_ENV=production

RUN apk upgrade --no-cache && \
    rm -rf \
      /usr/local/lib/node_modules/corepack \
      /usr/local/lib/node_modules/npm \
      /usr/local/bin/corepack \
      /usr/local/bin/npm \
      /usr/local/bin/npx \
      /usr/local/bin/pnpm \
      /usr/local/bin/pnpx \
      /usr/local/bin/yarn \
      /usr/local/bin/yarnpkg

WORKDIR /app

COPY --chown=node:node policy.mjs server.mjs trpc-procedures.json ./

USER node

EXPOSE 8080

CMD ["node", "server.mjs"]
