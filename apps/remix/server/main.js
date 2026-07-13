/**
 * This is the main entry point for the server which will launch the RR7 application
 * and spin up auth, api, etc.
 *
 * Note:
 *  This file will be copied to the build folder during build time.
 *  Running this file will not work without a build.
 */
import { readFile } from 'node:fs/promises';
import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import handle from 'hono-react-router-adapter/node';

const secretFileVariables = {
  NEXTAUTH_SECRET: 'NEXTAUTH_SECRET_FILE',
  NEXT_PRIVATE_DATABASE_URL: 'NEXT_PRIVATE_DATABASE_URL_FILE',
  NEXT_PRIVATE_DIRECT_DATABASE_URL: 'NEXT_PRIVATE_DIRECT_DATABASE_URL_FILE',
  NEXT_PRIVATE_ENCRYPTION_KEY: 'NEXT_PRIVATE_ENCRYPTION_KEY_FILE',
  NEXT_PRIVATE_ENCRYPTION_SECONDARY_KEY: 'NEXT_PRIVATE_ENCRYPTION_SECONDARY_KEY_FILE',
  NEXT_PRIVATE_SIGNING_PASSPHRASE: 'NEXT_PRIVATE_SIGNING_PASSPHRASE_FILE',
  NEXT_PRIVATE_SMTP_PASSWORD: 'NEXT_PRIVATE_SMTP_PASSWORD_FILE',
  NEXT_PRIVATE_SMTP_USERNAME: 'NEXT_PRIVATE_SMTP_USERNAME_FILE',
};

for (const [targetVariable, fileVariable] of Object.entries(secretFileVariables)) {
  const filePath = process.env[fileVariable];

  if (!filePath) {
    continue;
  }

  if (process.env[targetVariable]) {
    throw new Error(`${targetVariable} and ${fileVariable} cannot both be set.`);
  }

  const value = (await readFile(filePath, 'utf8')).replace(/[\r\n]+$/, '');

  if (!value) {
    throw new Error(`${fileVariable} points to an empty secret file.`);
  }

  process.env[targetVariable] = value;
}

const { validateVasiProductionConfig } = await import(
  './hono/packages/lib/server-only/vasi/validate-production-config.js'
);

validateVasiProductionConfig();

const [{ getLoadContext, default: server }, build] = await Promise.all([
  import('./hono/server/router.js'),
  import('./index.js'),
]);

server.use(
  serveStatic({
    root: 'build/client',
    onFound: (path, c) => {
      if (path.startsWith('build/client/assets')) {
        // Hard cache assets with hashed file names.
        c.header('Cache-Control', 'public, immutable, max-age=31536000');
      } else {
        // Cache with revalidation for rest of static files.
        c.header('Cache-Control', 'public, max-age=0, stale-while-revalidate=86400');
      }
    },
  }),
);

const handler = handle(build, server, { getLoadContext });

const port = parseInt(process.env.PORT || '3000', 10);

serve({ fetch: handler.fetch, port });
