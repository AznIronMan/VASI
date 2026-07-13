import fs from 'node:fs';

import { bootstrapInitialAdmin, validateBootstrapInputs } from './bootstrap-admin-lib.mjs';

const required = (name) => {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
};

const readOneValueFile = (name) => {
  const file = required(name);
  const value = fs.readFileSync(file, 'utf8').replace(/[\r\n]+$/, '');
  if (!value || value.includes('\n') || value.includes('\r')) {
    throw new Error(`${name} must contain exactly one non-empty value`);
  }
  return value;
};

if (process.env.NEXT_PRIVATE_DATABASE_URL || process.env.NEXT_PRIVATE_DIRECT_DATABASE_URL) {
  throw new Error('Bootstrap mode accepts database credentials only through the _FILE variables');
}

const databaseUrl = readOneValueFile('NEXT_PRIVATE_DATABASE_URL_FILE');
// biome-ignore lint/nursery/noUndeclaredEnvVars: This one-shot container tool does not run through Turborepo.
const directDatabaseUrl = process.env.NEXT_PRIVATE_DIRECT_DATABASE_URL_FILE
  ? readOneValueFile('NEXT_PRIVATE_DIRECT_DATABASE_URL_FILE')
  : databaseUrl;
const { email, name, password } = validateBootstrapInputs({
  email: required('VASI_BOOTSTRAP_ADMIN_EMAIL'),
  name: required('VASI_BOOTSTRAP_ADMIN_NAME'),
  password: readOneValueFile('VASI_BOOTSTRAP_ADMIN_PASSWORD_FILE'),
});

process.env.NEXT_PRIVATE_DATABASE_URL = databaseUrl;
process.env.NEXT_PRIVATE_DIRECT_DATABASE_URL = directDatabaseUrl;

const [{ PrismaClient }, { hash }] = await Promise.all([import('@prisma/client'), import('@node-rs/bcrypt')]);

const prisma = new PrismaClient();

try {
  const user = await bootstrapInitialAdmin({
    prisma,
    hashPassword: async (value) => await hash(value, 12),
    email,
    name,
    password,
  });

  process.stdout.write(`VASI administrator created with user ID ${user.id}.\n`);
} finally {
  await prisma.$disconnect();
  process.env.NEXT_PRIVATE_DATABASE_URL = '';
  process.env.NEXT_PRIVATE_DIRECT_DATABASE_URL = '';
}
