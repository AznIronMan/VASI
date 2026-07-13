import assert from 'node:assert/strict';
import test from 'node:test';

import { bootstrapInitialAdmin, validateBootstrapInputs } from './bootstrap-admin-lib.mjs';

test('normalizes and validates bootstrap inputs', () => {
  assert.deepEqual(
    validateBootstrapInputs({
      email: ' Initial.Admin@Example.Test ',
      name: ' Initial Administrator ',
      password: 'correct horse battery staple',
    }),
    {
      email: 'initial.admin@example.test',
      name: 'Initial Administrator',
      password: 'correct horse battery staple',
    },
  );

  assert.throws(() => validateBootstrapInputs({ email: 'bad', name: 'Admin', password: 'long-enough-password' }));
  assert.throws(() =>
    validateBootstrapInputs({
      email: 'admin@example.test',
      name: 'https://bad.example',
      password: 'long-enough-password',
    }),
  );
  assert.throws(() => validateBootstrapInputs({ email: 'admin@example.test', name: 'Admin', password: 'short' }));
});

const fakePrisma = ({ adminCount = 0, existingUser = null } = {}) => {
  const created = [];
  return {
    created,
    user: {
      count: () => adminCount,
      findUnique: () => existingUser,
      create: (input) => {
        created.push(input);
        return { id: 42 };
      },
    },
  };
};

test('creates exactly one verified native administrator with a hashed password', async () => {
  const prisma = fakePrisma();
  const user = await bootstrapInitialAdmin({
    prisma,
    hashPassword: (password) => `hashed:${password}`,
    email: 'admin@example.test',
    name: 'Initial Administrator',
    password: 'correct horse battery staple',
  });

  assert.equal(user.id, 42);
  assert.equal(prisma.created.length, 1);
  assert.deepEqual(prisma.created[0].data.roles, ['USER', 'ADMIN']);
  assert.equal(prisma.created[0].data.password, 'hashed:correct horse battery staple');
  assert.equal(prisma.created[0].data.source, 'VASI_BOOTSTRAP');
  assert.equal(prisma.created[0].data.emailVerified instanceof Date, true);
});

test('refuses an existing administrator or duplicate email without hashing', async () => {
  let hashCalls = 0;
  const hashPassword = () => {
    hashCalls += 1;
    return 'hashed';
  };

  await assert.rejects(
    bootstrapInitialAdmin({
      prisma: fakePrisma({ adminCount: 1 }),
      hashPassword,
      email: 'admin@example.test',
      name: 'Admin',
      password: 'long-enough-password',
    }),
    /administrator already exists/,
  );

  await assert.rejects(
    bootstrapInitialAdmin({
      prisma: fakePrisma({ existingUser: { id: 7 } }),
      hashPassword,
      email: 'admin@example.test',
      name: 'Admin',
      password: 'long-enough-password',
    }),
    /email already exists/,
  );

  assert.equal(hashCalls, 0);
});
