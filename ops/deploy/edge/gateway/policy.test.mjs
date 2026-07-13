import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyRequest, normalizePolicyPath, policyConstants } from './policy.mjs';

const canonicalOrigin = 'https://sign.example.test';

const classify = (method, rawTarget, options = {}) =>
  classifyRequest({
    method,
    rawTarget,
    canonicalOrigin,
    origin: options.origin ?? (method === 'GET' || method === 'HEAD' ? undefined : canonicalOrigin),
    hasBody: options.hasBody ?? false,
  });

test('normalizes one React Router data suffix', () => {
  assert.equal(normalizePolicyPath('/sign/opaque.data?x=1'), '/sign/opaque');
});

test('rejects ambiguous and encoded separator paths', () => {
  for (const path of ['/sign//x', '/sign/%2fx', '/sign/%252fx', '/a/../b', '/a%5cb', '/a;b']) {
    assert.equal(classify('GET', path).policy, 'malformed');
  }
});

test('classifies public assets and token pages narrowly', () => {
  for (const path of [
    '/assets/app-abc.js',
    '/__manifest',
    '/fonts/font.woff2',
    '/static/image.png',
    '/site.webmanifest',
    '/robots.txt',
    '/opengraph-image.jpg',
    '/.well-known/security.txt',
    '/favicon.ico',
    '/favicon-32x32.png',
    '/apple-touch-icon.png',
    '/android-chrome-192x192.png',
  ]) {
    assert.equal(classify('GET', path).policy, 'public_asset');
  }
  assert.equal(classify('POST', '/assets/app-abc.js').policy, 'method_not_allowed');
  assert.deepEqual(classify('POST', '/assets/app-abc.js').allowedMethods, ['GET', 'HEAD']);
  for (const path of [
    '/sign/token',
    '/sign/token/complete',
    '/sign/token/expired',
    '/sign/token/rejected',
    '/sign/token/waiting',
    '/d/token',
    '/report/token',
    '/share/slug',
    '/share/slug/opengraph',
    '/articles/signature-disclosure',
  ]) {
    assert.equal(classify('GET', path).policy, 'public');
  }
  assert.equal(classify('GET', '/sign/token/extra').policy, 'blocked');
  assert.equal(classify('GET', '/p/public-name').policy, 'blocked');
});

test('requires staff policy for management and staff authentication pages', () => {
  for (const path of [
    '/',
    '/dashboard',
    '/inbox',
    '/admin',
    '/admin/users',
    '/settings/security',
    '/t/team/documents',
    '/o/org/settings',
    '/signin',
    '/forgot-password',
    '/reset-password',
    '/reset-password/token',
    '/check-email',
    '/verify-email',
    '/verify-email/token',
    '/team/verify/email/token',
    '/unverified-account',
    '/organisation/invite/token',
    '/organisation/decline/token',
  ]) {
    assert.equal(classify('GET', path).policy, 'staff');
  }

  for (const path of [
    '/signup',
    '/o/org/signin',
    '/organisation/sso/confirmation/token',
    '/embed/v1',
    '/p/profile',
    '/ingest/event',
  ]) {
    assert.equal(classify('GET', path).policy, 'blocked');
  }
});

test('enforces exact public authentication routes and canonical origin', () => {
  assert.equal(classify('GET', '/api/auth/session').policy, 'public');
  assert.equal(classify('POST', '/api/auth/email-password/authorize').policy, 'public');
  assert.equal(
    classify('POST', '/api/auth/email-password/authorize', { origin: 'https://evil.example' }).policy,
    'origin_rejected',
  );
  assert.equal(classify('POST', '/api/nope', { origin: 'https://evil.example' }).policy, 'blocked');
  assert.equal(classify('POST', '/api/auth/signout').policy, 'staff');
});

test('enforces exact token and staff file routes', () => {
  for (const path of [
    '/api/avatar/id',
    '/api/branding/logo/team/id',
    '/api/branding/logo/organisation/id',
    '/api/files/token/t/envelopeItem/i',
    '/api/files/token/t/envelopeItem/i/download',
    '/api/files/token/t/envelopeItem/i/download/v1',
    '/api/files/token/t/envelope/e/envelopeItem/i/dataId/d/v1/item.pdf',
  ]) {
    assert.equal(classify('GET', path).policy, 'public');
  }
  assert.equal(classify('POST', '/api/files/token/t/envelopeItem/i/download/v1').policy, 'method_not_allowed');
  assert.equal(classify('POST', '/api/files/upload-pdf').policy, 'staff');
  assert.equal(classify('POST', '/api/files/upload-pdf').bodyLimit, 12 * 1024 * 1024);
  assert.equal(classify('POST', '/api/files/presigned-post-url').policy, 'staff');
  assert.equal(classify('GET', '/api/files/envelope/e/envelopeItem/i/download/v1').policy, 'staff');
  assert.equal(classify('GET', '/api/files/envelope/e/envelopeItem/i/dataId/d/v1/item.pdf').policy, 'staff');
  assert.equal(classify('GET', '/api/limits').policy, 'staff');
});

test('allows only homogeneous known public TRPC batches', () => {
  assert.equal(policyConstants.PUBLIC_TRPC_PROCEDURES.size, 12);
  for (const procedure of policyConstants.PUBLIC_TRPC_PROCEDURES) {
    assert.equal(policyConstants.ALL_TRPC_PROCEDURES.has(procedure), true);
  }
  assert.equal(classify('POST', '/api/trpc/envelope.field.sign').policy, 'public');
  assert.equal(classify('POST', '/api/trpc/envelope.field.sign,recipient.completeDocumentWithToken').policy, 'public');
  assert.equal(classify('POST', '/api/trpc/envelope.field.sign,admin.user.create').policy, 'blocked');
  assert.equal(classify('POST', '/api/trpc/envelope.field.sign,envelope.field.sign').policy, 'blocked');
  assert.equal(classify('POST', '/api/trpc/enterprise.csc.signEnvelope').policy, 'blocked');
  assert.equal(classify('POST', '/api/trpc/admin.user.create').policy, 'staff');
  assert.equal(classify('POST', '/api/trpc/not.a.real.procedure').policy, 'blocked');
});

test('classifies every pinned TRPC procedure', () => {
  for (const procedure of policyConstants.ALL_TRPC_PROCEDURES) {
    const expected = procedure.startsWith('enterprise.')
      ? 'blocked'
      : policyConstants.PUBLIC_TRPC_PROCEDURES.has(procedure)
        ? 'public'
        : 'staff';
    assert.equal(classify('POST', `/api/trpc/${procedure}`).policy, expected, procedure);
  }
});

test('blocks internal, integration, and unknown APIs', () => {
  for (const path of [
    '/api/health',
    '/api/jobs/trigger',
    '/api/webhook/trigger',
    '/api/v1/documents',
    '/api/v2/documents',
    '/api/v2-beta/documents',
    '/api/ai/chat',
    '/api/csc/sign',
    '/api/stripe/webhook',
    '/api/certificate-status',
    '/__htmltopdf/audit-log',
    '/__htmltopdf/certificate',
    '/api/nope',
  ]) {
    assert.equal(classify('GET', path).policy, 'blocked');
  }
});

test('rejects request bodies on GET and HEAD', () => {
  assert.equal(classify('GET', '/sign/token', { hasBody: true }).policy, 'malformed');
  assert.equal(classify('HEAD', '/assets/app.js', { hasBody: true }).policy, 'malformed');
});
