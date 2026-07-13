import procedureInventory from './trpc-procedures.json' with { type: 'json' };

const ALL_TRPC_PROCEDURES = new Set(procedureInventory);

const PUBLIC_TRPC_PROCEDURES = new Set([
  'auth.passkey.createAuthenticationOptions',
  'auth.passkey.find',
  'document.accessAuth.request2FAEmail',
  'envelope.attachment.find',
  'envelope.field.sign',
  'envelope.recipient.report',
  'envelope.signingStatus',
  'field.removeSignedFieldWithToken',
  'field.signFieldWithToken',
  'recipient.completeDocumentWithToken',
  'recipient.rejectDocumentWithToken',
  'template.createDocumentFromDirectTemplate',
]);

const READ_METHODS = new Set(['GET', 'HEAD']);
const TRPC_METHODS = new Set(['GET', 'POST']);
const STAFF_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']);
const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

const PUBLIC_ASSET_PATTERNS = [
  /^\/assets\/.+/,
  /^\/__manifest[^/]*$/,
  /^\/fonts\/.+/,
  /^\/static\/.+/,
  /^\/site\.webmanifest$/,
  /^\/robots\.txt$/,
  /^\/opengraph-image\.jpg$/,
  /^\/\.well-known\/security\.txt$/,
  /^\/favicon\.ico$/,
  /^\/favicon-[^/]+\.png$/,
  /^\/apple-touch-icon\.png$/,
  /^\/android-chrome-[^/]+\.png$/,
];

const TOKEN_PAGE_PATTERNS = [
  /^\/sign\/[^/]+$/,
  /^\/sign\/[^/]+\/(?:complete|expired|rejected|waiting)$/,
  /^\/d\/[^/]+$/,
  /^\/report\/[^/]+$/,
  /^\/share\/[^/]+$/,
  /^\/share\/[^/]+\/opengraph$/,
  /^\/articles\/signature-disclosure$/,
];

const STAFF_PAGE_PATTERNS = [
  /^\/$/,
  /^\/(?:dashboard|inbox)$/,
  /^\/admin(?:\/.*)?$/,
  /^\/settings(?:\/.*)?$/,
  /^\/t\/[^/]+(?:\/.*)?$/,
  /^\/o\/[^/]+(?:\/.*)?$/,
  /^\/(?:signin|forgot-password|reset-password|check-email|verify-email|unverified-account)$/,
  /^\/(?:reset-password|verify-email)\/[^/]+$/,
  /^\/team\/verify\/email\/[^/]+$/,
  /^\/organisation\/(?:invite|decline)\/[^/]+$/,
];

const BLOCKED_PAGE_PATTERNS = [
  /^\/signup$/,
  /^\/o\/[^/]+\/signin$/,
  /^\/organisation\/sso\/confirmation\/[^/]+$/,
  /^\/embed(?:\/.*)?$/,
  /^\/p\/[^/]+$/,
  /^\/ingest(?:\/.*)?$/,
];

const TOKEN_FILE_PATTERNS = [
  /^\/api\/avatar\/[^/]+$/,
  /^\/api\/branding\/logo\/(?:team|organisation)\/[^/]+$/,
  /^\/api\/files\/token\/[^/]+\/envelopeItem\/[^/]+$/,
  /^\/api\/files\/token\/[^/]+\/envelopeItem\/[^/]+\/download$/,
  /^\/api\/files\/token\/[^/]+\/envelopeItem\/[^/]+\/download\/[^/]+$/,
  /^\/api\/files\/token\/[^/]+\/envelope\/[^/]+\/envelopeItem\/[^/]+\/dataId\/[^/]+\/[^/]+\/item\.pdf$/,
];

const STAFF_FILE_RULES = [
  ['POST', /^\/api\/files\/(?:upload-pdf|presigned-post-url)$/],
  ['GET', /^\/api\/files\/envelope\/[^/]+\/envelopeItem\/[^/]+$/],
  ['GET', /^\/api\/files\/envelope\/[^/]+\/envelopeItem\/[^/]+\/download$/],
  ['GET', /^\/api\/files\/envelope\/[^/]+\/envelopeItem\/[^/]+\/download\/[^/]+$/],
  ['GET', /^\/api\/files\/envelope\/[^/]+\/envelopeItem\/[^/]+\/dataId\/[^/]+\/[^/]+\/item\.pdf$/],
  ['GET', /^\/api\/limits$/],
];

const PUBLIC_AUTH_RULES = new Set([
  'GET /api/auth/csrf',
  'GET /api/auth/session',
  'GET /api/auth/session-json',
  'POST /api/auth/email-password/authorize',
  'POST /api/auth/passkey/authorize',
]);

const BLOCKED_API_PATTERNS = [
  /^\/api\/(?:v1|v2|v2-beta)(?:\/.*)?$/,
  /^\/api\/ai(?:\/.*)?$/,
  /^\/api\/csc(?:\/.*)?$/,
  /^\/api\/stripe\/webhook$/,
  /^\/api\/certificate-status$/,
  /^\/api\/health$/,
  /^\/api\/jobs(?:\/.*)?$/,
  /^\/api\/webhook\/trigger$/,
  /^\/__htmltopdf\/(?:audit-log|certificate)$/,
];

const matchesAny = (path, patterns) => patterns.some((pattern) => pattern.test(path));

export function normalizePolicyPath(rawTarget) {
  if (typeof rawTarget !== 'string' || !rawTarget.startsWith('/')) {
    throw new Error('invalid_target');
  }

  const rawPath = rawTarget.split('?', 1)[0];

  if (
    rawPath.includes('\\') ||
    rawPath.includes('\0') ||
    rawPath.includes(';') ||
    rawPath.includes('//') ||
    /%(?:00|2f|5c)/i.test(rawPath)
  ) {
    throw new Error('ambiguous_path');
  }

  let decodedPath;

  try {
    decodedPath = decodeURIComponent(rawPath);
  } catch {
    throw new Error('invalid_encoding');
  }

  if (
    decodedPath.includes('\\') ||
    decodedPath.includes('\0') ||
    decodedPath.includes('//') ||
    /%[0-9a-f]{2}/i.test(decodedPath) ||
    decodedPath.split('/').some((segment) => segment === '.' || segment === '..')
  ) {
    throw new Error('ambiguous_path');
  }

  return decodedPath.endsWith('.data') ? decodedPath.slice(0, -5) : decodedPath;
}

function result(policy, rateClass = null, bodyLimit = 2 * 1024 * 1024, allowedMethods = []) {
  return { policy, rateClass, bodyLimit, allowedMethods };
}

function rejectMethod(knownPath, allowedMethods = []) {
  return result(knownPath ? 'method_not_allowed' : 'blocked', null, 2 * 1024 * 1024, allowedMethods);
}

function classifyTrpc(method, path) {
  const prefix = '/api/trpc/';
  const procedureSegment = path.slice(prefix.length);

  if (!TRPC_METHODS.has(method)) {
    return rejectMethod(procedureSegment.length > 0, [...TRPC_METHODS]);
  }

  if (!procedureSegment || procedureSegment.includes('/')) {
    return result('blocked');
  }

  const procedures = procedureSegment.split(',');
  const uniqueProcedures = new Set(procedures);

  if (procedures.some((procedure) => !procedure) || uniqueProcedures.size !== procedures.length) {
    return result('blocked');
  }

  if (procedures.some((procedure) => procedure.startsWith('enterprise.'))) {
    return result('blocked');
  }

  if (procedures.some((procedure) => !ALL_TRPC_PROCEDURES.has(procedure))) {
    return result('blocked');
  }

  const publicCount = procedures.filter((procedure) => PUBLIC_TRPC_PROCEDURES.has(procedure)).length;

  if (publicCount === procedures.length) {
    return result('public', 'public_trpc');
  }

  if (publicCount > 0) {
    return result('blocked');
  }

  return result('staff');
}

function classifyPathAndMethod({ method, rawTarget, hasBody = false, pdfUploadBodyLimit = 12 * 1024 * 1024 }) {
  const normalizedMethod = String(method || '').toUpperCase();
  let path;

  try {
    path = normalizePolicyPath(rawTarget);
  } catch {
    return result('malformed');
  }

  if ((normalizedMethod === 'GET' || normalizedMethod === 'HEAD') && hasBody) {
    return result('malformed');
  }

  if (matchesAny(path, PUBLIC_ASSET_PATTERNS)) {
    return READ_METHODS.has(normalizedMethod) ? result('public_asset') : rejectMethod(true, [...READ_METHODS]);
  }

  if (matchesAny(path, BLOCKED_PAGE_PATTERNS)) {
    return result('blocked');
  }

  if (matchesAny(path, TOKEN_PAGE_PATTERNS)) {
    return READ_METHODS.has(normalizedMethod) ? result('public', 'token') : rejectMethod(true, [...READ_METHODS]);
  }

  if (matchesAny(path, STAFF_PAGE_PATTERNS)) {
    return STAFF_METHODS.has(normalizedMethod) ? result('staff') : rejectMethod(true, [...STAFF_METHODS]);
  }

  if (matchesAny(path, TOKEN_FILE_PATTERNS)) {
    return READ_METHODS.has(normalizedMethod) ? result('public', 'token') : rejectMethod(true, [...READ_METHODS]);
  }

  if (path === '/api/theme' || path === '/api/locale') {
    return normalizedMethod === 'POST' ? result('public', 'public_auth') : rejectMethod(true, ['POST']);
  }

  const matchingStaffFile = STAFF_FILE_RULES.find(([, pattern]) => pattern.test(path));

  if (matchingStaffFile) {
    const [allowedMethod] = matchingStaffFile;
    const uploadLimit = path === '/api/files/upload-pdf' ? pdfUploadBodyLimit : 2 * 1024 * 1024;
    return normalizedMethod === allowedMethod
      ? result('staff', null, uploadLimit)
      : rejectMethod(true, [allowedMethod]);
  }

  const authRule = `${normalizedMethod} ${path}`;

  if (PUBLIC_AUTH_RULES.has(authRule)) {
    return result('public', 'public_auth');
  }

  const knownPublicAuthPath = [...PUBLIC_AUTH_RULES].filter((rule) => rule.endsWith(` ${path}`));
  if (knownPublicAuthPath.length > 0) {
    return rejectMethod(
      true,
      knownPublicAuthPath.map((rule) => rule.split(' ', 1)[0]),
    );
  }

  if (path.startsWith('/api/auth/')) {
    return STAFF_METHODS.has(normalizedMethod) ? result('staff') : rejectMethod(true, [...STAFF_METHODS]);
  }

  if (path.startsWith('/api/trpc/')) {
    return classifyTrpc(normalizedMethod, path);
  }

  if (matchesAny(path, BLOCKED_API_PATTERNS)) {
    return result('blocked');
  }

  return result('blocked');
}

export function classifyRequest(options) {
  const decision = classifyPathAndMethod(options);
  const method = String(options.method || '').toUpperCase();
  const allowedPolicy = new Set(['public', 'public_asset', 'staff']).has(decision.policy);

  if (allowedPolicy && STATE_CHANGING_METHODS.has(method) && options.origin !== options.canonicalOrigin) {
    return result('origin_rejected');
  }

  return decision;
}

export const policyConstants = {
  ALL_TRPC_PROCEDURES,
  PUBLIC_TRPC_PROCEDURES,
};
