type Environment = Record<string, string | undefined>;

const REQUIRED_SECRET_KEYS = [
  'NEXTAUTH_SECRET',
  'NEXT_PRIVATE_ENCRYPTION_KEY',
  'NEXT_PRIVATE_ENCRYPTION_SECONDARY_KEY',
] as const;

const DISABLED_INTEGRATION_KEYS = [
  'NEXT_PRIVATE_DOCUMENSO_LICENSE_KEY',
  'NEXT_PUBLIC_POSTHOG_KEY',
  'NEXT_PRIVATE_GOOGLE_CLIENT_ID',
  'NEXT_PRIVATE_GOOGLE_CLIENT_SECRET',
  'GOOGLE_APPLICATION_CREDENTIALS',
  'NEXT_PRIVATE_MICROSOFT_CLIENT_ID',
  'NEXT_PRIVATE_MICROSOFT_CLIENT_SECRET',
  'NEXT_PRIVATE_OIDC_WELL_KNOWN',
  'NEXT_PRIVATE_OIDC_CLIENT_ID',
  'NEXT_PRIVATE_OIDC_CLIENT_SECRET',
  'NEXT_PRIVATE_OIDC_PROVIDER_LABEL',
  'NEXT_PRIVATE_OIDC_SKIP_VERIFY',
  'NEXT_PRIVATE_OIDC_PROMPT',
  'NEXT_PRIVATE_ALLOWED_SIGNUP_DOMAINS',
  'NEXT_PRIVATE_STRIPE_API_KEY',
  'NEXT_PRIVATE_STRIPE_WEBHOOK_SECRET',
  'NEXT_PUBLIC_STRIPE_ENTERPRISE_PLAN_MONTHLY_PRICE_ID',
  'NEXT_PRIVATE_SES_ACCESS_KEY_ID',
  'NEXT_PRIVATE_SES_SECRET_ACCESS_KEY',
  'NEXT_PRIVATE_SES_REGION',
  'NEXT_PRIVATE_RESEND_API_KEY',
  'NEXT_PRIVATE_SMTP_APIKEY_USER',
  'NEXT_PRIVATE_SMTP_APIKEY',
  'NEXT_PRIVATE_SMTP_SERVICE',
  'NEXT_PRIVATE_MAILCHANNELS_API_KEY',
  'NEXT_PRIVATE_MAILCHANNELS_ENDPOINT',
  'NEXT_PRIVATE_MAILCHANNELS_DKIM_DOMAIN',
  'NEXT_PRIVATE_MAILCHANNELS_DKIM_SELECTOR',
  'NEXT_PRIVATE_MAILCHANNELS_DKIM_PRIVATE_KEY',
  'NEXT_PRIVATE_TURNSTILE_SECRET_KEY',
  'NEXT_PUBLIC_TURNSTILE_SITE_KEY',
  'GOOGLE_VERTEX_PROJECT_ID',
  'GOOGLE_VERTEX_API_KEY',
  'NEXT_PRIVATE_PLAIN_API_KEY',
  'NEXT_PRIVATE_BROWSERLESS_URL',
  'NEXT_PRIVATE_DOCUMENT_CONVERSION_URL',
  'NEXT_PRIVATE_DOCUMENT_CONVERSION_USERNAME',
  'NEXT_PRIVATE_DOCUMENT_CONVERSION_PASSWORD',
  'NEXT_PRIVATE_DOCUMENT_CONVERSION_TIMEOUT_MS',
  'NEXT_PUBLIC_DOCUMENT_CONVERSION_ENABLED',
  'NEXT_PRIVATE_WEBHOOK_SSRF_BYPASS_HOSTS',
  'NEXT_PRIVATE_REDIS_URL',
  'NEXT_PRIVATE_REDIS_PREFIX',
  'NEXT_PRIVATE_BULLMQ_CONCURRENCY',
  'NEXT_PRIVATE_INNGEST_APP_ID',
  'NEXT_PRIVATE_INNGEST_EVENT_KEY',
  'INNGEST_EVENT_KEY',
  'INNGEST_SIGNING_KEY',
  'NEXT_PRIVATE_DATABASE_REPLICA_URLS',
  'NEXT_PRIVATE_UPLOAD_ENDPOINT',
  'NEXT_PRIVATE_UPLOAD_FORCE_PATH_STYLE',
  'NEXT_PRIVATE_UPLOAD_REGION',
  'NEXT_PRIVATE_UPLOAD_BUCKET',
  'NEXT_PRIVATE_UPLOAD_ACCESS_KEY_ID',
  'NEXT_PRIVATE_UPLOAD_SECRET_ACCESS_KEY',
  'NEXT_PRIVATE_UPLOAD_DISTRIBUTION_DOMAIN',
  'NEXT_PRIVATE_UPLOAD_DISTRIBUTION_KEY_ID',
  'NEXT_PRIVATE_UPLOAD_DISTRIBUTION_KEY_CONTENTS',
  'NEXT_PRIVATE_UPLOAD_AZURE_ACCOUNT_NAME',
  'NEXT_PRIVATE_UPLOAD_AZURE_ACCOUNT_KEY',
  'NEXT_PRIVATE_UPLOAD_AZURE_CONTAINER',
  'NEXT_PRIVATE_UPLOAD_AZURE_ENDPOINT',
  'NEXT_PRIVATE_SIGNING_GCLOUD_HSM_KEY_PATH',
  'NEXT_PRIVATE_SIGNING_GCLOUD_HSM_PUBLIC_CRT_FILE_PATH',
  'NEXT_PRIVATE_SIGNING_GCLOUD_HSM_PUBLIC_CRT_FILE_CONTENTS',
  'NEXT_PRIVATE_SIGNING_GCLOUD_APPLICATION_CREDENTIALS_CONTENTS',
  'NEXT_PRIVATE_SIGNING_GCLOUD_HSM_CERT_CHAIN_FILE_PATH',
  'NEXT_PRIVATE_SIGNING_GCLOUD_HSM_CERT_CHAIN_CONTENTS',
  'NEXT_PRIVATE_SIGNING_GCLOUD_HSM_SECRET_MANAGER_CERT_PATH',
  'NEXT_PRIVATE_SIGNING_CSC_PROVIDER_BASE_URL',
  'NEXT_PRIVATE_SIGNING_CSC_OAUTH_CLIENT_ID',
  'NEXT_PRIVATE_SIGNING_CSC_OAUTH_CLIENT_SECRET',
  'NEXT_PRIVATE_SIGNING_CSC_SIGNATURE_LEVEL',
  'NEXT_PUBLIC_SIGNING_TRANSPORT_IS_CSC',
  'NEXT_PRIVATE_SIGNING_LOCAL_FILE_ENCODING',
  'NEXT_PUBLIC_USE_INTERNAL_URL_BROWSERLESS',
  'NEXT_PRIVATE_USE_PLAYWRIGHT_PDF',
  'NEXT_PRIVATE_LOGGER_FILE_PATH',
  'NEXT_PRIVATE_TELEMETRY_KEY',
  'NEXT_PRIVATE_TELEMETRY_HOST',
  'NEXT_PRIVATE_DELETED_SERVICE_ACCOUNT_EMAIL',
  'NEXT_PRIVATE_LEGACY_SERVICE_ACCOUNT_EMAIL',
  'INTERNAL_OVERRIDE_LICENSE_SERVER_URL',
  'DEBUG_PDF_INSERT',
  'NEXT_DEBUG',
  'NEXT_DEBUG_AUTH',
  'NEXT_DEBUG_JOB',
  'NEXT_DEBUG_MIDDLEWARE',
  'PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH',
  'E2E_TEST_AUTHENTICATE_USERNAME',
  'E2E_TEST_AUTHENTICATE_USER_EMAIL',
  'E2E_TEST_AUTHENTICATE_USER_PASSWORD',
] as const;

const PLACEHOLDER_PATTERN = /(cafebabe|deadbeef|change.?me|example|password|replace|secret|todo)/i;
const RESERVED_HOST_PATTERN = /(^|\.)example\.(com|net|org)$|\.(example|invalid|test)$/i;

const isSet = (value: string | undefined): value is string => typeof value === 'string' && value.trim().length > 0;

const requireValue = (environment: Environment, key: string, errors: string[]): string => {
  const value = environment[key];

  if (!isSet(value)) {
    errors.push(`${key} must be set.`);
    return '';
  }

  return value;
};

const validateHttpsUrl = (environment: Environment, key: string, errors: string[]): string => {
  const value = requireValue(environment, key, errors);

  if (!value) {
    return '';
  }

  try {
    const url = new URL(value);

    if (url.protocol !== 'https:') {
      errors.push(`${key} must use HTTPS.`);
    }

    if (url.username || url.password) {
      errors.push(`${key} must not contain credentials.`);
    }

    if (url.pathname !== '/' || url.search || url.hash) {
      errors.push(`${key} must be an origin URL without a path, query, or fragment.`);
    }

    if (['localhost', '127.0.0.1', '::1'].includes(url.hostname)) {
      errors.push(`${key} must not use a loopback host in production.`);
    }

    if (RESERVED_HOST_PATTERN.test(url.hostname)) {
      errors.push(`${key} must not use a reserved example host in production.`);
    }
  } catch {
    errors.push(`${key} must be a valid absolute URL.`);
  }

  return value;
};

const validateDatabaseUrl = (environment: Environment, key: string, errors: string[]): void => {
  const value = requireValue(environment, key, errors);

  if (!value) {
    return;
  }

  try {
    const url = new URL(value);

    if (!['postgres:', 'postgresql:'].includes(url.protocol)) {
      errors.push(`${key} must use a PostgreSQL URL.`);
    }

    if (!url.username || !url.password || !url.hostname || !url.pathname.slice(1)) {
      errors.push(`${key} must include a database user, password, host, and database name.`);
    }

    if (['localhost', '127.0.0.1', '::1'].includes(url.hostname)) {
      errors.push(`${key} must not use a loopback database host in production.`);
    }

    if (url.password.length < 12 || PLACEHOLDER_PATTERN.test(url.password)) {
      errors.push(`${key} must include a strong, non-placeholder database password.`);
    }
  } catch {
    errors.push(`${key} must be a valid PostgreSQL URL.`);
  }
};

export const getVasiProductionConfigErrors = (environment: Environment): string[] => {
  if (environment.NODE_ENV !== 'production') {
    return [];
  }

  const errors: string[] = [];

  if (environment.VASI_CONFIG_PROFILE !== 'production') {
    errors.push('VASI_CONFIG_PROFILE must be production when NODE_ENV is production.');
  }

  for (const key of REQUIRED_SECRET_KEYS) {
    const value = requireValue(environment, key, errors);

    if (value && (value.length < 32 || PLACEHOLDER_PATTERN.test(value))) {
      errors.push(`${key} must be at least 32 characters and must not be a placeholder.`);
    }
  }

  if (
    isSet(environment.NEXT_PRIVATE_ENCRYPTION_KEY) &&
    environment.NEXT_PRIVATE_ENCRYPTION_KEY === environment.NEXT_PRIVATE_ENCRYPTION_SECONDARY_KEY
  ) {
    errors.push('The primary and secondary encryption keys must be different.');
  }

  const publicUrl = validateHttpsUrl(environment, 'NEXT_PUBLIC_WEBAPP_URL', errors);
  const internalUrl = validateHttpsUrl(environment, 'NEXT_PRIVATE_INTERNAL_WEBAPP_URL', errors);
  const signingContact = requireValue(environment, 'NEXT_PUBLIC_SIGNING_CONTACT_INFO', errors);

  if (signingContact && PLACEHOLDER_PATTERN.test(signingContact)) {
    errors.push('NEXT_PUBLIC_SIGNING_CONTACT_INFO must not be a placeholder.');
  }

  if (publicUrl && publicUrl === internalUrl) {
    errors.push('The public and internal web application URLs must be different.');
  }

  validateDatabaseUrl(environment, 'NEXT_PRIVATE_DATABASE_URL', errors);
  validateDatabaseUrl(environment, 'NEXT_PRIVATE_DIRECT_DATABASE_URL', errors);

  if (environment.NEXT_PUBLIC_UPLOAD_TRANSPORT !== 'database') {
    errors.push('NEXT_PUBLIC_UPLOAD_TRANSPORT must be database for the supported VASI profile.');
  }

  if (environment.NEXT_PRIVATE_JOBS_PROVIDER !== 'local') {
    errors.push('NEXT_PRIVATE_JOBS_PROVIDER must be local for the supported VASI profile.');
  }

  const uploadLimit = Number(environment.NEXT_PUBLIC_DOCUMENT_SIZE_UPLOAD_LIMIT);

  if (!Number.isInteger(uploadLimit) || uploadLimit < 1 || uploadLimit > 25) {
    errors.push('NEXT_PUBLIC_DOCUMENT_SIZE_UPLOAD_LIMIT must be an integer from 1 through 25.');
  }

  if (environment.NEXT_PRIVATE_SMTP_TRANSPORT !== 'smtp-auth') {
    errors.push('NEXT_PRIVATE_SMTP_TRANSPORT must be smtp-auth.');
  }

  for (const key of [
    'NEXT_PRIVATE_SMTP_HOST',
    'NEXT_PRIVATE_SMTP_PORT',
    'NEXT_PRIVATE_SMTP_USERNAME',
    'NEXT_PRIVATE_SMTP_PASSWORD',
    'NEXT_PRIVATE_SMTP_FROM_NAME',
    'NEXT_PRIVATE_SMTP_FROM_ADDRESS',
    'NEXT_PUBLIC_SUPPORT_EMAIL',
  ]) {
    requireValue(environment, key, errors);
  }

  const smtpPort = Number(environment.NEXT_PRIVATE_SMTP_PORT);

  if (!Number.isInteger(smtpPort) || smtpPort < 1 || smtpPort > 65535) {
    errors.push('NEXT_PRIVATE_SMTP_PORT must be an integer from 1 through 65535.');
  }

  const smtpHost = environment.NEXT_PRIVATE_SMTP_HOST ?? '';

  if (['localhost', '127.0.0.1', '::1'].includes(smtpHost) || RESERVED_HOST_PATTERN.test(smtpHost)) {
    errors.push('NEXT_PRIVATE_SMTP_HOST must not use a loopback or reserved example host in production.');
  }

  const smtpUsername = environment.NEXT_PRIVATE_SMTP_USERNAME ?? '';
  const smtpPassword = environment.NEXT_PRIVATE_SMTP_PASSWORD ?? '';

  if (PLACEHOLDER_PATTERN.test(smtpUsername)) {
    errors.push('NEXT_PRIVATE_SMTP_USERNAME must not be a placeholder.');
  }

  if (smtpPassword.length < 12 || PLACEHOLDER_PATTERN.test(smtpPassword)) {
    errors.push('NEXT_PRIVATE_SMTP_PASSWORD must be at least 12 characters and must not be a placeholder.');
  }

  for (const key of ['NEXT_PRIVATE_SMTP_FROM_ADDRESS', 'NEXT_PUBLIC_SUPPORT_EMAIL']) {
    const email = environment[key] ?? '';

    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || PLACEHOLDER_PATTERN.test(email)) {
      errors.push(`${key} must be a valid, non-example email address.`);
    }
  }

  if (smtpHost !== 'smtp.azurecomm.net') {
    errors.push('NEXT_PRIVATE_SMTP_HOST must use the approved Azure Communication Services endpoint.');
  }

  if (smtpPort !== 587) {
    errors.push('NEXT_PRIVATE_SMTP_PORT must be 587 for the approved Azure Communication Services profile.');
  }

  if (environment.NEXT_PRIVATE_SMTP_SECURE !== 'false') {
    errors.push('NEXT_PRIVATE_SMTP_SECURE must be false for STARTTLS on port 587.');
  }

  if (environment.NEXT_PRIVATE_SMTP_REQUIRE_TLS !== 'true') {
    errors.push('NEXT_PRIVATE_SMTP_REQUIRE_TLS must be true.');
  }

  if (environment.NEXT_PRIVATE_SMTP_UNSAFE_IGNORE_TLS === 'true') {
    errors.push('NEXT_PRIVATE_SMTP_UNSAFE_IGNORE_TLS must not be true.');
  }

  if (environment.NEXT_PRIVATE_SMTP_FROM_NAME === 'Documenso') {
    errors.push('NEXT_PRIVATE_SMTP_FROM_NAME must use the approved VASI sender identity.');
  }

  if (environment.NEXT_PRIVATE_SMTP_FROM_ADDRESS === 'noreply@documenso.com') {
    errors.push('NEXT_PRIVATE_SMTP_FROM_ADDRESS must use an approved CNB sender address.');
  }

  if (environment.NEXT_PRIVATE_SIGNING_TRANSPORT !== 'local') {
    errors.push('NEXT_PRIVATE_SIGNING_TRANSPORT must be local for the supported VASI profile.');
  }

  const signingPath = requireValue(environment, 'NEXT_PRIVATE_SIGNING_LOCAL_FILE_PATH', errors);

  if (signingPath && !signingPath.startsWith('/run/secrets/')) {
    errors.push('NEXT_PRIVATE_SIGNING_LOCAL_FILE_PATH must reference a /run/secrets mount.');
  }

  if (isSet(environment.NEXT_PRIVATE_SIGNING_LOCAL_FILE_CONTENTS)) {
    errors.push('NEXT_PRIVATE_SIGNING_LOCAL_FILE_CONTENTS must be unset; mount the certificate as a file.');
  }

  const signingPassphrase = requireValue(environment, 'NEXT_PRIVATE_SIGNING_PASSPHRASE', errors);

  if (signingPassphrase && (signingPassphrase.length < 12 || PLACEHOLDER_PATTERN.test(signingPassphrase))) {
    errors.push('NEXT_PRIVATE_SIGNING_PASSPHRASE must be at least 12 characters and must not be a placeholder.');
  }

  for (const key of [
    'NEXT_PUBLIC_DISABLE_SIGNUP',
    'NEXT_PUBLIC_DISABLE_EMAIL_PASSWORD_SIGNUP',
    'NEXT_PUBLIC_DISABLE_GOOGLE_SIGNUP',
    'NEXT_PUBLIC_DISABLE_MICROSOFT_SIGNUP',
    'NEXT_PUBLIC_DISABLE_OIDC_SIGNUP',
  ]) {
    if (environment[key] !== 'true') {
      errors.push(`${key} must be true.`);
    }
  }

  if (environment.NEXT_PUBLIC_FEATURE_BILLING_ENABLED === 'true') {
    errors.push('NEXT_PUBLIC_FEATURE_BILLING_ENABLED must not be true.');
  }

  if (environment.DOCUMENSO_DISABLE_TELEMETRY !== 'true') {
    errors.push('DOCUMENSO_DISABLE_TELEMETRY must be true.');
  }

  if (environment.DANGEROUS_BYPASS_RATE_LIMITS === 'true') {
    errors.push('DANGEROUS_BYPASS_RATE_LIMITS must not be true.');
  }

  if (environment.NEXT_PRIVATE_USE_LEGACY_SIGNING_SUBFILTER === 'true') {
    errors.push('NEXT_PRIVATE_USE_LEGACY_SIGNING_SUBFILTER must not be true.');
  }

  for (const key of DISABLED_INTEGRATION_KEYS) {
    if (isSet(environment[key])) {
      errors.push(`${key} is not enabled in the supported VASI production profile.`);
    }
  }

  return errors;
};

export const validateVasiProductionConfig = (environment: Environment = process.env): void => {
  const errors = getVasiProductionConfigErrors(environment);

  if (errors.length > 0) {
    throw new Error(`Unsafe VASI production configuration:\n- ${errors.join('\n- ')}`);
  }
};
