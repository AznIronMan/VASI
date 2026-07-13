import { describe, expect, it } from 'vitest';

import { getVasiProductionConfigErrors, validateVasiProductionConfig } from './validate-production-config';

const validProductionEnvironment = (): Record<string, string> => ({
  NODE_ENV: 'production',
  VASI_CONFIG_PROFILE: 'production',
  NEXTAUTH_SECRET: 'a-strong-session-value-that-is-unique-01',
  NEXT_PRIVATE_ENCRYPTION_KEY: 'a-strong-primary-value-that-is-unique-02',
  NEXT_PRIVATE_ENCRYPTION_SECONDARY_KEY: 'a-strong-secondary-value-that-is-unique-03',
  NEXT_PUBLIC_WEBAPP_URL: 'https://sign.company.tld',
  NEXT_PRIVATE_INTERNAL_WEBAPP_URL: 'https://origin.internal.company.tld',
  NEXT_PUBLIC_SIGNING_CONTACT_INFO: 'https://www.company.tld',
  NEXT_PRIVATE_DATABASE_URL: 'postgresql://vasi:strong-db-value@database.internal.company.tld/vasi',
  NEXT_PRIVATE_DIRECT_DATABASE_URL: 'postgresql://vasi:strong-db-value@database.internal.company.tld/vasi',
  NEXT_PUBLIC_UPLOAD_TRANSPORT: 'database',
  NEXT_PUBLIC_DOCUMENT_SIZE_UPLOAD_LIMIT: '10',
  NEXT_PRIVATE_JOBS_PROVIDER: 'local',
  NEXT_PRIVATE_SMTP_TRANSPORT: 'smtp-auth',
  NEXT_PRIVATE_SMTP_HOST: 'smtp.azurecomm.net',
  NEXT_PRIVATE_SMTP_PORT: '587',
  NEXT_PRIVATE_SMTP_USERNAME: 'vasi-smtp-user',
  NEXT_PRIVATE_SMTP_PASSWORD: 'strong-smtp-value-01',
  NEXT_PRIVATE_SMTP_SECURE: 'false',
  NEXT_PRIVATE_SMTP_REQUIRE_TLS: 'true',
  NEXT_PRIVATE_SMTP_FROM_NAME: 'VASI',
  NEXT_PRIVATE_SMTP_FROM_ADDRESS: 'signing@company.tld',
  NEXT_PUBLIC_SUPPORT_EMAIL: 'support@company.tld',
  NEXT_PRIVATE_SIGNING_TRANSPORT: 'local',
  NEXT_PRIVATE_SIGNING_LOCAL_FILE_PATH: '/run/secrets/vasi-signing.p12',
  NEXT_PRIVATE_SIGNING_PASSPHRASE: 'strong-p12-value',
  NEXT_PUBLIC_DISABLE_SIGNUP: 'true',
  NEXT_PUBLIC_DISABLE_EMAIL_PASSWORD_SIGNUP: 'true',
  NEXT_PUBLIC_DISABLE_GOOGLE_SIGNUP: 'true',
  NEXT_PUBLIC_DISABLE_MICROSOFT_SIGNUP: 'true',
  NEXT_PUBLIC_DISABLE_OIDC_SIGNUP: 'true',
  NEXT_PUBLIC_FEATURE_BILLING_ENABLED: 'false',
  DOCUMENSO_DISABLE_TELEMETRY: 'true',
});

describe('VASI production configuration validation', () => {
  it('accepts the supported production profile', () => {
    expect(getVasiProductionConfigErrors(validProductionEnvironment())).toEqual([]);
    expect(() => validateVasiProductionConfig(validProductionEnvironment())).not.toThrow();
  });

  it('does not constrain development environments', () => {
    expect(getVasiProductionConfigErrors({ NODE_ENV: 'development' })).toEqual([]);
  });

  it('rejects unsafe production defaults and unsupported features', () => {
    const environment = validProductionEnvironment();

    environment.NEXTAUTH_SECRET = 'secret';
    environment.NEXT_PRIVATE_ENCRYPTION_SECONDARY_KEY = environment.NEXT_PRIVATE_ENCRYPTION_KEY;
    environment.NEXT_PUBLIC_WEBAPP_URL = 'http://localhost:3000';
    environment.NEXT_PUBLIC_DISABLE_SIGNUP = 'false';
    environment.NEXT_PUBLIC_POSTHOG_KEY = 'configured';
    environment.DANGEROUS_BYPASS_RATE_LIMITS = 'true';

    const errors = getVasiProductionConfigErrors(environment);

    expect(errors).toContain('NEXTAUTH_SECRET must be at least 32 characters and must not be a placeholder.');
    expect(errors).toContain('The primary and secondary encryption keys must be different.');
    expect(errors).toContain('NEXT_PUBLIC_WEBAPP_URL must use HTTPS.');
    expect(errors).toContain('NEXT_PUBLIC_WEBAPP_URL must not use a loopback host in production.');
    expect(errors).toContain('NEXT_PUBLIC_DISABLE_SIGNUP must be true.');
    expect(errors).toContain('NEXT_PUBLIC_POSTHOG_KEY is not enabled in the supported VASI production profile.');
    expect(errors).toContain('DANGEROUS_BYPASS_RATE_LIMITS must not be true.');
  });

  it('never includes secret values in error output', () => {
    const environment = validProductionEnvironment();
    const sensitiveValue = 'secret-value-that-must-not-appear';

    environment.NEXTAUTH_SECRET = sensitiveValue;

    expect(() => validateVasiProductionConfig(environment)).toThrow('NEXTAUTH_SECRET');

    try {
      validateVasiProductionConfig(environment);
    } catch (error) {
      expect(String(error)).not.toContain(sensitiveValue);
    }
  });

  it('requires the approved STARTTLS SMTP profile', () => {
    const environment = validProductionEnvironment();

    environment.NEXT_PRIVATE_SMTP_HOST = 'smtp.company.tld';
    environment.NEXT_PRIVATE_SMTP_PORT = '465';
    environment.NEXT_PRIVATE_SMTP_SECURE = 'true';
    environment.NEXT_PRIVATE_SMTP_REQUIRE_TLS = 'false';

    const errors = getVasiProductionConfigErrors(environment);

    expect(errors).toContain('NEXT_PRIVATE_SMTP_HOST must use the approved Azure Communication Services endpoint.');
    expect(errors).toContain(
      'NEXT_PRIVATE_SMTP_PORT must be 587 for the approved Azure Communication Services profile.',
    );
    expect(errors).toContain('NEXT_PRIVATE_SMTP_SECURE must be false for STARTTLS on port 587.');
    expect(errors).toContain('NEXT_PRIVATE_SMTP_REQUIRE_TLS must be true.');
  });
});
