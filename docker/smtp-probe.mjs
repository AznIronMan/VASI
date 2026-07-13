import { readFileSync } from 'node:fs';

import { createTransport } from 'nodemailer';

const readSecret = (environmentKey, fileKey) => {
  if (process.env[environmentKey]) {
    throw new Error(`${environmentKey} must be supplied through ${fileKey}, not inline.`);
  }

  const path = process.env[fileKey];

  if (!path) {
    throw new Error(`${fileKey} must be set.`);
  }

  const value = readFileSync(path, 'utf8').replace(/[\r\n]+$/, '');

  if (!value) {
    throw new Error(`${fileKey} points to an empty secret.`);
  }

  return value;
};

const host = process.env.NEXT_PRIVATE_SMTP_HOST;
const port = Number(process.env.NEXT_PRIVATE_SMTP_PORT);
const from = process.env.NEXT_PRIVATE_SMTP_FROM_ADDRESS;
const to = process.env.VASI_SMTP_PROBE_TO;

if (host !== 'smtp.azurecomm.net' || port !== 587) {
  throw new Error('The SMTP probe only supports the approved Azure Communication Services endpoint.');
}

if (process.env.NEXT_PRIVATE_SMTP_SECURE !== 'false') {
  throw new Error('NEXT_PRIVATE_SMTP_SECURE must be false for port 587 STARTTLS.');
}

if (process.env.NEXT_PRIVATE_SMTP_REQUIRE_TLS !== 'true') {
  throw new Error('NEXT_PRIVATE_SMTP_REQUIRE_TLS must be true.');
}

if (!from || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(from)) {
  throw new Error('NEXT_PRIVATE_SMTP_FROM_ADDRESS must be a valid sender address.');
}

if (to && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(to)) {
  throw new Error('VASI_SMTP_PROBE_TO must be a single valid recipient address.');
}

const transporter = createTransport({
  host,
  port,
  secure: false,
  requireTLS: true,
  ignoreTLS: false,
  tls: {
    minVersion: 'TLSv1.2',
    servername: host,
  },
  auth: {
    user: readSecret('NEXT_PRIVATE_SMTP_USERNAME', 'NEXT_PRIVATE_SMTP_USERNAME_FILE'),
    pass: readSecret('NEXT_PRIVATE_SMTP_PASSWORD', 'NEXT_PRIVATE_SMTP_PASSWORD_FILE'),
  },
});

try {
  await transporter.verify();
  console.log('SMTP authentication and mandatory STARTTLS verification passed.');

  if (to) {
    await transporter.sendMail({
      from: `${process.env.NEXT_PRIVATE_SMTP_FROM_NAME || 'VASI'} <${from}>`,
      to,
      subject: 'VASI transactional email delivery probe',
      text: 'This synthetic message verifies the VASI transactional email delivery path. It contains no document or recipient workflow data.',
    });

    console.log('Synthetic SMTP delivery was accepted by the provider.');
  }
} catch (error) {
  const code = typeof error === 'object' && error && 'code' in error ? String(error.code) : 'UNKNOWN';
  const safeCode = /^[A-Z0-9_-]{1,40}$/i.test(code) ? code : 'UNKNOWN';

  console.error(`SMTP probe failed with provider/client code ${safeCode}; inspect protected provider diagnostics.`);
  process.exitCode = 1;
} finally {
  transporter.close();
}
