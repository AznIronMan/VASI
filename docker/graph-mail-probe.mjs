import { readFile } from 'node:fs/promises';

const GRAPH_SCOPE = 'https://graph.microsoft.com/.default';
const EMAIL_PATTERN = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

const requireValue = (name) => {
  const value = process.env[name]?.trim();

  if (!value) {
    throw new Error(`${name} must be set.`);
  }

  return value;
};

const readSecret = async (name, fileName) => {
  const inlineValue = process.env[name];
  const filePath = process.env[fileName];

  if (inlineValue && filePath) {
    throw new Error(`${name} and ${fileName} cannot both be set.`);
  }

  if (inlineValue) {
    return inlineValue;
  }

  if (!filePath) {
    throw new Error(`${fileName} must be set.`);
  }

  const value = (await readFile(filePath, 'utf8')).replace(/[\r\n]+$/, '');

  if (!value) {
    throw new Error(`${fileName} points to an empty secret file.`);
  }

  return value;
};

const tenantId = requireValue('NEXT_PRIVATE_MICROSOFT_GRAPH_TENANT_ID');
const clientId = requireValue('NEXT_PRIVATE_MICROSOFT_GRAPH_CLIENT_ID');
const senderAddress = requireValue('NEXT_PRIVATE_SMTP_FROM_ADDRESS');
const senderName = process.env.NEXT_PRIVATE_SMTP_FROM_NAME?.trim() || 'VASI';
const recipientAddress = process.env.VASI_GRAPH_MAIL_PROBE_TO?.trim();
const clientSecret = await readSecret(
  'NEXT_PRIVATE_MICROSOFT_GRAPH_CLIENT_SECRET',
  'NEXT_PRIVATE_MICROSOFT_GRAPH_CLIENT_SECRET_FILE',
);

if (!EMAIL_PATTERN.test(senderAddress)) {
  throw new Error('NEXT_PRIVATE_SMTP_FROM_ADDRESS must be a valid sender address.');
}

if (recipientAddress && !EMAIL_PATTERN.test(recipientAddress)) {
  throw new Error('VASI_GRAPH_MAIL_PROBE_TO must be a single valid recipient address.');
}

const tokenResponse = await fetch(
  `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`,
  {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: 'client_credentials',
      scope: GRAPH_SCOPE,
    }),
  },
);

if (!tokenResponse.ok) {
  throw new Error(`Microsoft Graph token request failed with status ${tokenResponse.status}.`);
}

const tokenData = await tokenResponse.json();
const accessToken = tokenData.access_token;

if (typeof accessToken !== 'string' || !accessToken) {
  throw new Error('Microsoft Graph token response did not contain an access token.');
}

if (!recipientAddress) {
  console.log('Microsoft Graph app-only token acquisition passed; delivery was not attempted.');
  process.exit(0);
}

const message = [
  `From: ${senderName} <${senderAddress}>`,
  `To: ${recipientAddress}`,
  'Subject: VASI synthetic transactional mail probe',
  `Date: ${new Date().toUTCString()}`,
  `Message-ID: <${crypto.randomUUID()}@vasi.invalid>`,
  'MIME-Version: 1.0',
  'Content-Type: text/plain; charset=utf-8',
  'Content-Transfer-Encoding: 7bit',
  '',
  'This synthetic message verifies VASI transactional mail delivery. It contains no document data.',
  '',
].join('\r\n');

const graphResponse = await fetch(
  `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(senderAddress)}/sendMail`,
  {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'text/plain',
    },
    body: Buffer.from(message).toString('base64'),
  },
);

if (graphResponse.status !== 202) {
  throw new Error(`Microsoft Graph mail submission failed with status ${graphResponse.status}.`);
}

console.log('Microsoft Graph synthetic delivery was accepted.');
