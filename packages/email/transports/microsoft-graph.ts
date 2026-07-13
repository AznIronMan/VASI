import type { SentMessageInfo, Transport } from 'nodemailer';
import type MailMessage from 'nodemailer/lib/mailer/mail-message';

const VERSION = '1.0.0';
const GRAPH_SCOPE = 'https://graph.microsoft.com/.default';
// Microsoft Graph write requests are limited to 4 MB. Base64 expands the MIME
// message by roughly one third, so cap the raw message at 3,000,000 bytes.
const DEFAULT_MAX_MESSAGE_BYTES = 3_000_000;
const TOKEN_EXPIRY_BUFFER_MS = 60_000;

type MicrosoftGraphTransportOptions = {
  tenantId?: string;
  clientId?: string;
  clientSecret?: string;
  senderAddress?: string;
  maxMessageBytes?: number;
  fetchImpl?: typeof fetch;
  now?: () => number;
};

type CachedAccessToken = {
  value: string;
  expiresAt: number;
};

type TokenResponse = {
  access_token?: unknown;
  expires_in?: unknown;
};

const requireOption = (value: string | undefined, name: string): string => {
  if (!value) {
    throw new Error(`Microsoft Graph transport requires ${name}.`);
  }

  return value;
};

const readMessage = async (mail: MailMessage, maxMessageBytes: number): Promise<Buffer> => {
  mail.message.keepBcc = true;

  const chunks: Buffer[] = [];
  let totalBytes = 0;

  for await (const chunk of mail.message.createReadStream()) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);

    totalBytes += buffer.length;

    if (totalBytes > maxMessageBytes) {
      throw new Error('Microsoft Graph message exceeds the configured size limit.');
    }

    chunks.push(buffer);
  }

  return Buffer.concat(chunks, totalBytes);
};

export const makeMicrosoftGraphTransport = (options: MicrosoftGraphTransportOptions): Transport<SentMessageInfo> => {
  const tenantId = requireOption(options.tenantId, 'a tenant ID');
  const clientId = requireOption(options.clientId, 'a client ID');
  const clientSecret = requireOption(options.clientSecret, 'a client credential');
  const senderAddress = requireOption(options.senderAddress, 'a sender address');
  const maxMessageBytes = options.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES;
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? Date.now;

  let cachedAccessToken: CachedAccessToken | null = null;
  let pendingAccessToken: Promise<CachedAccessToken> | null = null;

  const requestAccessToken = async (): Promise<CachedAccessToken> => {
    const response = await fetchImpl(
      `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          grant_type: 'client_credentials',
          scope: GRAPH_SCOPE,
        }),
      },
    );

    if (!response.ok) {
      throw new Error(`Microsoft Graph token request failed with status ${response.status}.`);
    }

    const data = (await response.json()) as TokenResponse;

    if (typeof data.access_token !== 'string' || !data.access_token) {
      throw new Error('Microsoft Graph token response did not contain an access token.');
    }

    const expiresIn = typeof data.expires_in === 'number' ? data.expires_in : 3600;

    return {
      value: data.access_token,
      expiresAt: now() + expiresIn * 1000,
    };
  };

  const getAccessToken = async (forceRefresh = false): Promise<string> => {
    if (forceRefresh) {
      cachedAccessToken = null;
    }

    if (cachedAccessToken && cachedAccessToken.expiresAt - TOKEN_EXPIRY_BUFFER_MS > now()) {
      return cachedAccessToken.value;
    }

    pendingAccessToken ??= requestAccessToken();

    try {
      cachedAccessToken = await pendingAccessToken;
      return cachedAccessToken.value;
    } finally {
      pendingAccessToken = null;
    }
  };

  const submitMessage = async (encodedMessage: string, forceRefresh = false): Promise<Response> => {
    const accessToken = await getAccessToken(forceRefresh);

    return fetchImpl(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(senderAddress)}/sendMail`, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'text/plain',
      },
      body: encodedMessage,
    });
  };

  const send = (mail: MailMessage, callback: (error: Error | null, info: SentMessageInfo) => void): void => {
    void (async () => {
      const messageEnvelope = mail.message.getEnvelope();
      const envelope = mail.data.envelope ?? messageEnvelope;

      if (
        typeof messageEnvelope.from !== 'string' ||
        messageEnvelope.from.toLowerCase() !== senderAddress.toLowerCase() ||
        (envelope.from && envelope.from.toLowerCase() !== senderAddress.toLowerCase())
      ) {
        throw new Error('Microsoft Graph message sender does not match the authorized mailbox.');
      }

      const messageId = mail.message.messageId();
      const message = await readMessage(mail, maxMessageBytes);
      const encodedMessage = message.toString('base64');

      let response = await submitMessage(encodedMessage);

      if (response.status === 401) {
        response = await submitMessage(encodedMessage, true);
      }

      if (response.status !== 202) {
        throw new Error(`Microsoft Graph mail submission failed with status ${response.status}.`);
      }

      callback(null, {
        accepted: envelope.to,
        rejected: [],
        pending: [],
        envelope,
        messageId,
      });
    })().catch((error: unknown) => {
      callback(error instanceof Error ? error : new Error('Microsoft Graph mail submission failed.'), null);
    });
  };

  function verify(): Promise<true>;
  function verify(callback: (error: Error | null, success: true) => void): void;
  function verify(callback?: (error: Error | null, success: true) => void): Promise<true> | undefined {
    const verification = getAccessToken()
      .then(() => true as const)
      .catch((error: unknown) => {
        throw error instanceof Error ? error : new Error('Microsoft Graph token verification failed.');
      });

    if (!callback) {
      return verification;
    }

    void verification
      .then((success) => callback(null, success))
      .catch((error: unknown) => {
        callback(
          error instanceof Error ? error : new Error('Microsoft Graph token verification failed.'),
          undefined as never,
        );
      });
  }

  return {
    name: 'MicrosoftGraphTransport',
    version: VERSION,
    send,
    verify,
  };
};
