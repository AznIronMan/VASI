import { createTransport } from 'nodemailer';
import { describe, expect, it, vi } from 'vitest';

import { makeMicrosoftGraphTransport } from './microsoft-graph';

const tokenResponse = () =>
  new Response(JSON.stringify({ access_token: 'test-access-token', expires_in: 3600 }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });

describe('Microsoft Graph mail transport', () => {
  it('uses app-only OAuth and submits the Nodemailer MIME message', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(tokenResponse())
      .mockResolvedValueOnce(new Response(null, { status: 202 }));

    const transporter = createTransport(
      makeMicrosoftGraphTransport({
        tenantId: 'tenant-id',
        clientId: 'client-id',
        clientSecret: 'client-secret',
        senderAddress: 'sender@example.com',
        fetchImpl,
      }),
    );

    await transporter.sendMail({
      from: 'VASI <sender@example.com>',
      to: 'recipient@example.net',
      subject: 'Synthetic invitation',
      text: 'Synthetic message body.',
      attachments: [{ filename: 'evidence.txt', content: 'synthetic attachment' }],
    });

    expect(fetchImpl).toHaveBeenCalledTimes(2);

    const [tokenUrl, tokenOptions] = fetchImpl.mock.calls[0];
    const [graphUrl, graphOptions] = fetchImpl.mock.calls[1];

    expect(tokenUrl).toBe('https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token');
    expect(tokenOptions?.method).toBe('POST');
    expect(String(tokenOptions?.body)).toContain('grant_type=client_credentials');
    expect(String(tokenOptions?.body)).toContain('scope=https%3A%2F%2Fgraph.microsoft.com%2F.default');

    expect(graphUrl).toBe('https://graph.microsoft.com/v1.0/users/sender%40example.com/sendMail');
    expect(graphOptions?.headers).toMatchObject({
      Authorization: 'Bearer test-access-token',
      'Content-Type': 'text/plain',
    });

    const mimeMessage = Buffer.from(String(graphOptions?.body), 'base64').toString('utf8');

    expect(mimeMessage).toContain('Subject: Synthetic invitation');
    expect(mimeMessage).toContain('sender@example.com');
    expect(mimeMessage).toContain('recipient@example.net');
    expect(mimeMessage).toContain('filename=evidence.txt');
  });

  it('caches access tokens between messages', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(tokenResponse())
      .mockResolvedValue(new Response(null, { status: 202 }));

    const transporter = createTransport(
      makeMicrosoftGraphTransport({
        tenantId: 'tenant-id',
        clientId: 'client-id',
        clientSecret: 'client-secret',
        senderAddress: 'sender@example.com',
        fetchImpl,
        now: () => 1_000,
      }),
    );

    await transporter.sendMail({ from: 'sender@example.com', to: 'one@example.net', subject: 'One', text: 'One' });
    await transporter.sendMail({ from: 'sender@example.com', to: 'two@example.net', subject: 'Two', text: 'Two' });

    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(fetchImpl.mock.calls.filter(([url]) => String(url).includes('/oauth2/v2.0/token'))).toHaveLength(1);
  });

  it('does not include provider response bodies or credentials in errors', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(tokenResponse())
      .mockResolvedValueOnce(new Response('recipient@example.net client-secret', { status: 403 }));

    const transporter = createTransport(
      makeMicrosoftGraphTransport({
        tenantId: 'tenant-id',
        clientId: 'client-id',
        clientSecret: 'client-secret',
        senderAddress: 'sender@example.com',
        fetchImpl,
      }),
    );

    const submission = transporter.sendMail({
      from: 'sender@example.com',
      to: 'recipient@example.net',
      subject: 'Synthetic message',
      text: 'Synthetic body',
    });

    const error = await submission.catch((caught: unknown) => caught);

    expect(String(error)).toContain('Microsoft Graph mail submission failed with status 403.');
    expect(String(error)).not.toContain('recipient@example.net');
    expect(String(error)).not.toContain('client-secret');
  });

  it('rejects a message whose sender differs from the authorized mailbox', async () => {
    const fetchImpl = vi.fn<typeof fetch>();

    const transporter = createTransport(
      makeMicrosoftGraphTransport({
        tenantId: 'tenant-id',
        clientId: 'client-id',
        clientSecret: 'client-secret',
        senderAddress: 'sender@example.com',
        fetchImpl,
      }),
    );

    await expect(
      transporter.sendMail({
        from: 'other@example.com',
        to: 'recipient@example.net',
        subject: 'Disallowed sender',
        text: 'Synthetic body.',
      }),
    ).rejects.toThrow('Microsoft Graph message sender does not match the authorized mailbox.');

    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('rejects an oversized MIME message before requesting a token', async () => {
    const fetchImpl = vi.fn<typeof fetch>();

    const transporter = createTransport(
      makeMicrosoftGraphTransport({
        tenantId: 'tenant-id',
        clientId: 'client-id',
        clientSecret: 'client-secret',
        senderAddress: 'sender@example.com',
        maxMessageBytes: 128,
        fetchImpl,
      }),
    );

    await expect(
      transporter.sendMail({
        from: 'sender@example.com',
        to: 'recipient@example.net',
        subject: 'Oversized message',
        text: 'x'.repeat(256),
      }),
    ).rejects.toThrow('Microsoft Graph message exceeds the configured size limit.');

    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
