import { createHash, createHmac } from "node:crypto";

import nodemailer from "nodemailer";

import { canonicalJSON } from "../../packages/engine-crypto/index.mjs";

const graphTokenCache = new Map();

export function createNotificationDispatcher(binding, dependencies = {}) {
  const adapterId = binding.adapterId;
  if (!["disabled", "microsoft_graph", "smtp", "webhook"].includes(adapterId)) {
    throw new Error("The notification adapter is unsupported.");
  }
  if (binding.status === "disabled" || adapterId === "disabled") {
    return async () => ({ adapter: "disabled", outcome: "suppressed", responseMetadata: {} });
  }
  if (adapterId === "webhook") {
    const url = httpsURL(binding.config.url, "webhook.url");
    const secret = required(binding.credentials, "secret");
    if (Buffer.byteLength(secret, "utf8") < 32) {
      throw new Error("The webhook signing secret must contain at least 32 bytes.");
    }
    const fetchImplementation = dependencies.fetch || fetch;
    return async (job) => {
      const timestamp = Math.floor(Date.now() / 1_000);
      const body = canonicalJSON({
        event: job.payload,
        id: job.id,
        idempotencyKey: job.idempotencyKey,
        schema: "vasi-notification-webhook/v1",
      });
      const signature = createHmac("sha256", secret)
        .update(`${timestamp}.${body}`)
        .digest("base64url");
      const response = await fetchImplementation(url, {
        body,
        headers: {
          "content-type": "application/json",
          "x-vasi-idempotency-key": job.idempotencyKey,
          "x-vasi-signature": `t=${timestamp},v1=${signature}`,
        },
        method: "POST",
        redirect: "manual",
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) throw deliveryError("webhook_status", `Webhook returned ${response.status}.`);
      return {
        adapter: "webhook",
        outcome: "delivered",
        responseMetadata: { status: response.status },
      };
    };
  }
  if (adapterId === "microsoft_graph") {
    const tenantId = required(binding.config, "tenantId");
    const clientId = required(binding.config, "clientId");
    const senderEmail = required(binding.config, "senderEmail");
    const clientSecret = required(binding.credentials, "clientSecret");
    const request = dependencies.fetch || fetch;
    const now = dependencies.now || Date.now;
    return async (job) => {
      const accessToken = await microsoftGraphAccessToken({
        clientId,
        clientSecret,
        request,
        tenantId,
        now,
      });
      const message = notificationMessage(job.payload, optionalHTTPSOrigin(dependencies.participantOrigin));
      const response = await request(
        `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(senderEmail)}/sendMail`,
        {
          body: JSON.stringify({
            message: {
              body: { content: message.html, contentType: "HTML" },
              internetMessageHeaders: [{ name: "x-vasi-idempotency-key", value: job.idempotencyKey }],
              subject: message.subject,
              toRecipients: [{ emailAddress: { address: job.payload.recipient } }],
            },
          }),
          headers: {
            authorization: `Bearer ${accessToken}`,
            "content-type": "application/json",
          },
          method: "POST",
          redirect: "manual",
          signal: AbortSignal.timeout(10_000),
        },
      );
      if (response.status !== 202) {
        await response.body?.cancel().catch(() => undefined);
        throw deliveryError("graph_send_status", "Microsoft Graph mail delivery failed.");
      }
      return {
        adapter: "microsoft_graph",
        outcome: "delivered",
        responseMetadata: { status: response.status },
      };
    };
  }

  const host = required(binding.config, "host");
  const from = required(binding.config, "from");
  const port = integer(binding.config.port, 1, 65_535);
  const secure = binding.config.secure;
  if (typeof secure !== "boolean") throw new Error("The SMTP secure setting must be boolean.");
  const origin = optionalHTTPSOrigin(dependencies.participantOrigin);
  const createTransport = dependencies.createTransport || nodemailer.createTransport;
  const transporter = createTransport({
    auth: binding.config.username
      ? {
          pass: required(binding.credentials, "password"),
          user: binding.config.username,
        }
      : undefined,
    host,
    port,
    requireTLS: !secure,
    secure,
  });
  return async (job) => {
    const message = notificationMessage(job.payload, origin);
    const result = await transporter.sendMail({
      from,
      html: message.html,
      subject: message.subject,
      text: message.text,
      to: job.payload.recipient,
    });
    return {
      adapter: "smtp",
      outcome: "delivered",
      responseMetadata: { messageId: String(result.messageId || "") },
    };
  };
}

export function notificationMessage(payload, origin) {
  const company = payload.tenant?.name || "A company";
  const title = payload.title || "VASI request";
  const link = payload.participantPath && origin
    ? new URL(payload.participantPath, origin).toString()
    : undefined;
  if (payload.eventType === "request.completed") {
    return {
      html: `<p>Your response to <strong>${escapeHTML(title)}</strong> was recorded.</p><p>Sign in to VASI to review the available receipt.</p>`,
      subject: `Response recorded: ${title}`,
      text: `Your response to ${title} was recorded. Sign in to VASI to review the available receipt.`,
    };
  }
  const action = payload.eventType === "request.reminder" ? "reminds you about" : "sent you";
  const linkText = link ? `\n\nOpen the secure request: ${link}` : "\n\nUse the original secure link to continue.";
  return {
    html: `<p>${escapeHTML(company)} ${action} <strong>${escapeHTML(title)}</strong>.</p>${
      link ? `<p><a href="${escapeHTML(link)}">Open the secure request</a></p>` : "<p>Use the original secure link to continue.</p>"
    }`,
    subject: `${payload.eventType === "request.reminder" ? "Reminder" : "Action requested"}: ${title}`,
    text: `${company} ${action} ${title}.${linkText}`,
  };
}

async function microsoftGraphAccessToken({ clientId, clientSecret, now, request, tenantId }) {
  const cacheKey = createHash("sha256")
    .update(tenantId)
    .update("\0")
    .update(clientId)
    .update("\0")
    .update(clientSecret)
    .digest("hex");
  const currentTime = now();
  const cached = graphTokenCache.get(cacheKey);
  if (cached?.expiresAt > currentTime) return cached.value;
  pruneGraphTokenCache(currentTime);

  const response = await request(
    `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`,
    {
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: "client_credentials",
        scope: "https://graph.microsoft.com/.default",
      }),
      headers: { "content-type": "application/x-www-form-urlencoded" },
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    },
  );
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw deliveryError("graph_token_status", "Microsoft Graph token acquisition failed.");
  }
  const body = await boundedJSON(response, 65_536).catch(() => undefined);
  const expiresIn = Number(body?.expires_in);
  if (
    typeof body?.access_token !== "string" || body.access_token.length < 1 ||
    body.access_token.length > 32_768 || /[\u0000-\u001f\u007f]/.test(body.access_token) ||
    !Number.isSafeInteger(expiresIn) || expiresIn <= 60 || expiresIn > 86_400
  ) {
    throw deliveryError("graph_token_response", "Microsoft Graph returned an invalid token response.");
  }
  const token = Object.freeze({
    expiresAt: currentTime + (expiresIn - 60) * 1_000,
    value: body.access_token,
  });
  graphTokenCache.set(cacheKey, token);
  return token.value;
}

async function boundedJSON(response, maximumBytes) {
  if (!response.body) return undefined;
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximumBytes) {
      await reader.cancel().catch(() => undefined);
      throw new Error("response_limit");
    }
    chunks.push(Buffer.from(value));
  }
  return JSON.parse(Buffer.concat(chunks, total).toString("utf8"));
}

function pruneGraphTokenCache(now) {
  for (const [key, token] of graphTokenCache) {
    if (token.expiresAt <= now) graphTokenCache.delete(key);
  }
  while (graphTokenCache.size >= 256) {
    graphTokenCache.delete(graphTokenCache.keys().next().value);
  }
}

export function resetNotificationTokenCacheForTests() {
  graphTokenCache.clear();
}

function required(settings, name) {
  const value = settings[name];
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name} is required.`);
  return value.trim();
}

function httpsURL(value, name) {
  const url = new URL(required({ [name]: value }, name));
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new Error(`${name} must be an HTTPS URL without credentials.`);
  }
  return url;
}

function optionalHTTPSOrigin(value) {
  if (!value) return undefined;
  const url = new URL(value);
  if (url.protocol !== "https:" || url.pathname !== "/" || url.search || url.hash) {
    throw new Error("ENGINE_PARTICIPANT_ORIGIN must be an HTTPS origin.");
  }
  return url;
}

function integer(value, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error("The SMTP port is invalid.");
  }
  return parsed;
}

function deliveryError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
