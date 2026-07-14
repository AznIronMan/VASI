import { createHmac } from "node:crypto";

import nodemailer from "nodemailer";

import { canonicalJSON } from "../../packages/engine-crypto/index.mjs";

export function createNotificationDispatcher(settings, dependencies = {}) {
  const mode = settings.ENGINE_NOTIFICATION_MODE || "disabled";
  if (!["disabled", "smtp", "webhook"].includes(mode)) {
    throw new Error("ENGINE_NOTIFICATION_MODE must be disabled, smtp, or webhook.");
  }
  if (mode === "disabled") {
    return async () => ({ adapter: "disabled", outcome: "suppressed", responseMetadata: {} });
  }
  if (mode === "webhook") {
    const url = httpsURL(settings.ENGINE_NOTIFICATION_WEBHOOK_URL, "ENGINE_NOTIFICATION_WEBHOOK_URL");
    const secret = required(settings, "ENGINE_NOTIFICATION_WEBHOOK_SECRET");
    if (Buffer.byteLength(secret, "utf8") < 32) {
      throw new Error("ENGINE_NOTIFICATION_WEBHOOK_SECRET must contain at least 32 bytes.");
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

  const host = required(settings, "ENGINE_NOTIFICATION_SMTP_HOST");
  const from = required(settings, "ENGINE_NOTIFICATION_SMTP_FROM");
  const port = integer(settings.ENGINE_NOTIFICATION_SMTP_PORT || "587", 1, 65_535);
  const secure = boolean(settings.ENGINE_NOTIFICATION_SMTP_SECURE || "false");
  const origin = optionalHTTPSOrigin(settings.ENGINE_PARTICIPANT_ORIGIN);
  const createTransport = dependencies.createTransport || nodemailer.createTransport;
  const transporter = createTransport({
    auth: settings.ENGINE_NOTIFICATION_SMTP_USER
      ? {
          pass: required(settings, "ENGINE_NOTIFICATION_SMTP_PASSWORD"),
          user: settings.ENGINE_NOTIFICATION_SMTP_USER,
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

function boolean(value) {
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error("The SMTP secure setting must be true or false.");
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
