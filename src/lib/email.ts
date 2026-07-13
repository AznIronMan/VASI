import nodemailer from "nodemailer";

type AuthEmail = {
  to: string;
  subject: string;
  heading: string;
  message: string;
  actionLabel: string;
  actionUrl: string;
};

type EmailEnvironment = Record<string, string | undefined>;

export function hasEmailConfiguration(environment: EmailEnvironment = process.env) {
  return ["SMTP_HOST", "AUTH_EMAIL_FROM"].every((key) =>
    Boolean(environment[key]?.trim()),
  );
}

function escapeHtml(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

export async function sendAuthEmail(email: AuthEmail) {
  if (!hasEmailConfiguration()) {
    if (process.env.NODE_ENV !== "production") {
      console.info(`[VASI auth email] ${email.subject}: ${email.actionUrl}`);
      return;
    }

    throw new Error("Transactional email is not configured.");
  }

  const port = Number(process.env.SMTP_PORT ?? "587");
  const secure = process.env.SMTP_SECURE === "true";
  const hasUser = Boolean(process.env.SMTP_USER);
  const hasPassword = Boolean(process.env.SMTP_PASSWORD);
  if (hasUser !== hasPassword) {
    throw new Error("SMTP_USER and SMTP_PASSWORD must be configured together.");
  }

  const hasCredentials = hasUser && hasPassword;
  const transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure,
    requireTLS: !secure && process.env.SMTP_REQUIRE_TLS !== "false",
    auth: hasCredentials
      ? {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASSWORD,
        }
      : undefined,
  });

  const heading = escapeHtml(email.heading);
  const message = escapeHtml(email.message);
  const actionLabel = escapeHtml(email.actionLabel);
  const actionUrl = escapeHtml(email.actionUrl);

  await transport.sendMail({
    from: process.env.AUTH_EMAIL_FROM,
    to: email.to,
    subject: email.subject,
    text: `${email.heading}\n\n${email.message}\n\n${email.actionLabel}: ${email.actionUrl}`,
    html: `
      <div style="background:#f5f3ed;padding:40px 16px;font-family:Arial,sans-serif;color:#17231f">
        <div style="max-width:560px;margin:0 auto;background:#ffffff;border:1px solid #dedbd2;border-radius:20px;padding:36px">
          <p style="margin:0 0 28px;font-size:13px;font-weight:700;letter-spacing:.16em;color:#2e5b4e">CNB / V·SIGN</p>
          <h1 style="margin:0 0 16px;font-size:26px;line-height:1.2">${heading}</h1>
          <p style="margin:0 0 28px;font-size:16px;line-height:1.6;color:#52605b">${message}</p>
          <a href="${actionUrl}" style="display:inline-block;border-radius:10px;background:#183e34;color:#ffffff;text-decoration:none;padding:14px 22px;font-weight:700">${actionLabel}</a>
          <p style="margin:28px 0 0;font-size:12px;line-height:1.5;color:#78827e">If you did not request this message, you can safely ignore it.</p>
        </div>
      </div>`,
  });
}
