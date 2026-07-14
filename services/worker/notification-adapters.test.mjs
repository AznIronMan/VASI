import { createHmac } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import { createNotificationDispatcher, notificationMessage } from "./notification-adapters.mjs";

const job = {
  id: "job-1",
  idempotencyKey: "request-1:issued",
  payload: {
    eventType: "request.issued",
    participantPath: "/r/opaque",
    recipient: "person@example.test",
    tenant: { name: "Example Company" },
    title: "Safety terms",
  },
};

describe("notification adapters", () => {
  it("suppresses deterministically when delivery is disabled", async () => {
    const dispatch = createNotificationDispatcher({ ENGINE_NOTIFICATION_MODE: "disabled" });
    await expect(dispatch(job)).resolves.toMatchObject({ adapter: "disabled", outcome: "suppressed" });
  });

  it("signs a canonical webhook with an idempotency key", async () => {
    const fetchMock = vi.fn(async (_url, options) => {
      const signature = options.headers["x-vasi-signature"];
      const timestamp = signature.match(/^t=(\d+),v1=(.+)$/)[1];
      const expected = createHmac("sha256", "s".repeat(48))
        .update(`${timestamp}.${options.body}`)
        .digest("base64url");
      expect(signature).toBe(`t=${timestamp},v1=${expected}`);
      expect(options.headers["x-vasi-idempotency-key"]).toBe(job.idempotencyKey);
      return { ok: true, status: 202 };
    });
    const dispatch = createNotificationDispatcher({
      ENGINE_NOTIFICATION_MODE: "webhook",
      ENGINE_NOTIFICATION_WEBHOOK_SECRET: "s".repeat(48),
      ENGINE_NOTIFICATION_WEBHOOK_URL: "https://events.example.test/vasi",
    }, { fetch: fetchMock });
    await expect(dispatch(job)).resolves.toMatchObject({ adapter: "webhook", outcome: "delivered" });
  });

  it("escapes company content and includes only a VASI-owned link", () => {
    const message = notificationMessage({
      ...job.payload,
      tenant: { name: "<Example>" },
    }, new URL("https://vsign.example.test"));
    expect(message.html).toContain("&lt;Example&gt;");
    expect(message.html).toContain("https://vsign.example.test/r/opaque");
  });
});
