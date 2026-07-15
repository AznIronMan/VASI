import { createHmac } from "node:crypto";

import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  createNotificationDispatcher,
  notificationMessage,
  resetNotificationTokenCacheForTests,
} from "./notification-adapters.mjs";

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
  beforeEach(() => resetNotificationTokenCacheForTests());

  it("suppresses deterministically when delivery is disabled", async () => {
    const dispatch = createNotificationDispatcher({ adapterId: "disabled", config: {}, credentials: {}, status: "disabled" });
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
      expect(options.redirect).toBe("manual");
      return { ok: true, status: 202 };
    });
    const dispatch = createNotificationDispatcher({
      adapterId: "webhook",
      config: { url: "https://events.example.test/vasi" },
      credentials: { secret: "s".repeat(48) },
      status: "active",
    }, { fetch: fetchMock });
    await expect(dispatch(job)).resolves.toMatchObject({ adapter: "webhook", outcome: "delivered" });
  });

  it("uses a cached app-only token for mailbox-scoped Microsoft Graph delivery", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: "bounded-access-token",
        expires_in: 3600,
      }), { status: 200, headers: { "content-type": "application/json" } }))
      .mockResolvedValueOnce(new Response(null, { status: 202 }))
      .mockResolvedValueOnce(new Response(null, { status: 202 }));
    const dispatch = createNotificationDispatcher({
      adapterId: "microsoft_graph",
      config: {
        clientId: "22222222-2222-4222-8222-222222222222",
        senderEmail: "sender@example.test",
        tenantId: "11111111-1111-4111-8111-111111111111",
      },
      credentials: { clientSecret: "write-only-client-secret" },
      status: "active",
    }, {
      fetch: fetchMock,
      now: () => 1_700_000_000_000,
      participantOrigin: "https://vsign.example.test",
    });

    await expect(dispatch(job)).resolves.toMatchObject({
      adapter: "microsoft_graph",
      outcome: "delivered",
      responseMetadata: { status: 202 },
    });
    await expect(dispatch(job)).resolves.toMatchObject({ outcome: "delivered" });

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[0][0]).toBe(
      "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/oauth2/v2.0/token",
    );
    expect(String(fetchMock.mock.calls[0][1].body)).toContain("client_secret=write-only-client-secret");
    expect(String(fetchMock.mock.calls[0][0])).not.toContain("write-only-client-secret");
    expect(fetchMock.mock.calls[1][0]).toBe(
      "https://graph.microsoft.com/v1.0/users/sender%40example.test/sendMail",
    );
    const send = fetchMock.mock.calls[1][1];
    expect(send.headers.authorization).toBe("Bearer bounded-access-token");
    expect(send.redirect).toBe("manual");
    expect(JSON.parse(String(send.body))).toMatchObject({
      message: {
        internetMessageHeaders: [{ name: "x-vasi-idempotency-key", value: job.idempotencyKey }],
        subject: "Action requested: Safety terms",
        toRecipients: [{ emailAddress: { address: "person@example.test" } }],
      },
    });
  });

  it("redacts Microsoft Graph token and delivery response bodies", async () => {
    const dispatch = createNotificationDispatcher({
      adapterId: "microsoft_graph",
      config: {
        clientId: "22222222-2222-4222-8222-222222222222",
        senderEmail: "sender@example.test",
        tenantId: "11111111-1111-4111-8111-111111111111",
      },
      credentials: { clientSecret: "write-only-client-secret" },
      status: "active",
    }, {
      fetch: vi.fn().mockResolvedValue(new Response("provider-secret-diagnostic", { status: 401 })),
    });
    const error = await dispatch(job).catch((caught) => caught);
    expect(error).toMatchObject({ code: "graph_token_status" });
    expect(error.message).toBe("Microsoft Graph token acquisition failed.");
    expect(JSON.stringify(error)).not.toContain("provider-secret-diagnostic");

    resetNotificationTokenCacheForTests();
    const sendFailure = createNotificationDispatcher({
      adapterId: "microsoft_graph",
      config: {
        clientId: "22222222-2222-4222-8222-222222222222",
        senderEmail: "sender@example.test",
        tenantId: "11111111-1111-4111-8111-111111111111",
      },
      credentials: { clientSecret: "write-only-client-secret" },
      status: "active",
    }, {
      fetch: vi.fn()
        .mockResolvedValueOnce(new Response(JSON.stringify({ access_token: "token", expires_in: 3600 }), { status: 200 }))
        .mockResolvedValueOnce(new Response("provider-send-diagnostic", { status: 500 })),
    });
    const sendError = await sendFailure(job).catch((caught) => caught);
    expect(sendError).toMatchObject({ code: "graph_send_status" });
    expect(sendError.message).toBe("Microsoft Graph mail delivery failed.");
    expect(JSON.stringify(sendError)).not.toContain("provider-send-diagnostic");
  });

  it("escapes company content and includes only a VASI-owned link", () => {
    const message = notificationMessage({
      ...job.payload,
      tenant: { name: "<Example>" },
    }, new URL("https://vsign.example.test"));
    expect(message.html).toContain("&lt;Example&gt;");
    expect(message.html).toContain("https://vsign.example.test/r/opaque");
  });

  it.each([
    ["participant_data.ready", "protected VASI data export is ready"],
    ["participant_data.denied", "review completed"],
    ["participant_data.preparation_failed", "needs attention"],
    ["participant_data.expired", "data export expired"],
  ])("renders truthful, workspace-only participant status mail for %s", (eventType, subjectText) => {
    const message = notificationMessage({
      eventType,
      expiresAt: "2030-01-02T03:04:05.000Z",
      participantPath: "/workspace",
      recipient: "person@example.test",
      requestStatus: eventType.split(".").at(-1),
      schema: "vasi-participant-data-notification/v1",
      tenant: { id: "tenant-1", name: "<Example>" },
    }, new URL("https://vsign.example.test"));
    expect(message.subject.toLowerCase()).toContain(subjectText.toLowerCase());
    expect(message.html).toContain("&lt;Example&gt;");
    expect(message.html).toContain("https://vsign.example.test/workspace");
    expect(message.text).not.toContain("delivered");
  });
});
