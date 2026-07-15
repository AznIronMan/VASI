import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  hasGraphEmailConfiguration,
  resetGraphTokenCacheForTests,
  sendGraphEmail,
} from "@/lib/graph-email";

const environment = {
  GRAPH_TENANT_ID: "tenant-id",
  GRAPH_CLIENT_ID: "client-id",
  GRAPH_CLIENT_SECRET: "client-secret",
  GRAPH_SENDER_EMAIL: "server@example.com",
};

describe("Microsoft Graph email", () => {
  beforeEach(() => {
    resetGraphTokenCacheForTests();
  });

  it("requires the complete app-only configuration", () => {
    expect(hasGraphEmailConfiguration(environment)).toBe(true);
    expect(
      hasGraphEmailConfiguration({
        ...environment,
        GRAPH_CLIENT_SECRET: "",
      }),
    ).toBe(false);
  });

  it("acquires an app token and sends through the configured mailbox", async () => {
    const request = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: "access-token", expires_in: 3600 }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      )
      .mockResolvedValueOnce(new Response(null, { status: 202 }));

    await sendGraphEmail(
      {
        to: "recipient@example.com",
        subject: "Verify your account",
        html: "<p>Verification message</p>",
      },
      environment,
      request,
    );

    expect(request).toHaveBeenCalledTimes(2);
    expect(request.mock.calls[0][0]).toBe(
      "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token",
    );
    expect(request.mock.calls[1][0]).toBe(
      "https://graph.microsoft.com/v1.0/users/server%40example.com/sendMail",
    );

    const sendOptions = request.mock.calls[1][1] as RequestInit;
    expect(sendOptions.headers).toEqual({
      Authorization: "Bearer access-token",
      "Content-Type": "application/json",
    });
    expect(JSON.parse(String(sendOptions.body))).toMatchObject({
      message: {
        subject: "Verify your account",
        toRecipients: [{ emailAddress: { address: "recipient@example.com" } }],
      },
    });
  });

  it("does not expose Graph error responses", async () => {
    const request = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response("sensitive provider response", { status: 401 }));

    await expect(
      sendGraphEmail(
        {
          to: "recipient@example.com",
          subject: "Verify your account",
          html: "<p>Verification message</p>",
        },
        environment,
        request,
      ),
    ).rejects.toThrow("Microsoft Graph token acquisition failed.");
  });

  it("distinguishes provider rejection from an indeterminate send transport", async () => {
    const rejected = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "access-token", expires_in: 3600 }), { status: 200 }),
      )
      .mockResolvedValueOnce(new Response("private rejection", { status: 403 }));
    await expect(sendGraphEmail({
      to: "recipient@example.com",
      subject: "Verify",
      html: "<p>Verify</p>",
    }, environment, rejected)).rejects.toMatchObject({
      outcome: "failed",
    });

    resetGraphTokenCacheForTests();
    const indeterminate = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "access-token", expires_in: 3600 }), { status: 200 }),
      )
      .mockRejectedValueOnce(new Error("network reset"));
    await expect(sendGraphEmail({
      to: "recipient@example.com",
      subject: "Verify",
      html: "<p>Verify</p>",
    }, environment, indeterminate)).rejects.toMatchObject({
      outcome: "unknown",
    });
  });
});
