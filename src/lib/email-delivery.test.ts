import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  createTransport: vi.fn(),
  getRuntimeSettings: vi.fn(),
  resolveProductBrand: vi.fn(),
  sendGraphEmail: vi.fn(),
  sendMail: vi.fn(),
}));

vi.mock("nodemailer", () => ({
  default: { createTransport: mocks.createTransport },
}));
vi.mock("@/lib/runtime-settings", () => ({ getRuntimeSettings: mocks.getRuntimeSettings }));
vi.mock("@/lib/branding", () => ({ resolveProductBrand: mocks.resolveProductBrand }));
vi.mock("@/lib/graph-email", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/graph-email")>();
  return { ...actual, sendGraphEmail: mocks.sendGraphEmail };
});

import { sendAuthEmail } from "@/lib/email";
import type { AuthEmailDeliveryError } from "@/lib/email";
import { GraphEmailDeliveryError } from "@/lib/graph-email";

const message = {
  actionLabel: "Continue",
  actionUrl: "https://vsign.example.test/invite",
  heading: "Invitation",
  message: "Use your trusted identity provider.",
  subject: "V·Sign invitation",
  to: "owner@example.com",
};

describe("transactional email delivery certainty", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.resolveProductBrand.mockReturnValue({
      organizationName: "Example",
      productMark: "V·Sign",
    });
    mocks.createTransport.mockReturnValue({ sendMail: mocks.sendMail });
  });

  it("preserves an indeterminate Graph send outcome", async () => {
    mocks.getRuntimeSettings.mockResolvedValue(graphSettings());
    mocks.sendGraphEmail.mockRejectedValue(
      new GraphEmailDeliveryError("Graph outcome unknown.", "unknown"),
    );

    await expect(sendAuthEmail(message)).rejects.toMatchObject({
      outcome: "unknown",
    } satisfies Partial<AuthEmailDeliveryError>);
  });

  it("classifies a pre-delivery Graph failure as failed", async () => {
    mocks.getRuntimeSettings.mockResolvedValue(graphSettings());
    mocks.sendGraphEmail.mockRejectedValue(new Error("token acquisition failed"));

    await expect(sendAuthEmail(message)).rejects.toMatchObject({
      outcome: "failed",
    } satisfies Partial<AuthEmailDeliveryError>);
  });

  it("treats an SMTP transport error as indeterminate", async () => {
    mocks.getRuntimeSettings.mockResolvedValue({
      AUTH_EMAIL_FROM: "auth@example.com",
      AUTH_EMAIL_PROVIDER: "smtp",
      SMTP_HOST: "smtp.example.com",
    });
    mocks.sendMail.mockRejectedValue(new Error("connection reset"));

    await expect(sendAuthEmail(message)).rejects.toMatchObject({
      outcome: "unknown",
    } satisfies Partial<AuthEmailDeliveryError>);
  });
});

function graphSettings() {
  return {
    AUTH_EMAIL_PROVIDER: "graph",
    GRAPH_CLIENT_ID: "client-id",
    GRAPH_CLIENT_SECRET: "client-secret",
    GRAPH_SENDER_EMAIL: "server@example.com",
    GRAPH_TENANT_ID: "tenant-id",
  };
}
