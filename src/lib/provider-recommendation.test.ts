import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  emailDomain,
  recommendProviderForEmail,
  resetProviderRecommendationCacheForTests,
} from "@/lib/provider-recommendation";

describe("provider recommendation", () => {
  beforeEach(() => resetProviderRecommendationCacheForTests());

  it("recognizes common consumer identity domains without DNS", async () => {
    const resolver = vi.fn();

    await expect(recommendProviderForEmail("person@outlook.com", resolver)).resolves.toBe(
      "microsoft",
    );
    await expect(recommendProviderForEmail("person@gmail.com", resolver)).resolves.toBe(
      "google",
    );
    await expect(recommendProviderForEmail("person@me.com", resolver)).resolves.toBe("apple");
    await expect(recommendProviderForEmail("person@yahoo.co.uk", resolver)).resolves.toBe(
      "yahoo",
    );
    await expect(recommendProviderForEmail("person@zohomail.com", resolver)).resolves.toBe(
      "zoho",
    );
    expect(resolver).not.toHaveBeenCalled();
  });

  it("detects Microsoft 365, Google Workspace, and Zoho Mail MX records", async () => {
    await expect(
      recommendProviderForEmail("person@company.example", async () => [
        { exchange: "company-example.mail.protection.outlook.com", priority: 0 },
      ]),
    ).resolves.toBe("microsoft");

    resetProviderRecommendationCacheForTests();
    await expect(
      recommendProviderForEmail("person@company.example", async () => [
        { exchange: "aspmx.l.google.com", priority: 1 },
      ]),
    ).resolves.toBe("google");

    resetProviderRecommendationCacheForTests();
    await expect(
      recommendProviderForEmail("person@company.example", async () => [
        { exchange: "mx.zoho.com", priority: 10 },
        { exchange: "mx2.zoho.com", priority: 20 },
      ]),
    ).resolves.toBe("zoho");
  });

  it("rejects malformed or network-address domains", () => {
    expect(emailDomain("not-an-email")).toBeUndefined();
    expect(emailDomain("person@127.0.0.1")).toBeUndefined();
    expect(emailDomain("person@localhost")).toBeUndefined();
  });
});
