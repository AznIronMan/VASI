import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  emailDomain,
  recommendProviderForEmail,
  resetProviderRecommendationCacheForTests,
} from "@/lib/provider-recommendation";

describe("provider recommendation", () => {
  beforeEach(() => resetProviderRecommendationCacheForTests());
  afterEach(() => vi.useRealTimers());

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
    expect(emailDomain(`${"a".repeat(65)}@example.test`)).toBeUndefined();
    expect(emailDomain("person name@example.test")).toBeUndefined();
    expect(emailDomain(`${"a".repeat(309)}@example.test`)).toBeUndefined();
  });

  it("coalesces concurrent requests for the same custom domain", async () => {
    let complete!: (records: Array<{ exchange: string; priority: number }>) => void;
    const resolver = vi.fn(() => new Promise<Array<{ exchange: string; priority: number }>>(
      (resolve) => { complete = resolve; },
    ));

    const first = recommendProviderForEmail("one@company.example", resolver);
    const second = recommendProviderForEmail("two@company.example", resolver);
    await vi.waitFor(() => expect(resolver).toHaveBeenCalledOnce());
    complete([{ exchange: "aspmx.l.google.com", priority: 1 }]);

    await expect(Promise.all([first, second])).resolves.toEqual(["google", "google"]);
    expect(resolver).toHaveBeenCalledOnce();
  });

  it("runs at most 16 MX lookups and releases queued work as slots finish", async () => {
    const completions: Array<(records: Array<{ exchange: string; priority: number }>) => void> = [];
    const resolver = vi.fn(() => new Promise<Array<{ exchange: string; priority: number }>>(
      (resolve) => completions.push(resolve),
    ));
    const requests = Array.from({ length: 17 }, (_, index) =>
      recommendProviderForEmail(`person@company${index}.example`, resolver));

    await vi.waitFor(() => expect(resolver).toHaveBeenCalledTimes(16));
    completions[0]([]);
    await vi.waitFor(() => expect(resolver).toHaveBeenCalledTimes(17));
    completions.slice(1).forEach((complete) => complete([]));

    await expect(Promise.all(requests)).resolves.toEqual(Array(17).fill(undefined));
  });

  it("rejects work beyond the 16 active and 64 queued bound without starting DNS", async () => {
    const held: Array<(records: Array<{ exchange: string; priority: number }>) => void> = [];
    const resolver = vi.fn(() => {
      if (held.length < 16) {
        return new Promise<Array<{ exchange: string; priority: number }>>(
          (resolve) => held.push(resolve),
        );
      }
      return Promise.resolve([]);
    });
    const requests = Array.from({ length: 81 }, (_, index) =>
      recommendProviderForEmail(`person@bounded${index}.example`, resolver));

    await vi.waitFor(() => expect(resolver).toHaveBeenCalledTimes(16));
    await expect(requests[80]).resolves.toBeUndefined();
    expect(resolver).toHaveBeenCalledTimes(16);
    held.forEach((complete) => complete([]));
    await expect(Promise.all(requests.slice(0, 80))).resolves.toEqual(Array(80).fill(undefined));
    expect(resolver).toHaveBeenCalledTimes(80);
  });

  it("cancels a timed-out lookup and does not cache transient failure", async () => {
    vi.useFakeTimers();
    const cancel = vi.fn();
    const resolver = vi.fn(() => ({
      cancel,
      promise: new Promise<Array<{ exchange: string; priority: number }>>(() => undefined),
    }));
    const first = recommendProviderForEmail("person@timeout.example", resolver);
    await vi.advanceTimersByTimeAsync(1_500);
    await expect(first).resolves.toBeUndefined();
    expect(cancel).toHaveBeenCalledOnce();

    const second = recommendProviderForEmail("person@timeout.example", async () => []);
    await expect(second).resolves.toBeUndefined();
  });

  it("caches authoritative DNS absence but not transient resolver errors", async () => {
    const absent = vi.fn().mockRejectedValue(Object.assign(new Error("not found"), {
      code: "ENOTFOUND",
    }));
    await recommendProviderForEmail("one@absent.example", absent);
    await recommendProviderForEmail("two@absent.example", absent);
    expect(absent).toHaveBeenCalledOnce();

    const transient = vi.fn().mockRejectedValue(Object.assign(new Error("temporary"), {
      code: "ESERVFAIL",
    }));
    await recommendProviderForEmail("one@transient.example", transient);
    await recommendProviderForEmail("two@transient.example", transient);
    expect(transient).toHaveBeenCalledTimes(2);
  });

  it("rejects excessive or malformed MX responses without caching them", async () => {
    const excessive = vi.fn().mockResolvedValue(Array.from({ length: 21 }, (_, index) => ({
      exchange: `mx${index}.example.test`,
      priority: index,
    })));
    await recommendProviderForEmail("one@excessive.example", excessive);
    await recommendProviderForEmail("two@excessive.example", excessive);
    expect(excessive).toHaveBeenCalledTimes(2);

    resetProviderRecommendationCacheForTests();
    const malformed = vi.fn().mockResolvedValue([
      { exchange: "127.0.0.1", priority: 0 },
    ]);
    await expect(recommendProviderForEmail("one@malformed.example", malformed))
      .resolves.toBeUndefined();
    expect(malformed).toHaveBeenCalledOnce();
  });

  it("accepts an RFC null MX as a cacheable no-provider result", async () => {
    const resolver = vi.fn().mockResolvedValue([{ exchange: ".", priority: 0 }]);
    await recommendProviderForEmail("one@nomail.example", resolver);
    await recommendProviderForEmail("two@nomail.example", resolver);
    expect(resolver).toHaveBeenCalledOnce();
  });
});
