"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import type { OpenParticipantAssignment } from "@/lib/evidence-types";

type ContextPurpose = "presentation" | "save" | "submission";
type StorageState = "available" | "blocked" | "unavailable";
type ContextSnapshot = {
  browser: {
    language?: string;
    languages?: string[];
    online: boolean;
    timeZone?: string;
  };
  capabilities: {
    cookiesEnabled: boolean;
    localStorage: StorageState;
    pdfViewerEnabled?: boolean;
    sessionStorage: StorageState;
  };
  clientOccurredAt: string;
  connection?: {
    downlinkMbps?: number;
    effectiveType?: "slow-2g" | "2g" | "3g" | "4g";
    rttMs?: number;
    saveData?: boolean;
  };
  display: {
    availableHeight?: number;
    availableWidth?: number;
    colorDepth?: number;
    devicePixelRatio?: number;
    pixelDepth?: number;
    screenHeight?: number;
    screenWidth?: number;
    viewportHeight?: number;
    viewportWidth?: number;
  };
  id: string;
  input: { maxTouchPoints?: number };
  monotonicMs: number;
  preferences: {
    colorScheme: "dark" | "light" | "no-preference";
    contrast: "custom" | "less" | "more" | "no-preference";
    forcedColors: boolean;
    reducedMotion: boolean;
  };
  purpose: ContextPurpose;
  schema: "vasi-participant-context/v1";
  sequence: number;
};
type PendingSnapshot = { contextSessionId: string; snapshot: ContextSnapshot };

export type ParticipantContextRecorder = {
  error?: string;
  recordResponse: (purpose: "save" | "submission") => Promise<void>;
};

export function useParticipantContextRecorder(
  assignment: OpenParticipantAssignment,
  handle: string,
): ParticipantContextRecorder {
  const [error, setError] = useState<string>();
  const activityId = assignment.activityId || "";
  const interactionId = assignment.interaction.id;
  const contextSessionId = useRef("");
  const startedAt = useRef(0);
  const sequence = useRef(0);
  const queue = useRef<PendingSnapshot[]>([]);
  const activeFlush = useRef<Promise<void> | undefined>(undefined);
  const flushRef = useRef<(keepalive?: boolean) => Promise<void>>(async () => undefined);

  const flush = useCallback(async (keepalive = false) => {
    if (!activityId) return;
    if (activeFlush.current) {
      await activeFlush.current;
      if (!keepalive && queue.current.length) await flushRef.current(false);
      return;
    }
    const operation = (async () => {
      while (queue.current.length) {
        const pending = queue.current[0];
        const response = await fetch("/api/evidence/context-snapshots", {
          body: JSON.stringify({
            activityId,
            contextSessionId: pending.contextSessionId,
            handle,
            interactionId,
            snapshot: pending.snapshot,
          }),
          headers: { "content-type": "application/json" },
          keepalive,
          method: "POST",
          signal: keepalive ? undefined : AbortSignal.timeout(4_000),
        });
        const result = await response.json().catch(() => ({})) as { error?: string };
        if (!response.ok) {
          setError(result.error || "Browser-context evidence could not be synchronized; VASI will retry when possible.");
          return;
        }
        queue.current.shift();
        setError(undefined);
        if (keepalive) return;
      }
    })().catch(() => {
      setError("Browser-context evidence could not be synchronized; your response can still be submitted.");
    });
    activeFlush.current = operation;
    try {
      await operation;
    } finally {
      if (activeFlush.current === operation) activeFlush.current = undefined;
    }
  }, [activityId, handle, interactionId]);

  useEffect(() => { flushRef.current = flush; }, [flush]);

  const record = useCallback(async (purpose: ContextPurpose) => {
    if (!activityId) return;
    const newSession = !contextSessionId.current;
    if (!contextSessionId.current) {
      contextSessionId.current = crypto.randomUUID();
      startedAt.current = performance.now();
      sequence.current = 0;
    }
    if (purpose === "presentation" && sequence.current > 0) {
      await flushRef.current(false);
      return;
    }
    if (newSession && purpose !== "presentation") {
      queue.current.push({
        contextSessionId: contextSessionId.current,
        snapshot: captureSnapshot("presentation", ++sequence.current, 0),
      });
    }
    const snapshot = captureSnapshot(
      purpose,
      ++sequence.current,
      Math.min(604_800_000, Math.max(0, Math.round(performance.now() - startedAt.current))),
    );
    queue.current.push({ contextSessionId: contextSessionId.current, snapshot });
    await flushRef.current(false);
  }, [activityId]);

  useEffect(() => {
    if (!activityId) return;
    void record("presentation");
    const onPageHide = () => { void flushRef.current(true); };
    window.addEventListener("pagehide", onPageHide);
    return () => window.removeEventListener("pagehide", onPageHide);
  }, [activityId, record]);

  return {
    error,
    recordResponse: (purpose) => record(purpose),
  };
}

function captureSnapshot(
  purpose: ContextPurpose,
  sequence: number,
  monotonicMs: number,
): ContextSnapshot {
  const navigatorWithContext = navigator as Navigator & {
    connection?: {
      downlink?: number;
      effectiveType?: string;
      rtt?: number;
      saveData?: boolean;
    };
    pdfViewerEnabled?: boolean;
  };
  const connection = navigatorWithContext.connection;
  const languages = Array.from(new Set((navigator.languages || [])
    .map((value) => boundedText(value, 35))))
    .filter((value): value is string => Boolean(value))
    .slice(0, 8);
  const effectiveType = ["slow-2g", "2g", "3g", "4g"].includes(connection?.effectiveType || "")
    ? connection?.effectiveType as "slow-2g" | "2g" | "3g" | "4g"
    : undefined;
  const contrast = mediaPreference([
    ["(prefers-contrast: more)", "more"],
    ["(prefers-contrast: less)", "less"],
    ["(prefers-contrast: custom)", "custom"],
  ], "no-preference") as ContextSnapshot["preferences"]["contrast"];
  const colorScheme = mediaPreference([
    ["(prefers-color-scheme: dark)", "dark"],
    ["(prefers-color-scheme: light)", "light"],
  ], "no-preference") as ContextSnapshot["preferences"]["colorScheme"];
  const connectionSnapshot = connection ? compact({
    downlinkMbps: finiteNumber(connection.downlink, 0, 10_000),
    effectiveType,
    rttMs: finiteInteger(connection.rtt, 0, 60_000),
    saveData: typeof connection.saveData === "boolean" ? connection.saveData : undefined,
  }) : undefined;
  return {
    browser: compact({
      language: boundedText(navigator.language, 35),
      languages: languages.length ? languages : undefined,
      online: navigator.onLine,
      timeZone: boundedText(Intl.DateTimeFormat().resolvedOptions().timeZone, 100),
    }),
    capabilities: compact({
      cookiesEnabled: navigator.cookieEnabled,
      localStorage: storageState("localStorage"),
      pdfViewerEnabled: typeof navigatorWithContext.pdfViewerEnabled === "boolean"
        ? navigatorWithContext.pdfViewerEnabled
        : undefined,
      sessionStorage: storageState("sessionStorage"),
    }),
    clientOccurredAt: new Date().toISOString(),
    connection: connectionSnapshot && Object.keys(connectionSnapshot).length ? connectionSnapshot : undefined,
    display: compact({
      availableHeight: finiteInteger(screen.availHeight, 0, 32_768),
      availableWidth: finiteInteger(screen.availWidth, 0, 32_768),
      colorDepth: finiteInteger(screen.colorDepth, 1, 64),
      devicePixelRatio: finiteNumber(window.devicePixelRatio, 0.1, 16),
      pixelDepth: finiteInteger(screen.pixelDepth, 1, 64),
      screenHeight: finiteInteger(screen.height, 1, 32_768),
      screenWidth: finiteInteger(screen.width, 1, 32_768),
      viewportHeight: finiteInteger(window.innerHeight, 1, 32_768),
      viewportWidth: finiteInteger(window.innerWidth, 1, 32_768),
    }),
    id: crypto.randomUUID(),
    input: compact({ maxTouchPoints: finiteInteger(navigator.maxTouchPoints, 0, 32) }),
    monotonicMs,
    preferences: {
      colorScheme,
      contrast,
      forcedColors: window.matchMedia("(forced-colors: active)").matches,
      reducedMotion: window.matchMedia("(prefers-reduced-motion: reduce)").matches,
    },
    purpose,
    schema: "vasi-participant-context/v1",
    sequence,
  };
}

function storageState(name: "localStorage" | "sessionStorage"): StorageState {
  if (!(name in window)) return "unavailable";
  const key = `__vasi_context_probe_${crypto.randomUUID()}__`;
  try {
    const storage = window[name];
    storage.setItem(key, "1");
    storage.removeItem(key);
    return "available";
  } catch {
    try { window[name]?.removeItem(key); } catch { /* storage is blocked */ }
    return "blocked";
  }
}

function mediaPreference(values: Array<[string, string]>, fallback: string) {
  return values.find(([query]) => window.matchMedia(query).matches)?.[1] || fallback;
}

function compact<T extends Record<string, unknown>>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined)) as T;
}

function boundedText(value: unknown, maximum: number) {
  return typeof value === "string" && value.trim() ? value.slice(0, maximum) : undefined;
}

function finiteNumber(value: unknown, minimum: number, maximum: number) {
  return typeof value === "number" && Number.isFinite(value) && value >= minimum && value <= maximum
    ? value
    : undefined;
}

function finiteInteger(value: unknown, minimum: number, maximum: number) {
  return Number.isSafeInteger(value) && Number(value) >= minimum && Number(value) <= maximum
    ? Number(value)
    : undefined;
}
