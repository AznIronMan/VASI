"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import type { OpenParticipantAssignment } from "@/lib/evidence-types";
import type { ActivityInteractionSummary } from "@/lib/owner-types";

type ActivityInteractionEventType =
  "presented" | "visible" | "hidden" | "focus" | "blur" |
  "heartbeat" | "interaction" | "disconnect";

type ActivityInteractionEvent = {
  clientOccurredAt: string;
  id: string;
  monotonicMs: number;
  sequence: number;
  type: ActivityInteractionEventType;
};

type QueuedEvent = { event: ActivityInteractionEvent; telemetrySessionId: string };
type PendingBatch = { batchId: string; events: ActivityInteractionEvent[]; telemetrySessionId: string };

export type ActivityInteractionRecorder = {
  disconnectAndFlush: () => Promise<void>;
  error?: string;
  flush: () => Promise<void>;
  resume: () => void;
  summary?: ActivityInteractionSummary;
};

export function useActivityInteractionRecorder(
  assignment: OpenParticipantAssignment,
  handle: string,
  rootRef: React.RefObject<HTMLElement | null>,
): ActivityInteractionRecorder {
  const [error, setError] = useState<string>();
  const [summary, setSummary] = useState<ActivityInteractionSummary | undefined>(
    assignment.interactionEvidence?.summary,
  );
  const activityId = assignment.activityId || "";
  const interactionId = assignment.interaction.id;
  const policy = assignment.interactionEvidence?.policy;
  const startedAt = useRef(0);
  const sequence = useRef(0);
  const telemetrySessionId = useRef("");
  const disconnected = useRef(true);
  const intersecting = useRef(false);
  const queue = useRef<QueuedEvent[]>([]);
  const pendingBatch = useRef<PendingBatch | undefined>(undefined);
  const activeFlush = useRef<Promise<void> | undefined>(undefined);
  const flushTimer = useRef<number | undefined>(undefined);
  const lastInteractionAt = useRef(Number.NEGATIVE_INFINITY);
  const flushRef = useRef<(keepalive?: boolean) => Promise<void>>(async () => undefined);
  const emitRef = useRef<(type: ActivityInteractionEventType) => void>(() => undefined);

  const flush = useCallback(async (keepalive = false) => {
    if (!activityId) return;
    if (activeFlush.current) {
      await activeFlush.current;
      if (!keepalive && (pendingBatch.current || queue.current.length)) {
        await flushRef.current(false);
      }
      return;
    }
    const operation = (async () => {
      while (true) {
        if (!pendingBatch.current && queue.current.length) {
          const sessionId = queue.current[0].telemetrySessionId;
          const selected: ActivityInteractionEvent[] = [];
          while (queue.current.length && selected.length < 100 &&
                 queue.current[0].telemetrySessionId === sessionId) {
            selected.push(queue.current.shift()!.event);
          }
          pendingBatch.current = {
            batchId: crypto.randomUUID(),
            events: selected,
            telemetrySessionId: sessionId,
          };
        }
        const batch = pendingBatch.current;
        if (!batch) return;
        const response = await fetch("/api/evidence/interaction-events", {
          body: JSON.stringify({
            activityId,
            batchId: batch.batchId,
            events: batch.events,
            handle,
            interactionId,
            telemetrySessionId: batch.telemetrySessionId,
          }),
          headers: { "content-type": "application/json" },
          keepalive,
          method: "POST",
          signal: keepalive ? undefined : AbortSignal.timeout(4_000),
        });
        const result = await response.json().catch(() => ({})) as {
          error?: string;
          summary?: ActivityInteractionSummary;
        };
        if (!response.ok) {
          setError(result.error || "Activity-presence evidence could not be synchronized yet; VASI will retry.");
          return;
        }
        pendingBatch.current = undefined;
        setError(undefined);
        if (result.summary) setSummary(result.summary);
        if (keepalive) return;
      }
    })().catch(() => {
      setError("Activity-presence evidence could not be synchronized yet; VASI will retry.");
    });
    activeFlush.current = operation;
    try {
      await operation;
    } finally {
      if (activeFlush.current === operation) activeFlush.current = undefined;
    }
  }, [activityId, handle, interactionId]);

  useEffect(() => { flushRef.current = flush; }, [flush]);

  const emit = useCallback((type: ActivityInteractionEventType) => {
    if (!telemetrySessionId.current || (disconnected.current && type !== "presented")) return;
    const monotonicMs = Math.min(
      604_800_000,
      Math.max(0, Math.round(performance.now() - startedAt.current)),
    );
    queue.current.push({
      event: {
        clientOccurredAt: new Date().toISOString(),
        id: crypto.randomUUID(),
        monotonicMs,
        sequence: ++sequence.current,
        type,
      },
      telemetrySessionId: telemetrySessionId.current,
    });
    if (type === "disconnect") disconnected.current = true;
    if (flushTimer.current) window.clearTimeout(flushTimer.current);
    flushTimer.current = window.setTimeout(
      () => void flushRef.current(false),
      type === "disconnect" ? 0 : 1_500,
    );
  }, []);

  useEffect(() => { emitRef.current = emit; }, [emit]);

  const resume = useCallback(() => {
    telemetrySessionId.current = crypto.randomUUID();
    startedAt.current = performance.now();
    sequence.current = 0;
    lastInteractionAt.current = Number.NEGATIVE_INFINITY;
    disconnected.current = false;
    emitRef.current("presented");
    emitRef.current(intersecting.current && document.visibilityState === "visible" ? "visible" : "hidden");
    emitRef.current(document.hasFocus() ? "focus" : "blur");
  }, []);

  const disconnectAndFlush = useCallback(async () => {
    if (!disconnected.current) emitRef.current("disconnect");
    await flushRef.current(false);
  }, []);

  useEffect(() => {
    const root = rootRef.current;
    if (!root || !activityId) return;
    resume();
    const observer = new IntersectionObserver(([entry]) => {
      const next = Boolean(entry?.isIntersecting && entry.intersectionRatio >= 0.25);
      if (intersecting.current === next) return;
      intersecting.current = next;
      emitRef.current(next && document.visibilityState === "visible" ? "visible" : "hidden");
    }, { threshold: [0, 0.25, 1] });
    observer.observe(root);

    const onVisibility = () => emitRef.current(
      document.visibilityState === "visible" && intersecting.current ? "visible" : "hidden",
    );
    const onFocus = () => emitRef.current("focus");
    const onBlur = () => emitRef.current("blur");
    const onInteraction = () => {
      const now = performance.now();
      if (now - lastInteractionAt.current < 5_000) return;
      lastInteractionAt.current = now;
      emitRef.current("interaction");
    };
    const onPageHide = () => {
      if (!disconnected.current) emitRef.current("disconnect");
      void flushRef.current(true);
    };
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("focus", onFocus);
    window.addEventListener("blur", onBlur);
    window.addEventListener("pagehide", onPageHide);
    root.addEventListener("pointerdown", onInteraction);
    root.addEventListener("keydown", onInteraction);
    root.addEventListener("change", onInteraction);
    const heartbeat = window.setInterval(
      () => emitRef.current("heartbeat"),
      (policy?.heartbeatSeconds || 10) * 1_000,
    );
    return () => {
      observer.disconnect();
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("focus", onFocus);
      window.removeEventListener("blur", onBlur);
      window.removeEventListener("pagehide", onPageHide);
      root.removeEventListener("pointerdown", onInteraction);
      root.removeEventListener("keydown", onInteraction);
      root.removeEventListener("change", onInteraction);
      window.clearInterval(heartbeat);
      if (flushTimer.current) window.clearTimeout(flushTimer.current);
      if (!disconnected.current) emitRef.current("disconnect");
      void flushRef.current(true);
    };
  }, [activityId, policy?.heartbeatSeconds, resume, rootRef]);

  return {
    disconnectAndFlush,
    error,
    flush: () => flush(false),
    resume,
    summary,
  };
}
