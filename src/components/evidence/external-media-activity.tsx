"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import type { OpenParticipantAssignment } from "@/lib/evidence-types";
import type { ExternalMediaDescriptor, MediaSummary } from "@/lib/owner-types";

type MediaEventType =
  "presented" | "frame_loaded" | "frame_error" | "visible" | "hidden" |
  "focus" | "blur" | "heartbeat" | "interaction" | "ready" | "play" |
  "pause" | "buffer_start" | "buffer_end" | "seek" | "rate" | "position" |
  "ended" | "provider_error" | "departed" | "returned" | "disconnect" |
  "accessibility_alternative";

type MediaEventFields = {
  detail?: { code?: string; message?: string; providerEvent?: string };
  durationSeconds?: number;
  fromSeconds?: number;
  playbackRate?: number;
  positionSeconds?: number;
  toSeconds?: number;
};

type MediaEvent = MediaEventFields & {
  id: string;
  monotonicMs: number;
  sequence: number;
  type: MediaEventType;
};

type Telemetry = {
  emit: (type: MediaEventType, fields?: MediaEventFields) => void;
  error?: string;
  setPosition: (positionSeconds?: number, durationSeconds?: number, playbackRate?: number) => void;
  summary?: MediaSummary;
};

type YouTubePlayer = {
  destroy(): void;
  getCurrentTime(): number;
  getDuration(): number;
  getIframe(): HTMLIFrameElement;
  getPlaybackRate(): number;
};

type YouTubeNamespace = {
  Player: new (element: HTMLElement, options: {
    events: {
      onError(event: { data: number; target: YouTubePlayer }): void;
      onPlaybackRateChange(event: { data: number; target: YouTubePlayer }): void;
      onReady(event: { target: YouTubePlayer }): void;
      onStateChange(event: { data: number; target: YouTubePlayer }): void;
    };
    host: string;
    playerVars: Record<string, number | string>;
    videoId: string;
  }) => YouTubePlayer;
};

type VimeoEvent = {
  duration?: number;
  playbackRate?: number;
  seconds?: number;
};

type VimeoPlayer = {
  destroy(): Promise<void>;
  getCurrentTime(): Promise<number>;
  getDuration(): Promise<number>;
  off(name: string): void;
  on(name: string, callback: (event: VimeoEvent) => void): void;
  ready(): Promise<void>;
};

type VimeoNamespace = { Player: new (element: HTMLIFrameElement) => VimeoPlayer };

declare global {
  interface Window {
    Vimeo?: VimeoNamespace;
    YT?: YouTubeNamespace;
    onYouTubeIframeAPIReady?: () => void;
  }
}

let youtubeLoader: Promise<YouTubeNamespace> | undefined;
let vimeoLoader: Promise<VimeoNamespace> | undefined;

export function ExternalMediaActivity({ assignment, handle }: {
  assignment: OpenParticipantAssignment;
  handle: string;
}) {
  const descriptor = assignment.content.descriptor;
  const policy = assignment.content.completionPolicy;
  const saved = isMediaResponse(assignment.savedResponse) ? assignment.savedResponse : undefined;
  const [method, setMethod] = useState<"playback" | "acknowledgement">(
    saved?.method || (policy?.mode === "acknowledgement" ? "acknowledgement" : "playback"),
  );
  const containerRef = useRef<HTMLElement>(null);
  const telemetry = useMediaTelemetry(assignment, handle, containerRef);
  if (!descriptor || !policy || !assignment.activityId) {
    return <p className="form-message form-message--error">The hosted-media activity is incomplete.</p>;
  }
  const playbackAvailable = descriptor.capability === "instrumented_player";
  return <section className="participant-media" ref={containerRef}>
    <header className="participant-media__header">
      <div><p className="eyebrow eyebrow--green">PROVIDER-HOSTED CONTENT</p><h2>{descriptor.title}</h2></div>
      <span className="participant-media__provider">{providerLabel(descriptor.provider)}</span>
    </header>
    {descriptor.description && <p>{descriptor.description}</p>}
    <p className="participant-media__notice">{assignment.content.providerNotice}</p>
    <MediaSurface assignment={assignment} descriptor={descriptor} handle={handle} telemetry={telemetry} />
    <dl className="participant-media__metadata">
      <div><dt>Provider item</dt><dd>{descriptor.itemId || "Provider URL"}</dd></div>
      <div><dt>Evidence capability</dt><dd>{capabilityLabel(descriptor.capability)}</dd></div>
      <div><dt>Version reference</dt><dd>{versionLabel(descriptor)}</dd></div>
      <div><dt>Access</dt><dd>{descriptor.accessMode.replaceAll("_", " ")}</dd></div>
    </dl>
    {telemetry.summary && <MediaEvidenceStatus summary={telemetry.summary} />}
    {telemetry.error && <p className="participant-limit" role="status">{telemetry.error}</p>}
    <div className="participant-media__limits">
      <strong>What VASI can support</strong>
      <ul>{(descriptor.limitations || []).map((limitation) => <li key={limitation}>{limitation}</li>)}</ul>
    </div>
    {assignment.content.accessibilityAlternative && <p><a href={assignment.content.accessibilityAlternative.url || descriptor.sourceUrl} target="_blank" rel="noreferrer" onClick={() => telemetry.emit("accessibility_alternative")}>{assignment.content.accessibilityAlternative.label}</a></p>}
    <fieldset className="participant-media__completion">
      <legend>{assignment.content.prompt}</legend>
      {policy.mode === "playback_or_acknowledgement" && <div className="participant-choices">
        <label><input type="radio" name="mediaMethod" value="playback" checked={method === "playback"} onChange={() => setMethod("playback")} /><span>Use validated playback completion</span></label>
        <label><input type="radio" name="mediaMethod" value="acknowledgement" checked={method === "acknowledgement"} onChange={() => setMethod("acknowledgement")} /><span>Use review acknowledgement</span></label>
      </div>}
      {policy.mode !== "playback_or_acknowledgement" && <input type="hidden" name="mediaMethod" value={policy.mode === "playback" ? "playback" : "acknowledgement"} />}
      {(policy.mode === "acknowledgement" || method === "acknowledgement") && <label><input type="checkbox" name="mediaAcknowledged" defaultChecked={saved?.acknowledged === true} required /><span>{assignment.content.acknowledgementLabel}</span></label>}
      {(policy.mode === "playback" || method === "playback") && <p className="participant-limit">Playback completion requires at least {policy.thresholdPercent}% and {policy.minimumUniqueSeconds} unique second{policy.minimumUniqueSeconds === 1 ? "" : "s"}. Seeking, hidden playback, and implausible or missing telemetry are not credited.{!playbackAvailable ? " This provider cannot satisfy playback completion." : ""}</p>}
    </fieldset>
  </section>;
}

function MediaSurface({ assignment, descriptor, handle, telemetry }: {
  assignment: OpenParticipantAssignment;
  descriptor: ExternalMediaDescriptor;
  handle: string;
  telemetry: Telemetry;
}) {
  if (descriptor.provider === "youtube" && descriptor.capability === "instrumented_player") {
    return <YouTubeSurface descriptor={descriptor} telemetry={telemetry} />;
  }
  if (descriptor.provider === "vimeo" && descriptor.capability === "instrumented_player") {
    return <VimeoSurface descriptor={descriptor} telemetry={telemetry} />;
  }
  if (["generic_embed", "version_aware_preview"].includes(descriptor.capability || "")) {
    return <GenericFrame assignment={assignment} descriptor={descriptor} handle={handle} telemetry={telemetry} />;
  }
  return <ExternalLink descriptor={descriptor} telemetry={telemetry} />;
}

function YouTubeSurface({ descriptor, telemetry }: { descriptor: ExternalMediaDescriptor; telemetry: Telemetry }) {
  const host = useRef<HTMLDivElement>(null);
  const { emit, setPosition } = telemetry;
  useEffect(() => {
    let cancelled = false;
    let player: YouTubePlayer | undefined;
    let timer: number | undefined;
    let playing = false;
    let prior: { at: number; position: number } | undefined;
    void loadYouTube().then((YT) => {
      if (cancelled || !host.current || !descriptor.itemId) return;
      player = new YT.Player(host.current, {
        events: {
          onError(event) {
            emit("provider_error", { detail: { code: String(event.data), providerEvent: "youtube_error" } });
          },
          onPlaybackRateChange(event) {
            emit("rate", { playbackRate: finite(event.data, 1) });
          },
          onReady(event) {
            const values = youtubeValues(event.target);
            event.target.getIframe().setAttribute("referrerpolicy", "strict-origin");
            event.target.getIframe().setAttribute("sandbox", "allow-scripts allow-same-origin allow-presentation allow-popups");
            setPosition(values.positionSeconds, values.durationSeconds, values.playbackRate);
            emit("ready", values);
          },
          onStateChange(event) {
            const values = youtubeValues(event.target);
            setPosition(values.positionSeconds, values.durationSeconds, values.playbackRate);
            if (event.data === 1) {
              playing = true;
              prior = { at: performance.now(), position: values.positionSeconds };
              emit("play", values);
            } else if (event.data === 2) {
              emit("pause", values);
              playing = false;
            } else if (event.data === 3) emit("buffer_start", values);
            else if (event.data === 0) {
              emit("ended", values);
              playing = false;
            }
          },
        },
        host: "https://www.youtube-nocookie.com",
        playerVars: {
          enablejsapi: 1,
          origin: window.location.origin,
          playsinline: 1,
          rel: 0,
        },
        videoId: descriptor.itemId,
      });
      timer = window.setInterval(() => {
        if (!playing || !player) return;
        const values = youtubeValues(player);
        const now = performance.now();
        if (prior) {
          const elapsed = Math.max(0, (now - prior.at) / 1_000);
          const advance = values.positionSeconds - prior.position;
          const plausible = elapsed * Math.max(1, values.playbackRate || 1) * 1.75 + 2;
          if (advance < -0.5 || advance > plausible) {
            emit("seek", { fromSeconds: Math.max(0, prior.position), toSeconds: Math.max(0, values.positionSeconds) });
          }
        }
        prior = { at: now, position: values.positionSeconds };
        setPosition(values.positionSeconds, values.durationSeconds, values.playbackRate);
        emit("position", values);
      }, 1_000);
    }).catch((error: unknown) => {
      emit("provider_error", { detail: { code: "youtube_api_unavailable", message: errorMessage(error) } });
    });
    return () => {
      cancelled = true;
      if (timer) window.clearInterval(timer);
      player?.destroy();
    };
  }, [descriptor.itemId, emit, setPosition]);
  return <div className="participant-media__frame participant-media__frame--player"><div ref={host} /></div>;
}

function VimeoSurface({ descriptor, telemetry }: { descriptor: ExternalMediaDescriptor; telemetry: Telemetry }) {
  const frame = useRef<HTMLIFrameElement>(null);
  const { emit, setPosition } = telemetry;
  useEffect(() => {
    let cancelled = false;
    let player: VimeoPlayer | undefined;
    let lastPosition = 0;
    let seekingFrom = 0;
    let lastPositionEventAt = 0;
    const emitPosition = (event: VimeoEvent, force = false) => {
      const now = performance.now();
      const positionSeconds = finite(event.seconds, lastPosition);
      const durationSeconds = finiteOptional(event.duration);
      lastPosition = positionSeconds;
      setPosition(positionSeconds, durationSeconds);
      if (force || now - lastPositionEventAt >= 900) {
        lastPositionEventAt = now;
        emit("position", { durationSeconds, positionSeconds });
      }
    };
    void loadVimeo().then(async (Vimeo) => {
      if (cancelled || !frame.current) return;
      player = new Vimeo.Player(frame.current);
      const handlers: Array<[string, (event: VimeoEvent) => void]> = [
        ["play", (event) => { emitPosition(event, true); emit("play", vimeoValues(event)); }],
        ["pause", (event) => { emitPosition(event, true); emit("pause", vimeoValues(event)); }],
        ["bufferstart", (event) => emit("buffer_start", vimeoValues(event))],
        ["bufferend", (event) => emit("buffer_end", vimeoValues(event))],
        ["timeupdate", (event) => emitPosition(event)],
        ["seeking", (event) => { seekingFrom = lastPosition; emitPosition(event); }],
        ["seeked", (event) => { const toSeconds = finite(event.seconds, lastPosition); emit("seek", { fromSeconds: Math.max(0, seekingFrom), toSeconds: Math.max(0, toSeconds) }); emitPosition(event, true); }],
        ["playbackratechange", (event) => emit("rate", { playbackRate: finite(event.playbackRate, 1) })],
        ["ended", (event) => { emitPosition(event, true); emit("ended", vimeoValues(event)); }],
        ["error", () => emit("provider_error", { detail: { code: "vimeo_player_error", providerEvent: "error" } })],
      ];
      for (const [name, handler] of handlers) player.on(name, handler);
      try {
        await player.ready();
        if (cancelled) return;
        const [positionSeconds, durationSeconds] = await Promise.all([player.getCurrentTime(), player.getDuration()]);
        setPosition(positionSeconds, durationSeconds);
        emit("ready", { durationSeconds, positionSeconds });
      } catch (error) {
        emit("provider_error", { detail: { code: "vimeo_ready_failed", message: errorMessage(error) } });
      }
    }).catch((error: unknown) => {
      emit("provider_error", { detail: { code: "vimeo_api_unavailable", message: errorMessage(error) } });
    });
    return () => {
      cancelled = true;
      if (player) {
        for (const name of ["play", "pause", "bufferstart", "bufferend", "timeupdate", "seeking", "seeked", "playbackratechange", "ended", "error"]) player.off(name);
        void player.destroy().catch(() => undefined);
      }
    };
  }, [emit, setPosition]);
  return <div className="participant-media__frame participant-media__frame--player"><iframe ref={frame} src={descriptor.embedUrl} title={descriptor.title} allow="autoplay; fullscreen; picture-in-picture" referrerPolicy="strict-origin" sandbox="allow-scripts allow-same-origin allow-presentation allow-popups" /></div>;
}

function GenericFrame({ assignment, descriptor, handle, telemetry }: {
  assignment: OpenParticipantAssignment;
  descriptor: ExternalMediaDescriptor;
  handle: string;
  telemetry: Telemetry;
}) {
  const frame = useRef<HTMLIFrameElement>(null);
  const { emit } = telemetry;
  useEffect(() => {
    const receive = (event: MessageEvent) => {
      if (event.origin !== window.location.origin || event.source !== frame.current?.contentWindow || !isFrameMessage(event.data)) return;
      if (event.data.activityId !== assignment.activityId || event.data.itemId !== descriptor.itemId) return;
      if (event.data.type === "frame_loaded") emit("frame_loaded");
      else emit("frame_error", { detail: { code: event.data.detail?.code || "provider_frame_error" } });
    };
    window.addEventListener("message", receive);
    return () => window.removeEventListener("message", receive);
  }, [assignment.activityId, descriptor.itemId, emit]);
  const source = `/r/${handle}/media/${encodeURIComponent(assignment.activityId || "")}/frame`;
  return <div className="participant-media__frame"><iframe ref={frame} src={source} title={descriptor.title} referrerPolicy="strict-origin" sandbox="allow-scripts allow-same-origin" onError={() => emit("frame_error", { detail: { code: "vasi_frame_error" } })} /></div>;
}

function ExternalLink({ descriptor, telemetry }: { descriptor: ExternalMediaDescriptor; telemetry: Telemetry }) {
  const departed = useRef(false);
  const { emit } = telemetry;
  useEffect(() => {
    const returned = () => {
      if (!departed.current) return;
      departed.current = false;
      emit("returned");
    };
    window.addEventListener("focus", returned);
    return () => window.removeEventListener("focus", returned);
  }, [emit]);
  return <div className="participant-media__external"><p>This provider is opened in a separate tab. VASI can record that you left and returned, but cannot observe activity inside the provider.</p><a className="primary-button" href={descriptor.sourceUrl} target="_blank" rel="noreferrer" onClick={() => { departed.current = true; emit("departed"); }}>Open provider content</a></div>;
}

function MediaEvidenceStatus({ summary }: { summary: MediaSummary }) {
  return <section className="participant-media__status" aria-live="polite">
    <strong>{summary.playback.completionMet ? "Playback threshold met" : "Evidence recording in progress"}</strong>
    <span>{formatSeconds(summary.playback.uniqueMilliseconds)} unique playback · {formatPercent(summary.playback.percentBasisPoints)}</span>
    <span>{formatSeconds(summary.engagement.visibleMilliseconds)} visible · confidence {summary.confidence.level}</span>
    {summary.sessionIntegrity.incompleteSessionCount > 0 && <span>{summary.sessionIntegrity.incompleteSessionCount} active/incomplete telemetry session(s)</span>}
  </section>;
}

function useMediaTelemetry(
  assignment: OpenParticipantAssignment,
  handle: string,
  containerRef: React.RefObject<HTMLElement | null>,
): Telemetry {
  const [telemetrySessionId] = useState(() => crypto.randomUUID());
  const [summary, setSummary] = useState<MediaSummary | undefined>(assignment.mediaSummary);
  const [error, setError] = useState<string>();
  const startedAt = useRef(0);
  const sequence = useRef(0);
  const queue = useRef<MediaEvent[]>([]);
  const pendingBatch = useRef<{ batchId: string; events: MediaEvent[] } | undefined>(undefined);
  const flushing = useRef(false);
  const flushTimer = useRef<number | undefined>(undefined);
  const flushRef = useRef<(keepalive?: boolean) => Promise<void>>(async () => undefined);
  const position = useRef<Pick<MediaEventFields, "durationSeconds" | "playbackRate" | "positionSeconds">>({});
  const activityId = assignment.activityId || "";
  const interactionId = assignment.interaction.id;

  const flush = useCallback(async (keepalive = false) => {
    if (flushing.current || !activityId) return;
    flushing.current = true;
    try {
      while (true) {
        if (!pendingBatch.current && queue.current.length) {
          pendingBatch.current = { batchId: crypto.randomUUID(), events: queue.current.splice(0, 100) };
        }
        const batch = pendingBatch.current;
        if (!batch) return;
        const response = await fetch("/api/evidence/media-events", {
          body: JSON.stringify({
            activityId,
            batchId: batch.batchId,
            events: batch.events,
            handle,
            interactionId,
            telemetrySessionId,
          }),
          headers: { "content-type": "application/json" },
          keepalive,
          method: "POST",
        });
        const result = await response.json().catch(() => ({})) as { error?: string; summary?: MediaSummary };
        if (!response.ok) {
          setError(result.error || "Playback evidence could not be synchronized yet; VASI will retry.");
          return;
        }
        pendingBatch.current = undefined;
        setError(undefined);
        if (result.summary) setSummary(result.summary);
        if (keepalive) return;
      }
    } catch {
      setError("Playback evidence could not be synchronized yet; VASI will retry.");
    } finally {
      flushing.current = false;
    }
  }, [activityId, handle, interactionId, telemetrySessionId]);

  useEffect(() => { flushRef.current = flush; }, [flush]);

  const emit = useCallback((type: MediaEventType, fields: MediaEventFields = {}) => {
    const monotonicMs = Math.min(604_800_000, Math.max(0, Math.round(performance.now() - startedAt.current)));
    queue.current.push({
      ...fields,
      id: crypto.randomUUID(),
      monotonicMs,
      sequence: ++sequence.current,
      type,
    });
    if (flushTimer.current) window.clearTimeout(flushTimer.current);
    const urgent = ["pause", "ended", "provider_error", "frame_error", "disconnect"].includes(type);
    flushTimer.current = window.setTimeout(() => void flushRef.current(false), urgent ? 0 : 1_500);
  }, []);

  const setPosition = useCallback((positionSeconds?: number, durationSeconds?: number, playbackRate?: number) => {
    position.current = {
      durationSeconds: finiteOptional(durationSeconds),
      playbackRate: finiteOptional(playbackRate),
      positionSeconds: finiteOptional(positionSeconds),
    };
  }, []);

  useEffect(() => {
    startedAt.current = performance.now();
    const root = containerRef.current;
    if (!root) return;
    let intersecting = false;
    let reportedVisible: boolean | undefined;
    let disconnected = false;
    let lastInteractionAt = -10_000;
    const reportVisibility = () => {
      const next = intersecting && !document.hidden;
      if (next === reportedVisible) return;
      reportedVisible = next;
      emit(next ? "visible" : "hidden");
    };
    emit("presented");
    emit(document.hasFocus() ? "focus" : "blur");
    const observer = new IntersectionObserver((entries) => {
      intersecting = Boolean(entries[0]?.isIntersecting && entries[0].intersectionRatio >= 0.25);
      reportVisibility();
    }, { threshold: [0, 0.25, 0.75] });
    observer.observe(root);
    const focus = () => emit("focus");
    const blur = () => emit("blur");
    const visibility = () => reportVisibility();
    const interaction = () => {
      const now = performance.now();
      if (now - lastInteractionAt < 5_000) return;
      lastInteractionAt = now;
      emit("interaction");
    };
    const disconnect = () => {
      if (disconnected) return;
      disconnected = true;
      emit("disconnect", position.current);
      void flushRef.current(true);
    };
    window.addEventListener("focus", focus);
    window.addEventListener("blur", blur);
    window.addEventListener("pagehide", disconnect);
    document.addEventListener("visibilitychange", visibility);
    root.addEventListener("pointerdown", interaction, { passive: true });
    root.addEventListener("keydown", interaction);
    const heartbeat = window.setInterval(() => emit("heartbeat", position.current), (assignment.content.telemetryPolicy?.heartbeatSeconds || 5) * 1_000);
    return () => {
      observer.disconnect();
      window.removeEventListener("focus", focus);
      window.removeEventListener("blur", blur);
      window.removeEventListener("pagehide", disconnect);
      document.removeEventListener("visibilitychange", visibility);
      root.removeEventListener("pointerdown", interaction);
      root.removeEventListener("keydown", interaction);
      window.clearInterval(heartbeat);
      if (flushTimer.current) window.clearTimeout(flushTimer.current);
      disconnect();
    };
  }, [assignment.content.telemetryPolicy?.heartbeatSeconds, containerRef, emit]);

  return { emit, error, setPosition, summary };
}

function loadYouTube() {
  if (window.YT?.Player) return Promise.resolve(window.YT);
  youtubeLoader ||= new Promise<YouTubeNamespace>((resolve, reject) => {
    const prior = window.onYouTubeIframeAPIReady;
    window.onYouTubeIframeAPIReady = () => {
      prior?.();
      if (window.YT?.Player) resolve(window.YT);
      else reject(new Error("YouTube API did not initialize."));
    };
    let script = document.querySelector<HTMLScriptElement>('script[data-vasi-player="youtube"]');
    if (!script) {
      script = document.createElement("script");
      script.dataset.vasiPlayer = "youtube";
      script.src = "https://www.youtube.com/iframe_api";
      script.async = true;
      document.head.append(script);
    }
    script.addEventListener("error", () => reject(new Error("YouTube API could not be loaded.")), { once: true });
  });
  return youtubeLoader;
}

function loadVimeo() {
  if (window.Vimeo?.Player) return Promise.resolve(window.Vimeo);
  vimeoLoader ||= new Promise<VimeoNamespace>((resolve, reject) => {
    let script = document.querySelector<HTMLScriptElement>('script[data-vasi-player="vimeo"]');
    if (!script) {
      script = document.createElement("script");
      script.dataset.vasiPlayer = "vimeo";
      script.src = "https://player.vimeo.com/api/player.js";
      script.async = true;
      document.head.append(script);
    }
    script.addEventListener("load", () => window.Vimeo?.Player ? resolve(window.Vimeo) : reject(new Error("Vimeo API did not initialize.")), { once: true });
    script.addEventListener("error", () => reject(new Error("Vimeo API could not be loaded.")), { once: true });
  });
  return vimeoLoader;
}

function youtubeValues(player: YouTubePlayer): MediaEventFields & { positionSeconds: number } {
  return {
    durationSeconds: finiteOptional(player.getDuration()),
    playbackRate: finite(player.getPlaybackRate(), 1),
    positionSeconds: Math.max(0, finite(player.getCurrentTime(), 0)),
  };
}

function vimeoValues(event: VimeoEvent): MediaEventFields {
  return {
    durationSeconds: finiteOptional(event.duration),
    playbackRate: finiteOptional(event.playbackRate),
    positionSeconds: finiteOptional(event.seconds),
  };
}

function isFrameMessage(value: unknown): value is {
  activityId: string;
  detail?: { code?: string };
  itemId?: string;
  schema: "vasi-media-frame/v1";
  type: "frame_loaded" | "frame_error";
} {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return record.schema === "vasi-media-frame/v1" &&
    typeof record.activityId === "string" &&
    (record.itemId === undefined || typeof record.itemId === "string") &&
    ["frame_loaded", "frame_error"].includes(String(record.type));
}

function isMediaResponse(value: unknown): value is { acknowledged?: boolean; method: "playback" | "acknowledgement" } {
  return Boolean(value && typeof value === "object" && !Array.isArray(value) &&
    ["playback", "acknowledgement"].includes(String((value as Record<string, unknown>).method)));
}

function providerLabel(provider: ExternalMediaDescriptor["provider"]) {
  return ({
    dropbox: "Dropbox",
    external_link: "External provider",
    generic: "Approved provider",
    google_drive: "Google Drive",
    sharepoint: "SharePoint / OneDrive",
    vimeo: "Vimeo",
    youtube: "YouTube",
  })[provider];
}

function capabilityLabel(capability?: ExternalMediaDescriptor["capability"]) {
  return ({
    external_link: "Departure and return",
    generic_embed: "Frame presentation and visibility",
    instrumented_player: "Instrumented playback",
    version_aware_preview: "Version-aware frame presentation",
  })[capability || "external_link"];
}

function versionLabel(descriptor: ExternalMediaDescriptor) {
  const version = descriptor.version;
  return version?.checksum || version?.eTag || version?.cTag || version?.id || "Not supplied by provider";
}

function formatSeconds(milliseconds: number) {
  return `${(milliseconds / 1_000).toFixed(milliseconds % 1_000 ? 1 : 0)}s`;
}

function formatPercent(basisPoints: number) {
  return `${(basisPoints / 100).toFixed(basisPoints % 100 ? 2 : 0)}%`;
}

function finite(value: unknown, fallback: number) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function finiteOptional(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : undefined;
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message.slice(0, 500) : "Provider player error";
}
