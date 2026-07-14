export const MEDIA_PROVIDERS = Object.freeze([
  "youtube",
  "vimeo",
  "sharepoint",
  "google_drive",
  "dropbox",
  "generic",
  "external_link",
]);

export const MEDIA_CAPABILITIES = Object.freeze([
  "instrumented_player",
  "version_aware_preview",
  "generic_embed",
  "external_link",
]);

export const MEDIA_EVENT_TYPES = Object.freeze([
  "presented",
  "frame_loaded",
  "frame_error",
  "visible",
  "hidden",
  "focus",
  "blur",
  "heartbeat",
  "interaction",
  "ready",
  "play",
  "pause",
  "buffer_start",
  "buffer_end",
  "seek",
  "rate",
  "position",
  "ended",
  "provider_error",
  "departed",
  "returned",
  "disconnect",
  "accessibility_alternative",
]);

const PLAYER_EVENTS = new Set([
  "ready", "play", "pause", "buffer_start", "buffer_end", "seek", "rate",
  "position", "ended", "provider_error",
]);
const FRAME_EVENTS = new Set([
  "presented", "frame_loaded", "frame_error", "visible", "hidden", "focus",
  "blur", "heartbeat", "interaction", "disconnect", "accessibility_alternative",
]);
const LINK_EVENTS = new Set([
  "presented", "focus", "blur", "heartbeat", "interaction", "departed", "returned",
  "disconnect", "accessibility_alternative",
]);

export function normalizeExternalMediaContent(value) {
  const input = strictDefinitionObject(value, "external media content", [
    "accessibilityAlternative", "acknowledgementLabel", "completionPolicy", "descriptor",
    "prompt", "providerNotice", "telemetryPolicy",
  ]);
  const descriptor = normalizeDescriptor(input.descriptor);
  const completionPolicy = normalizeCompletionPolicy(input.completionPolicy, descriptor);
  return Object.freeze({
    accessibilityAlternative: normalizeAccessibilityAlternative(input.accessibilityAlternative),
    acknowledgementLabel: optionalDefinitionString(
      input.acknowledgementLabel,
      "acknowledgementLabel",
      160,
    ) || "I confirm that I reviewed the available media or accessibility alternative.",
    completionPolicy,
    descriptor,
    prompt: boundedDefinitionString(input.prompt, "activity.content.prompt", 2, 1_000),
    providerNotice: optionalDefinitionString(input.providerNotice, "providerNotice", 1_000) ||
      "This content is hosted by an external provider, which may receive normal network, browser, cookie, or account context.",
    telemetryPolicy: normalizeTelemetryPolicy(input.telemetryPolicy),
  });
}

export function validateMediaOriginPolicy(content, configuredOrigins = []) {
  const allowed = new Set(configuredOrigins.map(normalizeConfiguredOrigin));
  const descriptor = content.descriptor;
  if (["generic", "external_link"].includes(descriptor.provider) &&
      !allowed.has(new URL(descriptor.sourceUrl).origin)) {
    invalidDefinition("The generic media origin is not enabled by the installation policy.");
  }
  return content;
}

export function validateMediaEventBatch(value, content) {
  const input = strictTelemetryObject(value, "media event batch", [
    "activityId", "batchId", "events", "handle", "interactionId", "telemetrySessionId",
  ]);
  if (!Array.isArray(input.events) || !input.events.length || input.events.length > 100) {
    invalidTelemetry("A media batch requires 1 to 100 events.");
  }
  const events = input.events.map((event, index) => normalizeMediaEvent(event, index));
  for (let index = 1; index < events.length; index += 1) {
    if (events[index].sequence <= events[index - 1].sequence ||
        events[index].monotonicMs < events[index - 1].monotonicMs) {
      invalidTelemetry("Media event sequence and monotonic time must increase within a batch.");
    }
  }
  const ids = new Set(events.map((event) => event.id));
  if (ids.size !== events.length) invalidTelemetry("A media event ID cannot repeat within a batch.");
  const allowedEvents = allowedEventTypes(content.descriptor.capability);
  if (events.some((event) => !allowedEvents.has(event.type))) {
    invalidTelemetry("The media capability does not support one or more supplied events.");
  }
  return Object.freeze({
    activityId: responseToken(input.activityId, "activityId", 64),
    batchId: responseToken(input.batchId, "batchId", 128),
    events: Object.freeze(events),
    handle: responseToken(input.handle, "handle", 64),
    interactionId: responseToken(input.interactionId, "interactionId", 128),
    telemetrySessionId: responseToken(input.telemetrySessionId, "telemetrySessionId", 128),
  });
}

export function calculateMediaSummary(content, rows) {
  const events = rows.map(normalizeStoredEvent);
  const grouped = new Map();
  for (const event of events) {
    const key = event.telemetrySessionId || event.interactionId || "unknown";
    const group = grouped.get(key) || [];
    group.push(event);
    grouped.set(key, group);
  }

  let openMilliseconds = 0;
  let visibleMilliseconds = 0;
  let engagedMilliseconds = 0;
  let gapCount = 0;
  let uncreditedGapMilliseconds = 0;
  let seekCount = 0;
  let skippedMilliseconds = 0;
  let endedObserved = false;
  let providerErrorCount = 0;
  let disconnectCount = 0;
  let incompleteSessionCount = 0;
  const intervals = [];
  const observedDurations = [];

  for (const group of grouped.values()) {
    group.sort((left, right) => left.sequence - right.sequence);
    let previous;
    let opened = false;
    let visible = false;
    let focused = false;
    let playing = false;
    let buffering = false;
    let playbackRateMilli = 1_000;
    let lastInteractionMs;
    let sample;
    let sawDisconnect = false;
    let sawPresented = false;

    for (const event of group) {
      const playbackWasCreditable = playing && !buffering && visible;
      if (previous) {
        const deltaMilliseconds = event.monotonicMs - previous.monotonicMs;
        if (deltaMilliseconds < 0) {
          gapCount += 1;
        } else if (deltaMilliseconds > content.telemetryPolicy.maxCreditedGapSeconds * 1_000) {
          gapCount += 1;
          uncreditedGapMilliseconds += deltaMilliseconds;
          sample = undefined;
        } else {
          if (opened) openMilliseconds += deltaMilliseconds;
          if (opened && visible && focused) visibleMilliseconds += deltaMilliseconds;
          if (opened && visible && focused && lastInteractionMs !== undefined &&
              previous.monotonicMs - lastInteractionMs <= content.telemetryPolicy.idleSeconds * 1_000) {
            engagedMilliseconds += deltaMilliseconds;
          }
        }
      }

      if (event.durationMilliseconds !== undefined) observedDurations.push(event.durationMilliseconds);
      if (["position", "heartbeat", "pause", "ended"].includes(event.type) &&
          event.positionMilliseconds !== undefined) {
        if (sample && playbackWasCreditable) {
          const elapsed = event.monotonicMs - sample.monotonicMs;
          const advance = event.positionMilliseconds - sample.positionMilliseconds;
          const maximumPlausibleAdvance = Math.max(0, elapsed) *
            (Math.max(1_000, sample.playbackRateMilli) / 1_000) * 1.5 + 1_500;
          if (elapsed >= 0 && elapsed <= content.telemetryPolicy.maxCreditedGapSeconds * 1_000 &&
              advance >= 0 && advance <= maximumPlausibleAdvance) {
            if (advance > 0) intervals.push([sample.positionMilliseconds, event.positionMilliseconds]);
          } else if (Math.abs(advance) > 250) {
            gapCount += 1;
            skippedMilliseconds += Math.abs(advance);
          }
        }
        sample = {
          monotonicMs: event.monotonicMs,
          playbackRateMilli,
          positionMilliseconds: event.positionMilliseconds,
        };
      }
      if (event.type === "presented") {
        opened = true;
        sawPresented = true;
      }
      if (event.type === "visible") visible = true;
      if (event.type === "hidden") visible = false;
      if (event.type === "focus") focused = true;
      if (event.type === "blur") focused = false;
      if (event.type === "interaction") lastInteractionMs = event.monotonicMs;
      if (event.type === "play") {
        playing = true;
        buffering = false;
      }
      if (event.type === "pause") playing = false;
      if (event.type === "buffer_start") buffering = true;
      if (event.type === "buffer_end") buffering = false;
      if (event.type === "rate") playbackRateMilli = event.playbackRateMilli;
      if (event.type === "seek") {
        seekCount += 1;
        skippedMilliseconds += Math.abs(event.toMilliseconds - event.fromMilliseconds);
        sample = undefined;
      }
      if (event.type === "ended") {
        endedObserved = true;
        playing = false;
      }
      if (["provider_error", "frame_error"].includes(event.type)) providerErrorCount += 1;
      if (event.type === "disconnect") {
        opened = false;
        sawDisconnect = true;
        disconnectCount += 1;
      }
      previous = event;
    }
    if (sawPresented && !sawDisconnect) incompleteSessionCount += 1;
  }

  const uniqueMilliseconds = intervalUnionMilliseconds(intervals);
  const configuredDuration = content.descriptor.durationMilliseconds;
  const observedDuration = consistentDuration(observedDurations);
  const durationMilliseconds = configuredDuration || observedDuration;
  const durationSource = configuredDuration
    ? "workflow_descriptor"
    : observedDuration ? "provider_player_reported" : "unavailable";
  const percentBasisPoints = durationMilliseconds
    ? Math.min(10_000, Math.round((uniqueMilliseconds / durationMilliseconds) * 10_000))
    : 0;
  const instrumented = content.descriptor.capability === "instrumented_player";
  const completionMet = instrumented && Boolean(durationMilliseconds) &&
    percentBasisPoints >= content.completionPolicy.thresholdPercent * 100 &&
    uniqueMilliseconds >= content.completionPolicy.minimumUniqueSeconds * 1_000;
  const limitations = [...content.descriptor.limitations];
  if (!instrumented) limitations.push("This capability does not provide validated playback events.");
  if (!durationMilliseconds) limitations.push("Media duration was unavailable, so playback completion cannot be calculated.");
  if (gapCount) limitations.push("One or more telemetry gaps or implausible position changes were not credited.");
  if (providerErrorCount) limitations.push("The provider or embed reported one or more errors.");
  if (incompleteSessionCount) limitations.push("One or more telemetry sessions had no disconnect event at the time of calculation; no time after the last event was credited.");
  limitations.push("Browser telemetry is supporting evidence and does not prove attention or comprehension.");
  const uniqueLimitations = [...new Set(limitations)];
  const confidence = !instrumented || !events.length
    ? "none"
    : providerErrorCount || gapCount || !durationMilliseconds ? "low" : "medium";

  return Object.freeze({
    calculation: Object.freeze({
      clock: "client_monotonic_anchored_to_server_receive_time",
      policyVersion: "vasi-media-calculation/v1",
      telemetryPolicy: content.telemetryPolicy,
    }),
    capability: content.descriptor.capability,
    confidence: Object.freeze({ level: confidence, limitations: Object.freeze(uniqueLimitations) }),
    engagement: Object.freeze({
      engagedMilliseconds,
      openMilliseconds,
      visibleMilliseconds,
    }),
    eventCount: events.length,
    gaps: Object.freeze({ count: gapCount, uncreditedMilliseconds: uncreditedGapMilliseconds }),
    playback: Object.freeze({
      completionMet,
      durationMilliseconds,
      durationSource,
      endedObserved,
      percentBasisPoints,
      providerErrorCount,
      seekCount,
      skippedMilliseconds,
      thresholdPercent: content.completionPolicy.thresholdPercent,
      uniqueMilliseconds,
    }),
    schema: "vasi-media-summary/v1",
    sessionCount: grouped.size,
    sessionIntegrity: Object.freeze({ disconnectCount, incompleteSessionCount }),
  });
}

function normalizeDescriptor(value) {
  const input = strictDefinitionObject(value, "media descriptor", [
    "accessMode", "checksum", "description", "dimensions", "durationSeconds", "embedUrl",
    "itemId", "kind", "lastModifiedAt", "owner", "provider", "sourceUrl", "title",
    "version",
  ]);
  const provider = boundedDefinitionString(input.provider, "descriptor.provider", 1, 32);
  if (!MEDIA_PROVIDERS.includes(provider)) invalidDefinition("The media provider is unsupported.");
  const source = safeURL(input.sourceUrl, "descriptor.sourceUrl");
  const kind = input.kind || "video";
  if (!['image', 'video', 'audio', 'presentation', 'document'].includes(kind)) {
    invalidDefinition("The media kind is unsupported.");
  }
  const version = normalizeVersion(input);
  const normalized = providerDescriptor(provider, source, input, version, kind);
  return Object.freeze({
    accessMode: normalizeAccessMode(input.accessMode),
    adapter: Object.freeze(normalized.adapter),
    allowedOrigins: Object.freeze(normalized.allowedOrigins),
    capability: normalized.capability,
    description: optionalDefinitionString(input.description, "descriptor.description", 2_000),
    dimensions: normalizeDimensions(input.dimensions),
    durationMilliseconds: optionalDurationMilliseconds(input.durationSeconds, "descriptor.durationSeconds"),
    embedUrl: normalized.embedUrl,
    itemId: normalized.itemId,
    kind: normalized.kind,
    limitations: Object.freeze(normalized.limitations),
    metadataProvenance: "tenant_supplied_unverified",
    owner: optionalDefinitionString(input.owner, "descriptor.owner", 320),
    provider,
    sourceUrl: source.href,
    title: boundedDefinitionString(input.title, "descriptor.title", 2, 200),
    version,
  });
}

function providerDescriptor(provider, source, input, version, kind) {
  switch (provider) {
    case "youtube": {
      const itemId = youtubeId(source, input.itemId);
      return {
        adapter: { id: "vasi-youtube-iframe", version: "1" },
        allowedOrigins: ["https://www.youtube-nocookie.com", "https://www.youtube.com"],
        capability: "instrumented_player",
        embedUrl: `https://www.youtube-nocookie.com/embed/${itemId}?enablejsapi=1&rel=0&playsinline=1`,
        itemId,
        kind: "video",
        limitations: providerLimitations(version),
      };
    }
    case "vimeo": {
      const itemId = vimeoId(source, input.itemId);
      return {
        adapter: { id: "vasi-vimeo-player", version: "1" },
        allowedOrigins: ["https://player.vimeo.com"],
        capability: "instrumented_player",
        embedUrl: `https://player.vimeo.com/video/${itemId}?dnt=1`,
        itemId,
        kind: "video",
        limitations: providerLimitations(version),
      };
    }
    case "sharepoint": {
      requireHost(source, (host) => host.endsWith(".sharepoint.com") || host === "onedrive.live.com");
      const embed = safeURL(input.embedUrl || input.sourceUrl, "descriptor.embedUrl");
      requireHost(embed, (host) => host.endsWith(".sharepoint.com") || host === "onedrive.live.com");
      const stable = hasStableVersion(version);
      return {
        adapter: { id: "vasi-microsoft-preview", version: "1" },
        allowedOrigins: [embed.origin],
        capability: stable ? "version_aware_preview" : "generic_embed",
        embedUrl: embed.href,
        itemId: requiredItemId(input.itemId, "SharePoint"),
        kind,
        limitations: [
          ...(stable ? [] : ["No stable version/eTag/checksum was supplied; the referenced bytes cannot be identified exactly."]),
          "SharePoint preview access can expire, be revoked, or require a separate provider session.",
          "SharePoint preview presentation is observable, but in-frame playback is not claimed.",
        ],
      };
    }
    case "google_drive": {
      requireHost(source, (host) => host === "drive.google.com" || host === "docs.google.com");
      const itemId = googleDriveId(source, input.itemId);
      return {
        adapter: { id: "vasi-google-drive-preview", version: "1" },
        allowedOrigins: ["https://drive.google.com", "https://docs.google.com"],
        capability: "generic_embed",
        embedUrl: `https://drive.google.com/file/d/${encodeURIComponent(itemId)}/preview`,
        itemId,
        kind,
        limitations: [
          ...providerLimitations(version),
          "Google Drive access can be revoked or require a separate provider session.",
          "Google Drive preview visibility is observable, but in-frame playback is not claimed.",
        ],
      };
    }
    case "dropbox": {
      requireHost(source, (host) => host === "www.dropbox.com" || host === "dropbox.com");
      return {
        adapter: { id: "vasi-dropbox-external", version: "1" },
        allowedOrigins: [source.origin],
        capability: "external_link",
        embedUrl: undefined,
        itemId: optionalDefinitionString(input.itemId, "descriptor.itemId", 256) || source.pathname,
        kind,
        limitations: [
          ...providerLimitations(version),
          "Dropbox Embedder does not support audio or video; VASI records external-link departure and return only.",
        ],
      };
    }
    case "generic": {
      const embed = safeURL(input.embedUrl || input.sourceUrl, "descriptor.embedUrl");
      if (embed.origin !== source.origin) invalidDefinition("Generic source and embed origins must match.");
      return {
        adapter: { id: "vasi-generic-embed", version: "1" },
        allowedOrigins: [source.origin],
        capability: "generic_embed",
        embedUrl: embed.href,
        itemId: optionalDefinitionString(input.itemId, "descriptor.itemId", 256) || source.href,
        kind,
        limitations: [
          ...providerLimitations(version),
          "Generic iframe visibility is observable, but in-frame interaction or playback is not claimed.",
        ],
      };
    }
    case "external_link":
      return {
        adapter: { id: "vasi-external-link", version: "1" },
        allowedOrigins: [source.origin],
        capability: "external_link",
        embedUrl: undefined,
        itemId: optionalDefinitionString(input.itemId, "descriptor.itemId", 256) || source.href,
        kind,
        limitations: [
          ...providerLimitations(version),
          "The provider is opened outside VASI; only departure, return, and acknowledgement are observable.",
        ],
      };
    default:
      invalidDefinition("The media adapter is unavailable.");
  }
}

function normalizeCompletionPolicy(value, descriptor) {
  const input = value === undefined ? {} : strictDefinitionObject(value, "completion policy", [
    "minimumUniqueSeconds", "mode", "thresholdPercent",
  ]);
  const defaultMode = descriptor.capability === "instrumented_player"
    ? "playback_or_acknowledgement"
    : "acknowledgement";
  const mode = input.mode || defaultMode;
  if (!['playback', 'acknowledgement', 'playback_or_acknowledgement'].includes(mode)) {
    invalidDefinition("The media completion mode is unsupported.");
  }
  if (descriptor.capability !== "instrumented_player" && mode !== "acknowledgement") {
    invalidDefinition("This media capability cannot require playback completion.");
  }
  return Object.freeze({
    minimumUniqueSeconds: safeInteger(input.minimumUniqueSeconds ?? 1, "minimumUniqueSeconds", 0, 604_800),
    mode,
    thresholdPercent: safeInteger(input.thresholdPercent ?? 90, "thresholdPercent", 1, 100),
  });
}

function normalizeTelemetryPolicy(value) {
  const input = value === undefined ? {} : strictDefinitionObject(value, "telemetry policy", [
    "heartbeatSeconds", "idleSeconds", "maxCreditedGapSeconds",
  ]);
  const heartbeatSeconds = safeInteger(input.heartbeatSeconds ?? 5, "heartbeatSeconds", 2, 60);
  return Object.freeze({
    heartbeatSeconds,
    idleSeconds: safeInteger(input.idleSeconds ?? 30, "idleSeconds", heartbeatSeconds, 900),
    maxCreditedGapSeconds: safeInteger(
      input.maxCreditedGapSeconds ?? Math.max(10, heartbeatSeconds * 2),
      "maxCreditedGapSeconds",
      heartbeatSeconds,
      120,
    ),
  });
}

function normalizeAccessibilityAlternative(value) {
  if (value === undefined) return undefined;
  const input = strictDefinitionObject(value, "accessibility alternative", ["label", "url"]);
  return Object.freeze({
    label: boundedDefinitionString(input.label, "accessibilityAlternative.label", 2, 160),
    url: input.url ? safeURL(input.url, "accessibilityAlternative.url").href : undefined,
  });
}

function normalizeVersion(input) {
  const nested = input.version === undefined
    ? {}
    : strictDefinitionObject(input.version, "media version", ["cTag", "checksum", "eTag", "id", "lastModifiedAt"]);
  return Object.freeze({
    cTag: optionalDefinitionString(nested.cTag, "version.cTag", 512),
    checksum: optionalDefinitionString(nested.checksum || input.checksum, "version.checksum", 512),
    eTag: optionalDefinitionString(nested.eTag, "version.eTag", 512),
    id: optionalDefinitionString(nested.id, "version.id", 512),
    lastModifiedAt: normalizeDate(nested.lastModifiedAt || input.lastModifiedAt, "version.lastModifiedAt"),
  });
}

function normalizeDimensions(value) {
  if (value === undefined) return undefined;
  const input = strictDefinitionObject(value, "media dimensions", ["height", "width"]);
  return Object.freeze({
    height: safeInteger(input.height, "dimensions.height", 1, 100_000),
    width: safeInteger(input.width, "dimensions.width", 1, 100_000),
  });
}

function normalizeMediaEvent(value, index) {
  const input = strictTelemetryObject(value, `media event ${index + 1}`, [
    "detail", "durationSeconds", "fromSeconds", "id", "monotonicMs", "playbackRate",
    "positionSeconds", "sequence", "toSeconds", "type",
  ]);
  const type = responseToken(input.type, "event.type", 64);
  if (!MEDIA_EVENT_TYPES.includes(type)) invalidTelemetry("The media event type is unsupported.");
  const event = {
    detail: normalizeEventDetail(input.detail),
    durationMilliseconds: optionalTelemetryMilliseconds(input.durationSeconds, "durationSeconds", 0, 604_800),
    fromMilliseconds: optionalTelemetryMilliseconds(input.fromSeconds, "fromSeconds", 0, 604_800),
    id: responseToken(input.id, "event.id", 128),
    monotonicMs: safeTelemetryInteger(input.monotonicMs, "monotonicMs", 0, 604_800_000),
    playbackRateMilli: optionalTelemetryRate(input.playbackRate, "playbackRate"),
    positionMilliseconds: optionalTelemetryMilliseconds(input.positionSeconds, "positionSeconds", 0, 604_800),
    sequence: safeTelemetryInteger(input.sequence, "sequence", 1, 10_000_000),
    toMilliseconds: optionalTelemetryMilliseconds(input.toSeconds, "toSeconds", 0, 604_800),
    type,
  };
  if (type === "position" && event.positionMilliseconds === undefined) {
    invalidTelemetry("A position event requires positionSeconds.");
  }
  if (type === "seek" && (event.fromMilliseconds === undefined || event.toMilliseconds === undefined)) {
    invalidTelemetry("A seek event requires fromSeconds and toSeconds.");
  }
  if (type === "rate" && event.playbackRateMilli === undefined) {
    invalidTelemetry("A rate event requires playbackRate.");
  }
  return Object.freeze(event);
}

function normalizeStoredEvent(row) {
  const event = row.event || row.eventData || row;
  return {
    ...event,
    durationMilliseconds: event.durationMilliseconds ?? secondsToMilliseconds(event.durationSeconds),
    fromMilliseconds: event.fromMilliseconds ?? secondsToMilliseconds(event.fromSeconds),
    interactionId: row.interactionId || event.interactionId,
    playbackRateMilli: event.playbackRateMilli ?? rateToMilli(event.playbackRate),
    positionMilliseconds: event.positionMilliseconds ?? secondsToMilliseconds(event.positionSeconds),
    telemetrySessionId: row.telemetrySessionId || event.telemetrySessionId,
    monotonicMs: Number(event.monotonicMs),
    sequence: Number(event.sequence),
    toMilliseconds: event.toMilliseconds ?? secondsToMilliseconds(event.toSeconds),
  };
}

function allowedEventTypes(capability) {
  if (capability === "instrumented_player") return new Set([...FRAME_EVENTS, ...PLAYER_EVENTS]);
  if (["version_aware_preview", "generic_embed"].includes(capability)) return FRAME_EVENTS;
  return LINK_EVENTS;
}

function intervalUnionMilliseconds(intervals) {
  const normalized = intervals
    .map(([start, end]) => [Math.max(0, start), Math.max(0, end)])
    .filter(([start, end]) => end > start)
    .sort((left, right) => left[0] - right[0]);
  let total = 0;
  let current;
  for (const interval of normalized) {
    if (!current) current = [...interval];
    else if (interval[0] <= current[1]) current[1] = Math.max(current[1], interval[1]);
    else {
      total += current[1] - current[0];
      current = [...interval];
    }
  }
  if (current) total += current[1] - current[0];
  return total;
}

function consistentDuration(values) {
  const valid = values.filter((value) => Number.isFinite(value) && value > 0);
  if (!valid.length) return undefined;
  const candidate = valid.at(-1);
  const tolerance = Math.max(1, candidate * 0.01);
  return valid.every((value) => Math.abs(value - candidate) <= tolerance) ? candidate : undefined;
}

function providerLimitations(version) {
  return hasStableVersion(version)
    ? ["VASI binds the supplied provider change token but does not possess or hash the external media bytes."]
    : ["The provider supplied no stable version or content digest; VASI cannot prove the exact media bytes shown."];
}

function hasStableVersion(version) {
  return Boolean(version.id || version.eTag || version.cTag || version.checksum);
}

function youtubeId(source, supplied) {
  let candidate = supplied;
  const host = source.hostname.toLowerCase().replace(/^www\./, "");
  if (host === "youtu.be") candidate ||= source.pathname.split("/").filter(Boolean)[0];
  else if (["youtube.com", "m.youtube.com", "music.youtube.com", "youtube-nocookie.com"].includes(host)) {
    candidate ||= source.searchParams.get("v") || source.pathname.match(/\/(?:embed|shorts|live)\/([^/?]+)/)?.[1];
  } else invalidDefinition("The YouTube source host is unsupported.");
  if (typeof candidate !== "string" || !/^[A-Za-z0-9_-]{11}$/.test(candidate)) {
    invalidDefinition("The YouTube video ID is invalid.");
  }
  return candidate;
}

function vimeoId(source, supplied) {
  requireHost(source, (host) => host === "vimeo.com" || host === "www.vimeo.com" || host === "player.vimeo.com");
  const candidate = supplied || source.pathname.match(/(?:\/video)?\/(\d{6,12})(?:\/|$)/)?.[1];
  if (typeof candidate !== "string" || !/^\d{6,12}$/.test(candidate)) {
    invalidDefinition("The Vimeo video ID is invalid.");
  }
  return candidate;
}

function googleDriveId(source, supplied) {
  const candidate = supplied || source.pathname.match(/\/d\/([A-Za-z0-9_-]{10,200})/)?.[1] || source.searchParams.get("id");
  if (typeof candidate !== "string" || !/^[A-Za-z0-9_-]{10,200}$/.test(candidate)) {
    invalidDefinition("The Google Drive item ID is invalid.");
  }
  return candidate;
}

function requiredItemId(value, provider) {
  const itemId = optionalDefinitionString(value, "descriptor.itemId", 512);
  if (!itemId) invalidDefinition(`${provider} media requires a stable item ID.`);
  return itemId;
}

function safeURL(value, field) {
  if (typeof value !== "string" || value.length > 2_048) invalidDefinition(`${field} is invalid.`);
  let url;
  try {
    url = new URL(value);
  } catch {
    invalidDefinition(`${field} is invalid.`);
  }
  if (url.protocol !== "https:" || url.username || url.password || (url.port && url.port !== "443")) {
    invalidDefinition(`${field} must be a credential-free HTTPS URL.`);
  }
  url.hash = "";
  return url;
}

function requireHost(url, predicate) {
  if (!predicate(url.hostname.toLowerCase())) invalidDefinition("The media source host is unsupported for this provider.");
}

function normalizeConfiguredOrigin(value) {
  const url = safeURL(value, "configured media origin");
  if (url.pathname !== "/" || url.search) invalidDefinition("A configured media origin cannot include a path or query.");
  return url.origin;
}

function normalizeAccessMode(value) {
  const mode = value || "provider_shared";
  if (!['public', 'provider_shared', 'provider_authenticated'].includes(mode)) {
    invalidDefinition("The media access mode is unsupported.");
  }
  return mode;
}

function normalizeDate(value, field) {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") invalidDefinition(`${field} is invalid.`);
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) invalidDefinition(`${field} is invalid.`);
  return date.toISOString();
}

function normalizeEventDetail(value) {
  if (value === undefined) return undefined;
  const input = strictTelemetryObject(value, "event detail", ["code", "message", "providerEvent"]);
  return Object.freeze({
    code: optionalResponseString(input.code, 128),
    message: optionalResponseString(input.message, 500),
    providerEvent: optionalResponseString(input.providerEvent, 128),
  });
}

function strictDefinitionObject(value, name, allowedKeys) {
  if (!value || Array.isArray(value) || typeof value !== "object") invalidDefinition(`The ${name} must be an object.`);
  for (const key of Object.keys(value)) {
    if (!allowedKeys.includes(key)) invalidDefinition(`The ${name} field ${key} is unsupported.`);
  }
  return value;
}

function strictTelemetryObject(value, name, allowedKeys) {
  if (!value || Array.isArray(value) || typeof value !== "object") invalidTelemetry(`The ${name} must be an object.`);
  for (const key of Object.keys(value)) {
    if (!allowedKeys.includes(key)) invalidTelemetry(`The ${name} field ${key} is unsupported.`);
  }
  return value;
}

function boundedDefinitionString(value, field, minimum, maximum) {
  if (typeof value !== "string") invalidDefinition(`${field} must be a string.`);
  const result = value.trim();
  if (result.length < minimum || result.length > maximum) {
    invalidDefinition(`${field} must contain ${minimum} to ${maximum} characters.`);
  }
  return result;
}

function optionalDefinitionString(value, field, maximum) {
  if (value === undefined || value === null || value === "") return undefined;
  return boundedDefinitionString(value, field, 1, maximum);
}

function responseToken(value, field, maximum) {
  if (typeof value !== "string" || !value.trim() || value.length > maximum || /[\u0000-\u001f]/.test(value)) {
    invalidTelemetry(`${field} is invalid.`);
  }
  return value;
}

function optionalResponseString(value, maximum) {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || value.length > maximum || /\u0000/.test(value)) {
    invalidTelemetry("An event detail value is invalid.");
  }
  return value;
}

function safeInteger(value, field, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalidDefinition(`${field} must be a whole number between ${minimum} and ${maximum}.`);
  }
  return value;
}

function safeTelemetryInteger(value, field, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalidTelemetry(`${field} is outside the allowed range.`);
  }
  return value;
}

function optionalDurationMilliseconds(value, field) {
  if (value === undefined || value === null) return undefined;
  if (!Number.isFinite(value) || value < 0.25 || value > 604_800) {
    invalidDefinition(`${field} is outside the allowed range.`);
  }
  return Math.round(value * 1_000);
}

function optionalTelemetryMilliseconds(value, field, minimum, maximum) {
  if (value === undefined || value === null) return undefined;
  if (!Number.isFinite(value) || value < minimum || value > maximum) {
    invalidTelemetry(`${field} is outside the allowed range.`);
  }
  return Math.round(value * 1_000);
}

function optionalTelemetryRate(value, field) {
  if (value === undefined || value === null) return undefined;
  if (!Number.isFinite(value) || value < 0.1 || value > 16) {
    invalidTelemetry(`${field} is outside the allowed range.`);
  }
  return Math.round(value * 1_000);
}

function secondsToMilliseconds(value) {
  return Number.isFinite(value) ? Math.round(value * 1_000) : undefined;
}

function rateToMilli(value) {
  return Number.isFinite(value) ? Math.round(value * 1_000) : undefined;
}

function invalidDefinition(message) {
  const error = new Error(message);
  error.code = "INVALID_WORKFLOW";
  throw error;
}

function invalidTelemetry(message) {
  const error = new Error(message);
  error.code = "INVALID_MEDIA_TELEMETRY";
  throw error;
}
