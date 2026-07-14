export const ACTIVITY_INTERACTION_EVENT_TYPES = Object.freeze([
  "presented",
  "visible",
  "hidden",
  "focus",
  "blur",
  "heartbeat",
  "interaction",
  "disconnect",
]);

export const ACTIVITY_INTERACTION_POLICY_VERSION = "vasi-activity-interaction-policy/v1";
export const ACTIVITY_INTERACTION_SUMMARY_SCHEMA = "vasi-activity-interaction-summary/v1";

const EVENT_TYPES = new Set(ACTIVITY_INTERACTION_EVENT_TYPES);
const DAY_MILLISECONDS = 86_400_000;

export function activityInteractionPolicy(settings = {}) {
  const heartbeatSeconds = settingInteger(
    settings.ENGINE_ACTIVITY_HEARTBEAT_SECONDS,
    10,
    2,
    60,
    "ENGINE_ACTIVITY_HEARTBEAT_SECONDS",
  );
  const idleSeconds = settingInteger(
    settings.ENGINE_ACTIVITY_IDLE_SECONDS,
    60,
    heartbeatSeconds,
    900,
    "ENGINE_ACTIVITY_IDLE_SECONDS",
  );
  const maxCreditedGapSeconds = settingInteger(
    settings.ENGINE_ACTIVITY_MAX_CREDITED_GAP_SECONDS,
    20,
    heartbeatSeconds,
    120,
    "ENGINE_ACTIVITY_MAX_CREDITED_GAP_SECONDS",
  );
  return Object.freeze({
    heartbeatSeconds,
    idleSeconds,
    maxCreditedGapSeconds,
    version: ACTIVITY_INTERACTION_POLICY_VERSION,
  });
}

export function validateActivityInteractionBatch(value) {
  const input = strictObject(value, "activity interaction batch", [
    "activityId",
    "batchId",
    "events",
    "handle",
    "interactionId",
    "telemetrySessionId",
  ]);
  if (!Array.isArray(input.events) || !input.events.length || input.events.length > 100) {
    invalid("An activity interaction batch requires 1 to 100 events.");
  }
  const events = input.events.map((event, index) => normalizeEvent(event, index));
  for (let index = 1; index < events.length; index += 1) {
    if (events[index].sequence <= events[index - 1].sequence ||
        events[index].monotonicMs < events[index - 1].monotonicMs) {
      invalid("Activity interaction sequence and monotonic time must increase within a batch.");
    }
  }
  if (new Set(events.map((event) => event.id)).size !== events.length) {
    invalid("An activity interaction event ID cannot repeat within a batch.");
  }
  return Object.freeze({
    activityId: token(input.activityId, "activityId", 64),
    batchId: token(input.batchId, "batchId", 128),
    events: Object.freeze(events),
    handle: token(input.handle, "handle", 64),
    interactionId: token(input.interactionId, "interactionId", 128),
    telemetrySessionId: token(input.telemetrySessionId, "telemetrySessionId", 128),
  });
}

export function calculateActivityInteractionSummary(policyValue, rows) {
  const policy = normalizedPolicy(policyValue);
  if (!Array.isArray(rows) || rows.length > 100_000) invalid("Stored activity interaction events are invalid or unbounded.");
  const events = rows.map(normalizeStoredEvent);
  const grouped = new Map();
  for (const event of events) {
    const group = grouped.get(event.telemetrySessionId) || [];
    group.push(event);
    grouped.set(event.telemetrySessionId, group);
  }

  let openMilliseconds = 0;
  let foregroundVisibleMilliseconds = 0;
  let engagedMilliseconds = 0;
  let uncreditedGapMilliseconds = 0;
  let gapCount = 0;
  let disconnectCount = 0;
  let incompleteSessionCount = 0;
  let presentedCount = 0;
  let heartbeatCount = 0;
  let visibleCount = 0;
  let focusCount = 0;
  let interactionCount = 0;
  const receivedTimes = [];
  const clientTimes = [];

  for (const group of grouped.values()) {
    group.sort((left, right) => left.sequence - right.sequence);
    let previous;
    let opened = false;
    let visible = false;
    let focused = false;
    let lastInteractionMs;
    let sawPresented = false;

    for (const event of group) {
      receivedTimes.push(event.receivedAt);
      if (event.clientOccurredAt) clientTimes.push(event.clientOccurredAt);
      if (previous) {
        const deltaMilliseconds = event.monotonicMs - previous.monotonicMs;
        if (opened && (deltaMilliseconds < 0 || deltaMilliseconds > policy.maxCreditedGapSeconds * 1_000)) {
          gapCount += 1;
          uncreditedGapMilliseconds += Math.max(0, deltaMilliseconds);
        } else if (opened) {
          openMilliseconds += deltaMilliseconds;
          if (visible && focused) {
            foregroundVisibleMilliseconds += deltaMilliseconds;
            if (lastInteractionMs !== undefined &&
                previous.monotonicMs - lastInteractionMs <= policy.idleSeconds * 1_000) {
              engagedMilliseconds += deltaMilliseconds;
            }
          }
        }
      }

      if (event.type === "presented") {
        opened = true;
        sawPresented = true;
        presentedCount += 1;
      } else if (event.type === "visible") {
        visible = true;
        visibleCount += 1;
      } else if (event.type === "hidden") {
        visible = false;
      } else if (event.type === "focus") {
        focused = true;
        focusCount += 1;
      } else if (event.type === "blur") {
        focused = false;
      } else if (event.type === "heartbeat") {
        heartbeatCount += 1;
      } else if (event.type === "interaction") {
        lastInteractionMs = event.monotonicMs;
        interactionCount += 1;
      } else if (event.type === "disconnect") {
        opened = false;
        visible = false;
        focused = false;
        disconnectCount += 1;
      }
      previous = event;
    }
    if (sawPresented && opened) incompleteSessionCount += 1;
  }

  const limitations = [
    "Activity presence is browser-reported supporting evidence and can be absent, reduced, automated, or spoofed.",
    "Foreground visibility and coarse interaction do not prove attention, comprehension, identity, or freedom from coercion.",
    "VASI records only coarse interaction occurrence; it does not retain keys pressed, pointer coordinates, or input contents in this telemetry.",
    "Intervals longer than the credited-gap policy are excluded rather than treated as continuous activity.",
  ];
  if (!presentedCount) limitations.push("No browser presentation event was received.");
  if (!heartbeatCount) limitations.push("No periodic heartbeat was received, so duration evidence is limited.");
  if (!visibleCount) limitations.push("No foreground-visible activity event was received.");
  if (!focusCount) limitations.push("No focused-window activity event was received.");
  if (incompleteSessionCount) limitations.push("One or more telemetry sessions ended without a recorded disconnect.");
  if (gapCount) limitations.push("One or more missing or oversized telemetry intervals received no duration credit.");

  return Object.freeze({
    calculation: Object.freeze({
      clock: "browser_monotonic",
      policyVersion: policy.version,
      telemetryPolicy: Object.freeze({
        heartbeatSeconds: policy.heartbeatSeconds,
        idleSeconds: policy.idleSeconds,
        maxCreditedGapSeconds: policy.maxCreditedGapSeconds,
      }),
    }),
    confidence: Object.freeze({
      level: presentedCount > 0 && heartbeatCount > 0 && visibleCount > 0 && focusCount > 0 &&
          gapCount === 0 && incompleteSessionCount === 0
        ? "medium"
        : "low",
      limitations: Object.freeze(limitations),
    }),
    events: Object.freeze({
      count: events.length,
      firstClientOccurredAt: earliest(clientTimes),
      firstReceivedAt: earliest(receivedTimes),
      heartbeatCount,
      focusCount,
      interactionCount,
      lastClientOccurredAt: latest(clientTimes),
      lastReceivedAt: latest(receivedTimes),
      presentedCount,
      visibleCount,
    }),
    schema: ACTIVITY_INTERACTION_SUMMARY_SCHEMA,
    sessions: Object.freeze({
      count: grouped.size,
      disconnectCount,
      incompleteCount: incompleteSessionCount,
    }),
    timing: Object.freeze({
      backgroundOrHiddenMilliseconds: Math.max(0, openMilliseconds - foregroundVisibleMilliseconds),
      engagedMilliseconds,
      foregroundVisibleMilliseconds,
      idleForegroundMilliseconds: Math.max(0, foregroundVisibleMilliseconds - engagedMilliseconds),
      openMilliseconds,
      uncreditedGapMilliseconds,
    }),
  });
}

function normalizeEvent(value, index) {
  const input = strictObject(value, `activity interaction event ${index + 1}`, [
    "clientOccurredAt",
    "id",
    "monotonicMs",
    "sequence",
    "type",
  ]);
  if (!EVENT_TYPES.has(input.type)) invalid("The activity interaction event type is unsupported.");
  return Object.freeze({
    clientOccurredAt: optionalCanonicalTimestamp(input.clientOccurredAt),
    id: token(input.id, "event.id", 128),
    monotonicMs: integer(input.monotonicMs, "event.monotonicMs", 0, 7 * DAY_MILLISECONDS),
    sequence: integer(input.sequence, "event.sequence", 1, 100_000),
    type: input.type,
  });
}

function normalizeStoredEvent(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid("A stored activity interaction event is invalid.");
  const type = value.eventType || value.type || value.eventData?.type || value.event?.type;
  if (!EVENT_TYPES.has(type)) invalid("A stored activity interaction event type is unsupported.");
  return Object.freeze({
    clientOccurredAt: optionalCanonicalTimestamp(
      value.eventData?.clientOccurredAt || value.event?.clientOccurredAt || value.clientOccurredAt,
    ),
    monotonicMs: integer(
      Number(value.monotonicMs ?? value.eventData?.monotonicMs ?? value.event?.monotonicMs),
      "stored.monotonicMs",
      0,
      7 * DAY_MILLISECONDS,
    ),
    receivedAt: storedTimestamp(value.receivedAt, "stored.receivedAt"),
    sequence: integer(Number(value.sequence), "stored.sequence", 1, 100_000),
    telemetrySessionId: token(value.telemetrySessionId, "stored.telemetrySessionId", 128),
    type,
  });
}

function normalizedPolicy(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid("The activity interaction policy is invalid.");
  const heartbeatSeconds = integer(value.heartbeatSeconds, "policy.heartbeatSeconds", 2, 60);
  return Object.freeze({
    heartbeatSeconds,
    idleSeconds: integer(value.idleSeconds, "policy.idleSeconds", heartbeatSeconds, 900),
    maxCreditedGapSeconds: integer(value.maxCreditedGapSeconds, "policy.maxCreditedGapSeconds", heartbeatSeconds, 120),
    version: value.version === ACTIVITY_INTERACTION_POLICY_VERSION
      ? value.version
      : invalid("The activity interaction policy version is unsupported."),
  });
}

function strictObject(value, name, allowed) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(`The ${name} must be an object.`);
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length) invalid(`The ${name} contains unsupported fields.`);
  return value;
}

function token(value, name, maximum) {
  if (typeof value !== "string" || !value.length || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) {
    invalid(`The ${name} is invalid.`);
  }
  return value;
}

function settingInteger(value, fallback, minimum, maximum, name) {
  const parsed = value === undefined || value === null || value === "" ? fallback : Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`VASI setting ${name} must be between ${minimum} and ${maximum}.`);
  }
  return parsed;
}

function integer(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) invalid(`The ${name} is invalid.`);
  return value;
}

function optionalCanonicalTimestamp(value) {
  return value === undefined || value === null ? undefined : canonicalTimestamp(value, "event.clientOccurredAt");
}

function canonicalTimestamp(value, name) {
  if (typeof value !== "string") invalid(`The ${name} is invalid.`);
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) invalid(`The ${name} is invalid.`);
  return value;
}

function storedTimestamp(value, name) {
  if (value instanceof Date && Number.isFinite(value.getTime())) return value.toISOString();
  return canonicalTimestamp(value, name);
}

function earliest(values) {
  return values.length ? [...values].sort()[0] : undefined;
}

function latest(values) {
  return values.length ? [...values].sort().at(-1) : undefined;
}

function invalid(message) {
  const error = new Error(message);
  error.code = "INVALID_ACTIVITY_INTERACTION";
  throw error;
}
