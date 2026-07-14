export const PARTICIPANT_CONTEXT_SCHEMA = "vasi-participant-context/v1";
export const PARTICIPANT_CONTEXT_POLICY_VERSION = "vasi-participant-context-policy/v1";

export const PARTICIPANT_CONTEXT_EXCLUDED_SIGNALS = Object.freeze([
  "plugin_or_font_enumeration",
  "canvas_webgl_audio_or_gpu_fingerprints",
  "precise_geolocation",
  "hardware_or_advertising_identifiers",
  "camera_microphone_or_biometric_capture",
  "keystrokes_input_contents_or_pointer_coordinates",
  "credentials_tokens_or_reusable_session_secrets",
]);

export const PARTICIPANT_CONTEXT_LIMITATIONS = Object.freeze([
  "Browser-reported context can be absent, reduced, randomized, automated, or spoofed.",
  "Browser and device context is supporting evidence and does not prove identity, attention, comprehension, physical location, or freedom from coercion.",
  "Display, capability, preference, and connection values describe what the browser reported at one observation time and can change later.",
]);

const PURPOSES = new Set(["presentation", "save", "submission"]);
const STORAGE_STATES = new Set(["available", "blocked", "unavailable"]);
const COLOR_SCHEMES = new Set(["dark", "light", "no-preference"]);
const CONTRASTS = new Set(["custom", "less", "more", "no-preference"]);
const EFFECTIVE_TYPES = new Set(["slow-2g", "2g", "3g", "4g"]);
const DAY_MILLISECONDS = 86_400_000;

export function participantContextPolicy(settings = {}) {
  return Object.freeze({
    allowedGroups: Object.freeze([
      "browser_locale_and_time_zone",
      "viewport_and_screen",
      "touch_capability",
      "cookie_storage_and_pdf_capability",
      "accessibility_and_display_preferences",
      "online_and_coarse_connection_state",
    ]),
    excludedSignals: PARTICIPANT_CONTEXT_EXCLUDED_SIGNALS,
    limitations: PARTICIPANT_CONTEXT_LIMITATIONS,
    maxSnapshotsPerActivity: settingInteger(
      settings.ENGINE_PARTICIPANT_CONTEXT_MAX_SNAPSHOTS_PER_ACTIVITY,
      16,
      2,
      64,
      "ENGINE_PARTICIPANT_CONTEXT_MAX_SNAPSHOTS_PER_ACTIVITY",
    ),
    reliabilityClass: "browser_reported",
    version: PARTICIPANT_CONTEXT_POLICY_VERSION,
  });
}

export function validateParticipantContextSubmission(value) {
  const input = strictObject(value, "participant context submission", [
    "activityId",
    "contextSessionId",
    "handle",
    "interactionId",
    "snapshot",
  ]);
  return Object.freeze({
    activityId: token(input.activityId, "activityId", 64),
    contextSessionId: token(input.contextSessionId, "contextSessionId", 128),
    handle: token(input.handle, "handle", 64),
    interactionId: token(input.interactionId, "interactionId", 128),
    snapshot: normalizeSnapshot(input.snapshot),
  });
}

export function validateStoredParticipantContextSnapshot(value) {
  const input = strictObject(value, "stored participant context snapshot", [
    "browser",
    "capabilities",
    "clientOccurredAt",
    "connection",
    "display",
    "id",
    "input",
    "monotonicMs",
    "preferences",
    "provenance",
    "purpose",
    "schema",
    "sequence",
  ]);
  validateProvenance(input.provenance);
  const snapshot = { ...input };
  delete snapshot.provenance;
  return withParticipantContextProvenance(normalizeSnapshot(snapshot));
}

export function withParticipantContextProvenance(snapshot) {
  return Object.freeze({
    ...snapshot,
    provenance: Object.freeze({
      collectionMethod: "vasi-browser-context/v1",
      limitations: PARTICIPANT_CONTEXT_LIMITATIONS,
      reliabilityClass: "browser_reported",
      source: "browser_api",
    }),
  });
}

function normalizeSnapshot(value) {
  const input = strictObject(value, "participant context snapshot", [
    "browser",
    "capabilities",
    "clientOccurredAt",
    "connection",
    "display",
    "id",
    "input",
    "monotonicMs",
    "preferences",
    "purpose",
    "schema",
    "sequence",
  ]);
  if (input.schema !== PARTICIPANT_CONTEXT_SCHEMA) {
    invalid("The participant context schema is unsupported.");
  }
  if (!PURPOSES.has(input.purpose)) invalid("The participant context purpose is unsupported.");
  const normalized = Object.freeze({
    browser: optionalBrowser(input.browser),
    capabilities: optionalCapabilities(input.capabilities),
    clientOccurredAt: canonicalTimestamp(input.clientOccurredAt, "snapshot.clientOccurredAt"),
    connection: optionalConnection(input.connection),
    display: optionalDisplay(input.display),
    id: token(input.id, "snapshot.id", 128),
    input: optionalInput(input.input),
    monotonicMs: integer(input.monotonicMs, "snapshot.monotonicMs", 0, 7 * DAY_MILLISECONDS),
    preferences: optionalPreferences(input.preferences),
    purpose: input.purpose,
    schema: PARTICIPANT_CONTEXT_SCHEMA,
    sequence: integer(input.sequence, "snapshot.sequence", 1, 64),
  });
  if (![normalized.browser, normalized.capabilities, normalized.connection, normalized.display,
    normalized.input, normalized.preferences].some(hasDefinedValue)) {
    invalid("The participant context snapshot has no supported context values.");
  }
  return normalized;
}

function optionalBrowser(value) {
  if (value === undefined || value === null) return undefined;
  const input = strictObject(value, "participant context browser group", [
    "language",
    "languages",
    "online",
    "timeZone",
  ]);
  let languages;
  if (input.languages !== undefined) {
    if (!Array.isArray(input.languages) || !input.languages.length || input.languages.length > 8) {
      invalid("The participant context languages are invalid.");
    }
    languages = Object.freeze(input.languages.map((entry) => text(entry, "browser.languages[]", 35)));
    if (new Set(languages).size !== languages.length) {
      invalid("The participant context languages cannot repeat.");
    }
  }
  const result = Object.freeze({
    language: optionalText(input.language, "browser.language", 35),
    languages,
    online: optionalBoolean(input.online, "browser.online"),
    timeZone: optionalText(input.timeZone, "browser.timeZone", 100),
  });
  return requireNonemptyGroup(result, "browser");
}

function optionalCapabilities(value) {
  if (value === undefined || value === null) return undefined;
  const input = strictObject(value, "participant context capabilities group", [
    "cookiesEnabled",
    "localStorage",
    "pdfViewerEnabled",
    "sessionStorage",
  ]);
  const result = Object.freeze({
    cookiesEnabled: optionalBoolean(input.cookiesEnabled, "capabilities.cookiesEnabled"),
    localStorage: optionalEnum(input.localStorage, STORAGE_STATES, "capabilities.localStorage"),
    pdfViewerEnabled: optionalBoolean(input.pdfViewerEnabled, "capabilities.pdfViewerEnabled"),
    sessionStorage: optionalEnum(input.sessionStorage, STORAGE_STATES, "capabilities.sessionStorage"),
  });
  return requireNonemptyGroup(result, "capabilities");
}

function optionalDisplay(value) {
  if (value === undefined || value === null) return undefined;
  const input = strictObject(value, "participant context display group", [
    "availableHeight",
    "availableWidth",
    "colorDepth",
    "devicePixelRatio",
    "pixelDepth",
    "screenHeight",
    "screenWidth",
    "viewportHeight",
    "viewportWidth",
  ]);
  const result = Object.freeze({
    availableHeight: optionalInteger(input.availableHeight, "display.availableHeight", 0, 32_768),
    availableWidth: optionalInteger(input.availableWidth, "display.availableWidth", 0, 32_768),
    colorDepth: optionalInteger(input.colorDepth, "display.colorDepth", 1, 64),
    devicePixelRatio: optionalNumber(input.devicePixelRatio, "display.devicePixelRatio", 0.1, 16),
    pixelDepth: optionalInteger(input.pixelDepth, "display.pixelDepth", 1, 64),
    screenHeight: optionalInteger(input.screenHeight, "display.screenHeight", 1, 32_768),
    screenWidth: optionalInteger(input.screenWidth, "display.screenWidth", 1, 32_768),
    viewportHeight: optionalInteger(input.viewportHeight, "display.viewportHeight", 1, 32_768),
    viewportWidth: optionalInteger(input.viewportWidth, "display.viewportWidth", 1, 32_768),
  });
  return requireNonemptyGroup(result, "display");
}

function optionalInput(value) {
  if (value === undefined || value === null) return undefined;
  const input = strictObject(value, "participant context input group", ["maxTouchPoints"]);
  const result = Object.freeze({
    maxTouchPoints: optionalInteger(input.maxTouchPoints, "input.maxTouchPoints", 0, 32),
  });
  return requireNonemptyGroup(result, "input");
}

function optionalPreferences(value) {
  if (value === undefined || value === null) return undefined;
  const input = strictObject(value, "participant context preferences group", [
    "colorScheme",
    "contrast",
    "forcedColors",
    "reducedMotion",
  ]);
  const result = Object.freeze({
    colorScheme: optionalEnum(input.colorScheme, COLOR_SCHEMES, "preferences.colorScheme"),
    contrast: optionalEnum(input.contrast, CONTRASTS, "preferences.contrast"),
    forcedColors: optionalBoolean(input.forcedColors, "preferences.forcedColors"),
    reducedMotion: optionalBoolean(input.reducedMotion, "preferences.reducedMotion"),
  });
  return requireNonemptyGroup(result, "preferences");
}

function optionalConnection(value) {
  if (value === undefined || value === null) return undefined;
  const input = strictObject(value, "participant context connection group", [
    "downlinkMbps",
    "effectiveType",
    "rttMs",
    "saveData",
  ]);
  const result = Object.freeze({
    downlinkMbps: optionalNumber(input.downlinkMbps, "connection.downlinkMbps", 0, 10_000),
    effectiveType: optionalEnum(input.effectiveType, EFFECTIVE_TYPES, "connection.effectiveType"),
    rttMs: optionalInteger(input.rttMs, "connection.rttMs", 0, 60_000),
    saveData: optionalBoolean(input.saveData, "connection.saveData"),
  });
  return requireNonemptyGroup(result, "connection");
}

function validateProvenance(value) {
  const input = strictObject(value, "participant context provenance", [
    "collectionMethod",
    "limitations",
    "reliabilityClass",
    "source",
  ]);
  if (input.collectionMethod !== "vasi-browser-context/v1" ||
      input.reliabilityClass !== "browser_reported" || input.source !== "browser_api" ||
      !Array.isArray(input.limitations) ||
      input.limitations.length !== PARTICIPANT_CONTEXT_LIMITATIONS.length ||
      input.limitations.some((entry, index) => entry !== PARTICIPANT_CONTEXT_LIMITATIONS[index])) {
    invalid("The participant context provenance is invalid.");
  }
}

function strictObject(value, name, allowed) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(`The ${name} must be an object.`);
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    invalid(`The ${name} contains unsupported fields.`);
  }
  return value;
}

function requireNonemptyGroup(value, name) {
  if (!hasDefinedValue(value)) invalid(`The participant context ${name} group is empty.`);
  return value;
}

function hasDefinedValue(value) {
  return Boolean(value && Object.values(value).some((entry) => entry !== undefined));
}

function token(value, name, maximum) {
  if (typeof value !== "string" || !value.length || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) {
    invalid(`The participant context ${name} is invalid.`);
  }
  return value;
}

function text(value, name, maximum) {
  if (typeof value !== "string" || !value.trim() || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) {
    invalid(`The participant context ${name} is invalid.`);
  }
  return value;
}

function optionalText(value, name, maximum) {
  return value === undefined || value === null ? undefined : text(value, name, maximum);
}

function optionalBoolean(value, name) {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "boolean") invalid(`The participant context ${name} is invalid.`);
  return value;
}

function optionalEnum(value, allowed, name) {
  if (value === undefined || value === null) return undefined;
  if (!allowed.has(value)) invalid(`The participant context ${name} is invalid.`);
  return value;
}

function integer(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalid(`The participant context ${name} is invalid.`);
  }
  return value;
}

function optionalInteger(value, name, minimum, maximum) {
  return value === undefined || value === null ? undefined : integer(value, name, minimum, maximum);
}

function optionalNumber(value, name, minimum, maximum) {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isFinite(value) || value < minimum || value > maximum) {
    invalid(`The participant context ${name} is invalid.`);
  }
  return value;
}

function canonicalTimestamp(value, name) {
  if (typeof value !== "string") invalid(`The participant context ${name} is invalid.`);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    invalid(`The participant context ${name} is invalid.`);
  }
  return value;
}

function settingInteger(value, fallback, minimum, maximum, name) {
  const parsed = value === undefined || value === null || value === "" ? fallback : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`VASI setting ${name} must be between ${minimum} and ${maximum}.`);
  }
  return parsed;
}

function invalid(message) {
  const error = new Error(message);
  error.code = "INVALID_PARTICIPANT_CONTEXT";
  throw error;
}
