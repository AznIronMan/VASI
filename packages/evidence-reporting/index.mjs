import { canonicalJSON, hashCanonicalJSON } from "../engine-crypto/index.mjs";

export const EVIDENCE_REPORT_GENERATOR = "vasi-evidence-reporting/1";
export const EVIDENCE_REPORT_TEMPLATE = "vasi-evidence-report/v1";

export function buildEvidenceReports(record) {
  const context = reportContext(record);
  return Object.freeze({
    nontechnical: buildReport("nontechnical", context),
    participant: buildReport("participant", context),
    structured: buildReport("structured", context),
    technical: buildReport("technical", context),
  });
}

export function renderEvidenceReport(report, format) {
  if (format === "json") {
    return Buffer.from(`${JSON.stringify(JSON.parse(canonicalJSON(report)), null, 2)}\n`, "utf8");
  }
  const text = reportText(report);
  if (format === "text") return Buffer.from(text, "utf8");
  if (format === "html") return Buffer.from(reportHTML(report, text), "utf8");
  throw new Error("The evidence report format is unsupported.");
}

export function evidenceReportMediaType(format) {
  if (format === "json") return "application/vnd.vasi.evidence-report+json";
  if (format === "text") return "text/plain; charset=utf-8";
  if (format === "html") return "text/html; charset=utf-8";
  throw new Error("The evidence report format is unsupported.");
}

function buildReport(profile, context) {
  const common = {
    eventReferences: context.eventReferences,
    generatedFrom: {
      completedAt: context.completedAt,
      generator: EVIDENCE_REPORT_GENERATOR,
      manifestHash: context.manifestHash,
      manifestSchema: context.manifest.schema,
      template: EVIDENCE_REPORT_TEMPLATE,
    },
    integrity: context.integrity,
    profile,
    schema: EVIDENCE_REPORT_TEMPLATE,
    transaction: context.transaction,
  };
  if (profile === "participant") {
    return Object.freeze({
      ...common,
      explanation: "This report summarizes the participant's completed VASI transaction. It does not expose the full forensic browser and network record.",
      identity: {
        authentication: context.identity.authentication,
        email: context.identity.email,
      },
      activityTiming: context.activityTiming,
      contextEvidence: context.contextEvidence.participant,
      outcomes: context.outcomes,
      requester: context.requester,
    });
  }
  if (profile === "nontechnical") {
    return Object.freeze({
      ...common,
      explanation: "This report explains who requested the activity, who completed it, what occurred, when it occurred, and how the integrity record can be checked.",
      activityTiming: context.activityTiming,
      contextEvidence: context.contextEvidence.narrative,
      identity: context.identity,
      limitations: context.limitations,
      outcomes: context.outcomes,
      requester: context.requester,
      timeline: context.timeline,
    });
  }
  if (profile === "technical") {
    return Object.freeze({
      ...common,
      explanation: "This forensic report preserves complete event, manifest, authentication, server-observed request context, privacy-bounded browser-reported participant context, generalized activity-interaction, media, artifact, response-revision, and seal data available in the sealed record.",
      events: context.record.events,
      limitations: context.limitations,
      manifest: context.manifest,
      seals: context.seals,
      verification: context.verification,
    });
  }
  return Object.freeze({
    ...common,
    explanation: "This structured export contains the sealed record without interpretive or LLM-generated additions.",
    record: context.record,
  });
}

function reportContext(record) {
  const manifest = record.manifest;
  const seals = record.seals?.length ? record.seals : [record.seal];
  const primarySeal = seals.find((seal) => (seal.role || "vasi_integrity") === "vasi_integrity") || seals[0];
  const participantEvents = record.events.filter((event) =>
    event.eventData?.actor?.principalId === manifest.assignment?.principalId,
  );
  const requesterEvent = record.events.find((event) => event.eventData?.eventType === "request.issued");
  const participantActor = participantEvents.find((event) => event.eventData?.actor)?.eventData.actor || {};
  const startedAt = manifest.timestamps?.startedAt;
  const completedAt = manifest.timestamps?.completedAt;
  const durationMilliseconds = timestampDifference(startedAt, completedAt);
  const eventReferences = Object.freeze(record.events.map((event) => Object.freeze({
    eventHash: event.eventHash,
    eventId: event.eventData?.eventId,
    eventType: event.eventData?.eventType,
    receivedAt: event.eventData?.receivedAt,
    sequence: event.sequence,
  })));
  const limitations = evidenceLimitations(manifest);
  const contextEvidence = participantContextSummary(manifest);
  const activityTiming = latestActivityInteractionSummaries(manifest).map((entry) => Object.freeze({
    activityId: entry.activityId,
    confidence: entry.summary?.confidence?.level,
    limitations: entry.summary?.confidence?.limitations || [],
    revision: entry.revision,
    timing: entry.summary?.timing,
  }));
  const outcomes = manifest.outcome?.activities?.length
    ? manifest.outcome.activities
    : manifest.outcome?.response !== undefined
      ? [{
          activityId: manifest.workflow?.id || "response",
          outcome: manifest.outcome.response,
          respondedAt: completedAt,
          response: manifest.outcome.response,
          responseLabel: manifest.outcome.response,
        }]
      : [];
  return {
    activityTiming: Object.freeze(activityTiming),
    completedAt,
    contextEvidence,
    eventReferences,
    identity: {
      authentication: participantActor.authentication || { method: "unspecified" },
      authenticatedAt: participantActor.authenticatedAt,
      email: manifest.assignment?.participantEmail,
      principalId: manifest.assignment?.principalId,
      requestContext: participantActor.requestContext,
    },
    integrity: {
      algorithm: primarySeal.algorithm,
      keyId: primarySeal.keyId,
      manifestHash: primarySeal.manifestHash,
      profile: primarySeal.profile,
      sealCount: seals.length,
      signature: primarySeal.signature,
    },
    limitations,
    manifest,
    manifestHash: primarySeal.manifestHash,
    outcomes: Object.freeze(outcomes.map((activity) => Object.freeze({
      activityId: activity.activityId,
      outcome: activity.outcome,
      respondedAt: activity.respondedAt,
      response: activity.response,
      responseLabel: activity.responseLabel,
      result: activity.result,
    }))),
    record,
    requester: {
      email: requesterEvent?.eventData?.actor?.email,
      principalId: requesterEvent?.eventData?.actor?.principalId,
      tenant: manifest.tenant,
    },
    seals,
    timeline: Object.freeze(record.events.map((event) => Object.freeze({
      at: event.eventData?.receivedAt,
      description: eventDescription(event.eventData?.eventType, event.eventData?.payload),
      eventId: event.eventData?.eventId,
      eventType: event.eventData?.eventType,
      sequence: event.sequence,
    }))),
    transaction: {
      assignmentId: manifest.assignment?.id,
      completedAt,
      durationMilliseconds,
      expiresAt: manifest.request?.expiresAt,
      issuedAt: manifest.timestamps?.issuedAt,
      purpose: manifest.request?.purpose,
      requestId: manifest.request?.id,
      startedAt,
      status: manifest.outcome?.status,
      tenant: manifest.tenant,
      title: manifest.workflow?.title,
      workflowRevision: manifest.workflow?.revision,
    },
    verification: {
      eventCount: record.events.length,
      eventHeadHash: manifest.evidence?.headHash,
      reportHash: undefined,
      result: "cryptographically_verified",
      sealPublicKeys: seals.map((seal) => ({ keyId: seal.keyId, publicJWK: seal.publicJWK })),
    },
  };
}

function evidenceLimitations(manifest) {
  const limitations = [
    "The VASI integrity seal proves that the sealed record has not changed since sealing; it does not by itself decide legal enforceability.",
    "Authentication and browser evidence identify the recorded session but cannot prove a person's attention, comprehension, or freedom from coercion.",
  ];
  for (const descriptor of manifest.media?.descriptors || []) {
    for (const limitation of descriptor.descriptor?.limitations || []) limitations.push(limitation);
  }
  for (const summary of manifest.media?.summaries || []) {
    for (const limitation of summary.summary?.confidence?.limitations || []) limitations.push(limitation);
  }
  for (const summary of manifest.activityInteraction?.summaries || []) {
    for (const limitation of summary.summary?.confidence?.limitations || []) limitations.push(limitation);
  }
  for (const limitation of manifest.participantContext?.policy?.limitations || []) {
    limitations.push(limitation);
  }
  if (["vasi-evidence-manifest/v5", "vasi-evidence-manifest/v6"].includes(manifest.schema) &&
      !(manifest.activityInteraction?.events || []).length) {
    limitations.push("No browser-reported generalized activity-presence events were available when the record was sealed.");
  }
  if (manifest.schema === "vasi-evidence-manifest/v6" &&
      !(manifest.participantContext?.snapshots || []).length) {
    limitations.push("No privacy-bounded browser/device context snapshot was available when the record was sealed.");
  }
  return Object.freeze([...new Set(limitations)]);
}

function eventDescription(eventType, payload) {
  switch (eventType) {
    case "request.issued": return "The company issued the immutable request to the intended participant.";
    case "participant.opened": return "The authenticated participant opened the request.";
    case "participant.responded": return `The participant recorded a response${payload?.activityId ? ` for ${payload.activityId}` : ""}.`;
    case "activity.completed": return `The participant completed activity ${payload?.activityId || "(unspecified)"}.`;
    case "media.telemetry.recorded": return `VASI accepted a bounded media telemetry batch${payload?.activityId ? ` for ${payload.activityId}` : ""}.`;
    case "activity.interaction.recorded": return `VASI accepted a privacy-bounded activity-presence batch${payload?.activityId ? ` for ${payload.activityId}` : ""}.`;
    case "participant.context.recorded": return `VASI recorded a privacy-bounded browser context snapshot${payload?.activityId ? ` for ${payload.activityId}` : ""}.`;
    case "request.completed": return "All required activities completed and VASI sealed the transaction.";
    case "request.revoked": return "The company revoked the request.";
    case "request.reissued": return "The company reissued the request as a new transaction.";
    case "request.reminder": return "The company requested a reminder.";
    default: return `VASI recorded ${eventType || "an unspecified event"}.`;
  }
}

function timestampDifference(start, end) {
  const startTime = Date.parse(start || "");
  const endTime = Date.parse(end || "");
  if (!Number.isFinite(startTime) || !Number.isFinite(endTime) || endTime < startTime) return undefined;
  return endTime - startTime;
}

function reportText(report) {
  const lines = [
    `VASI ${profileTitle(report.profile)} Evidence Report`,
    `Report schema: ${report.schema}`,
    `Source manifest: ${report.generatedFrom.manifestHash}`,
    `Transaction: ${report.transaction.title}`,
    `Company: ${report.transaction.tenant?.name || "Unspecified"}`,
    `Purpose: ${report.transaction.purpose || "Unspecified"}`,
    `Issued: ${report.transaction.issuedAt || "Unspecified"}`,
    `Started: ${report.transaction.startedAt || "Unspecified"}`,
    `Completed: ${report.transaction.completedAt || "Unspecified"}`,
    `Status: ${report.transaction.status || "Unspecified"}`,
    "",
    report.explanation,
  ];
  if (report.requester) {
    lines.push("", "REQUESTER", `Company: ${report.requester.tenant?.name || "Unspecified"}`, `Email: ${report.requester.email || "Unspecified"}`);
  }
  if (report.identity) {
    lines.push("", "PARTICIPANT IDENTITY", `Email: ${report.identity.email || "Unspecified"}`, `Authentication: ${authenticationText(report.identity.authentication)}`);
    if (report.profile !== "participant" && report.identity.requestContext) {
      lines.push(`IP address: ${report.identity.requestContext.ipAddress || "Unavailable"}`, `User agent: ${report.identity.requestContext.userAgent || "Unavailable"}`);
    }
  }
  if (report.outcomes) {
    lines.push("", "RECORDED OUTCOMES");
    for (const outcome of report.outcomes) {
      lines.push(`${outcome.activityId}: ${outcome.responseLabel || printable(outcome.response)}${outcome.outcome ? ` (${outcome.outcome})` : ""}`);
    }
  }
  if (report.activityTiming?.length) {
    lines.push("", "ACTIVITY PRESENCE (BROWSER-REPORTED SUPPORTING EVIDENCE)");
    for (const activity of report.activityTiming) {
      lines.push(
        `${activity.activityId}: open ${durationText(activity.timing?.openMilliseconds)}, ` +
        `foreground-visible ${durationText(activity.timing?.foregroundVisibleMilliseconds)}, ` +
        `engaged ${durationText(activity.timing?.engagedMilliseconds)}, ` +
        `idle foreground ${durationText(activity.timing?.idleForegroundMilliseconds)}, ` +
        `uncredited gaps ${durationText(activity.timing?.uncreditedGapMilliseconds)}; ` +
        `confidence ${activity.confidence || "unavailable"}`,
      );
    }
  }
  if (report.contextEvidence) {
    lines.push(
      "",
      "BROWSER/DEVICE CONTEXT (BROWSER-REPORTED SUPPORTING EVIDENCE)",
      `Snapshots: ${report.contextEvidence.snapshotCount}`,
      `Purposes: ${(report.contextEvidence.purposes || []).join(", ") || "none"}`,
      `Reliability: ${report.contextEvidence.reliabilityClass || "browser_reported"}`,
      report.contextEvidence.explanation,
    );
    if (report.contextEvidence.firstReceivedAt) lines.push(`First received: ${report.contextEvidence.firstReceivedAt}`);
    if (report.contextEvidence.lastReceivedAt) lines.push(`Last received: ${report.contextEvidence.lastReceivedAt}`);
  }
  if (report.timeline) {
    lines.push("", "CHRONOLOGY");
    for (const entry of report.timeline) lines.push(`${entry.sequence}. ${entry.at || "time unavailable"} — ${entry.description} [${entry.eventId}]`);
  }
  if (report.limitations) {
    lines.push("", "LIMITATIONS");
    for (const limitation of report.limitations) lines.push(`- ${limitation}`);
  }
  lines.push("", "INTEGRITY", `Profile: ${report.integrity.profile}`, `Algorithm: ${report.integrity.algorithm}`, `Key: ${report.integrity.keyId}`, `Manifest fingerprint: ${report.integrity.manifestHash}`, "", "EVENT REFERENCES");
  for (const event of report.eventReferences) lines.push(`${event.sequence}. ${event.eventType} ${event.eventId} ${event.eventHash}`);
  if (["technical", "structured"].includes(report.profile)) {
    lines.push("", "STRUCTURED DETAIL", JSON.stringify(JSON.parse(canonicalJSON(report.profile === "structured" ? report.record : { events: report.events, manifest: report.manifest, seals: report.seals })), null, 2));
  }
  return `${lines.join("\n")}\n`;
}

function reportHTML(report, text) {
  const title = `VASI ${profileTitle(report.profile)} Evidence Report`;
  return `<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHTML(title)}</title><style>body{color:#17211d;font:15px/1.55 system-ui,sans-serif;margin:0 auto;max-width:960px;padding:48px}h1{color:#0c4a38}pre{background:#f4f7f5;border:1px solid #d9e2dd;border-radius:8px;overflow-wrap:anywhere;padding:24px;white-space:pre-wrap}@media print{body{max-width:none;padding:0}pre{border:0}}</style></head><body><h1>${escapeHTML(title)}</h1><pre>${escapeHTML(text)}</pre></body></html>\n`;
}

function profileTitle(profile) {
  return ({ participant: "Participant", nontechnical: "Plain-Language", technical: "Technical Forensic", structured: "Structured" })[profile] || profile;
}

function authenticationText(value) {
  if (!value || typeof value !== "object") return "Unspecified";
  return [value.method, value.provider, value.issuer].filter(Boolean).join(" / ") || "Unspecified";
}

function printable(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.join(", ");
  return JSON.stringify(value);
}

function latestActivityInteractionSummaries(manifest) {
  const latest = new Map();
  for (const entry of manifest.activityInteraction?.summaries || []) {
    const previous = latest.get(entry.activityId);
    if (!previous || Number(entry.revision) > Number(previous.revision)) {
      latest.set(entry.activityId, entry);
    }
  }
  return [...latest.values()];
}

function participantContextSummary(manifest) {
  const snapshots = manifest.participantContext?.snapshots || [];
  const received = snapshots.map((entry) => entry.receivedAt).filter(Boolean).sort();
  const purposes = [...new Set(snapshots.map((entry) => entry.purpose).filter(Boolean))].sort();
  const explanation = snapshots.length
    ? "VASI retained fixed, privacy-bounded browser-reported context observations. Ordinary reports summarize their presence; the sealed technical record contains the eligible values and provenance. These observations do not prove identity, attention, comprehension, or physical location."
    : "No browser-reported context snapshot was available. Missing context is not inferred.";
  const common = Object.freeze({
    explanation,
    purposes: Object.freeze(purposes),
    reliabilityClass: manifest.participantContext?.policy?.reliabilityClass || "browser_reported",
    snapshotCount: snapshots.length,
  });
  return Object.freeze({
    narrative: Object.freeze({
      ...common,
      firstReceivedAt: received[0],
      lastReceivedAt: received.at(-1),
    }),
    participant: common,
  });
}

function durationText(value) {
  return Number.isFinite(value) && value >= 0 ? `${Math.round(value)} ms` : "unavailable";
}

function escapeHTML(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

export function evidenceReportHash(report) {
  return hashCanonicalJSON(report);
}
