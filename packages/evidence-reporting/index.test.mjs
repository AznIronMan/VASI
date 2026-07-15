import { describe, expect, it } from "vitest";

import { sealedTestRecord } from "../evidence-verifier/test-fixture.mjs";
import { buildEvidenceReports, evidenceReportHash, renderEvidenceReport } from "./index.mjs";

describe("deterministic evidence reports", () => {
  it("creates participant, plain-language, forensic, and structured reports traced to every event", () => {
    const { record } = sealedTestRecord();
    const reports = buildEvidenceReports(record);
    expect(Object.keys(reports)).toEqual(["nontechnical", "participant", "structured", "technical"]);
    for (const report of Object.values(reports)) {
      expect(report.generatedFrom.manifestHash).toBe(record.seal.manifestHash);
      expect(report.eventReferences).toHaveLength(record.events.length);
      expect(report.eventReferences.map((event) => event.eventId)).toEqual([
        "event-1",
        "event-2",
        "event-3",
        "event-4",
        "event-5",
        "event-6",
      ]);
    }
    expect(JSON.stringify(reports.participant)).not.toContain("192.0.2.20");
    expect(reports.participant.requester.email).toBe("owner@example.test");
    expect(reports.participant.activityTiming[0]).toMatchObject({
      activityId: "terms",
      confidence: "medium",
    });
    expect(reports.participant.contextEvidence).toMatchObject({
      reliabilityClass: "browser_reported",
      snapshotCount: 1,
    });
    expect(JSON.stringify(reports.participant)).not.toContain("viewportWidth");
    expect(JSON.stringify(reports.technical)).toContain("192.0.2.20");
    expect(reports.nontechnical.notificationDelivery.notifications[0]).toMatchObject({
      notificationType: "request.issued",
      status: "provider_accepted",
    });
    expect(reports.nontechnical.productionAdmission).toMatchObject({
      approvedGates: 8,
      requiredGates: 8,
      status: "admitted",
    });
    expect(reports.participant.authenticationAssurance).toMatchObject({
      acceptedMethods: ["federated"],
      evaluationCount: 2,
      maximumAgeSeconds: 900,
    });
    expect(JSON.stringify(reports.participant.notificationDelivery)).not.toContain("notification-job-1");
    const plainText = renderEvidenceReport(reports.nontechnical, "text").toString();
    expect(plainText).toContain("CHRONOLOGY");
    expect(plainText).toContain("ACTIVITY PRESENCE (BROWSER-REPORTED SUPPORTING EVIDENCE)");
    expect(plainText).toContain("BROWSER/DEVICE CONTEXT (BROWSER-REPORTED SUPPORTING EVIDENCE)");
    expect(plainText).toContain("NOTIFICATION DELIVERY (PROVIDER-ACCEPTANCE EVIDENCE)");
    expect(plainText).toContain("PRODUCTION ADMISSION");
    expect(plainText).toContain("AUTHENTICATION ASSURANCE");
    expect(plainText).toContain("does not prove inbox delivery");
    expect(renderEvidenceReport(reports.nontechnical, "html").toString()).toContain("<!doctype html>");
    expect(evidenceReportHash(buildEvidenceReports(record).technical)).toBe(evidenceReportHash(reports.technical));
  });
});
