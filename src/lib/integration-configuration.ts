import type { OwnerIntegration } from "@/lib/owner-types";

type FormValues = Pick<FormData, "get">;

export function integrationCommandFromForm(
  adapterId: OwnerIntegration["adapterId"],
  data: FormValues,
) {
  if (adapterId === "webhook") {
    return {
      config: { url: text(data, "webhookUrl") },
      credentials: { secret: text(data, "webhookSecret") },
      status: "active" as const,
    };
  }
  if (adapterId === "microsoft_graph") {
    return {
      config: {
        clientId: text(data, "graphClientId"),
        senderEmail: text(data, "graphSenderEmail"),
        tenantId: text(data, "graphTenantId"),
      },
      credentials: { clientSecret: text(data, "graphClientSecret") },
      status: "active" as const,
    };
  }
  if (adapterId === "smtp") {
    return {
      config: {
        from: text(data, "smtpFrom"),
        host: text(data, "smtpHost"),
        port: Number(data.get("smtpPort")),
        secure: data.get("smtpSecure") === "true",
        username: optionalText(data, "smtpUsername"),
      },
      credentials: { password: optionalText(data, "smtpPassword") },
      status: "active" as const,
    };
  }
  if (adapterId === "https_malware_scanner") {
    return {
      config: {
        timeoutSeconds: Number(data.get("scannerTimeoutSeconds")),
        url: text(data, "scannerUrl"),
      },
      credentials: {
        caCertificatePem: optionalText(data, "scannerCaCertificatePem"),
        secret: text(data, "scannerSecret"),
      },
      status: "active" as const,
    };
  }
  return { config: {}, credentials: {}, status: "disabled" as const };
}

function text(data: FormValues, name: string) {
  return String(data.get(name) || "");
}

function optionalText(data: FormValues, name: string) {
  return text(data, name) || undefined;
}
