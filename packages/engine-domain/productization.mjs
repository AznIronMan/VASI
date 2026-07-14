import { X509Certificate } from "node:crypto";

export const TENANT_PROFILE_SCHEMA = "vasi-tenant-profile/v1";
export const INSTALLATION_PROFILE_SCHEMA = "vasi-installation-profile/v1";
export const INTEGRATION_CAPABILITIES = Object.freeze([
  "document.malware_scan",
  "notification.delivery",
]);

export const BUILT_IN_ADAPTERS = Object.freeze([
  Object.freeze({
    capabilities: Object.freeze(["notification.delivery"]),
    id: "disabled",
    name: "Disabled delivery",
    schema: "vasi-integration-adapter/v1",
    version: "1",
  }),
  Object.freeze({
    capabilities: Object.freeze(["document.malware_scan"]),
    id: "scan_disabled",
    name: "Disabled document malware scanning",
    schema: "vasi-integration-adapter/v1",
    version: "1",
  }),
  Object.freeze({
    capabilities: Object.freeze(["document.malware_scan"]),
    id: "https_malware_scanner",
    name: "Signed HTTPS document malware scanner",
    schema: "vasi-integration-adapter/v1",
    version: "1",
  }),
  Object.freeze({
    capabilities: Object.freeze(["notification.delivery"]),
    id: "microsoft_graph",
    name: "Microsoft Graph mail delivery",
    schema: "vasi-integration-adapter/v1",
    version: "1",
  }),
  Object.freeze({
    capabilities: Object.freeze(["notification.delivery"]),
    id: "smtp",
    name: "SMTP delivery",
    schema: "vasi-integration-adapter/v1",
    version: "1",
  }),
  Object.freeze({
    capabilities: Object.freeze(["notification.delivery"]),
    id: "webhook",
    name: "Signed webhook delivery",
    schema: "vasi-integration-adapter/v1",
    version: "1",
  }),
]);

export function defaultInstallationProfile(mode = "self_hosted") {
  if (!["self_hosted", "saas"].includes(mode)) invalid("The deployment mode is unsupported.");
  return Object.freeze({
    adapters: Object.freeze({
      allow: Object.freeze(BUILT_IN_ADAPTERS.map((adapter) => adapter.id)),
      microsoftGraphAllowedClientIds: Object.freeze([]),
      microsoftGraphAllowedSenders: Object.freeze([]),
      microsoftGraphAllowedTenantIds: Object.freeze([]),
      malwareScannerAllowedHosts: Object.freeze([]),
      smtpAllowedHosts: Object.freeze([]),
      webhookAllowedHosts: Object.freeze([]),
    }),
    deployment: Object.freeze({
      engineDatabaseBoundary: "dedicated",
      mode,
      publicIngress: "gateway_only",
    }),
    product: Object.freeze({
      organizationName: "VASI",
      productName: "V·Sign",
      supportEmail: "support@example.invalid",
    }),
    provisioning: Object.freeze({
      maxTenants: mode === "saas" ? 100_000 : 1_000,
      mode: "administrators_only",
    }),
    schema: INSTALLATION_PROFILE_SCHEMA,
  });
}

export function defaultTenantProfile(name = "Organization") {
  const displayName = boundedString(name, "name", 2, 160);
  return Object.freeze({
    branding: Object.freeze({
      accentColor: "#2e5b4e",
      displayName,
      primaryColor: "#183e34",
      shortName: displayName.slice(0, 48),
      supportEmail: null,
    }),
    policies: Object.freeze({ defaultRetentionProfile: "tenant_default" }),
    quotas: Object.freeze({
      maxActiveRequests: 10_000,
      maxArtifactBytes: 1_073_741_824,
      maxArtifactBytesPerArtifact: 52_428_800,
      maxIntegrations: 8,
      maxMembers: 100,
      maxWorkflows: 500,
    }),
    schema: TENANT_PROFILE_SCHEMA,
  });
}

export function validateInstallationProfile(value) {
  const input = strictObject(value, "installation profile", [
    "adapters", "deployment", "product", "provisioning", "schema",
  ]);
  if (input.schema !== INSTALLATION_PROFILE_SCHEMA) invalid("The installation profile schema is unsupported.");
  const deployment = strictObject(input.deployment, "installation deployment", [
    "engineDatabaseBoundary", "mode", "publicIngress",
  ]);
  if (!["self_hosted", "saas"].includes(deployment.mode)) invalid("The deployment mode is unsupported.");
  if (deployment.engineDatabaseBoundary !== "dedicated") {
    invalid("The private engine requires a dedicated database boundary.");
  }
  if (deployment.publicIngress !== "gateway_only") {
    invalid("The public ingress must terminate at the identity gateway.");
  }
  const product = strictObject(input.product, "installation product", [
    "organizationName", "productName", "supportEmail",
  ]);
  const provisioning = strictObject(input.provisioning, "installation provisioning", [
    "maxTenants", "mode",
  ]);
  if (provisioning.mode !== "administrators_only") {
    invalid("Only administrator-controlled tenant provisioning is supported.");
  }
  const adapters = strictObject(input.adapters, "installation adapters", [
    "allow", "microsoftGraphAllowedClientIds", "microsoftGraphAllowedSenders",
    "microsoftGraphAllowedTenantIds", "malwareScannerAllowedHosts", "smtpAllowedHosts",
    "webhookAllowedHosts",
  ]);
  if (!Array.isArray(adapters.allow) || !adapters.allow.length || adapters.allow.length > BUILT_IN_ADAPTERS.length) {
    invalid("The installation adapter allowlist is invalid.");
  }
  const supportedAdapters = new Set(BUILT_IN_ADAPTERS.map((adapter) => adapter.id));
  const allow = [...new Set(adapters.allow.map((id) => token(id, "adapter")))].sort();
  if (allow.some((id) => !supportedAdapters.has(id)) || !allow.includes("disabled")) {
    invalid("The installation adapter allowlist contains an unsupported adapter.");
  }
  return Object.freeze({
    adapters: Object.freeze({
      allow: Object.freeze(allow),
      ...(adapters.microsoftGraphAllowedClientIds === undefined ? {} : {
        microsoftGraphAllowedClientIds: allowedUUIDs(
          adapters.microsoftGraphAllowedClientIds,
          "microsoftGraphAllowedClientIds",
        ),
      }),
      ...(adapters.microsoftGraphAllowedSenders === undefined ? {} : {
        microsoftGraphAllowedSenders: allowedEmails(
          adapters.microsoftGraphAllowedSenders,
          "microsoftGraphAllowedSenders",
        ),
      }),
      ...(adapters.microsoftGraphAllowedTenantIds === undefined ? {} : {
        microsoftGraphAllowedTenantIds: allowedUUIDs(
          adapters.microsoftGraphAllowedTenantIds,
          "microsoftGraphAllowedTenantIds",
        ),
      }),
      ...(adapters.malwareScannerAllowedHosts === undefined ? {} : {
        malwareScannerAllowedHosts: allowedHosts(
          adapters.malwareScannerAllowedHosts,
          "malwareScannerAllowedHosts",
        ),
      }),
      smtpAllowedHosts: allowedHosts(adapters.smtpAllowedHosts, "smtpAllowedHosts"),
      webhookAllowedHosts: allowedHosts(adapters.webhookAllowedHosts, "webhookAllowedHosts"),
    }),
    deployment: Object.freeze({
      engineDatabaseBoundary: "dedicated",
      mode: deployment.mode,
      publicIngress: "gateway_only",
    }),
    product: Object.freeze({
      organizationName: boundedString(product.organizationName, "organizationName", 2, 120),
      productName: boundedString(product.productName, "productName", 2, 80),
      supportEmail: email(product.supportEmail, "supportEmail"),
    }),
    provisioning: Object.freeze({
      maxTenants: safeInteger(provisioning.maxTenants, "maxTenants", 1, 1_000_000),
      mode: "administrators_only",
    }),
    schema: INSTALLATION_PROFILE_SCHEMA,
  });
}

export function validateTenantProfile(value) {
  const input = strictObject(value, "tenant profile", ["branding", "policies", "quotas", "schema"]);
  if (input.schema !== TENANT_PROFILE_SCHEMA) invalid("The tenant profile schema is unsupported.");
  const branding = strictObject(input.branding, "tenant branding", [
    "accentColor", "displayName", "primaryColor", "shortName", "supportEmail",
  ]);
  const policies = strictObject(input.policies, "tenant policies", ["defaultRetentionProfile"]);
  const quotas = strictObject(input.quotas, "tenant quotas", [
    "maxActiveRequests", "maxArtifactBytes", "maxArtifactBytesPerArtifact",
    "maxIntegrations", "maxMembers", "maxWorkflows",
  ]);
  const maxArtifactBytes = safeInteger(
    quotas.maxArtifactBytes,
    "maxArtifactBytes",
    1_048_576,
    10_995_116_277_760,
  );
  const maxArtifactBytesPerArtifact = safeInteger(
    quotas.maxArtifactBytesPerArtifact,
    "maxArtifactBytesPerArtifact",
    1_024,
    1_073_741_824,
  );
  if (maxArtifactBytesPerArtifact > maxArtifactBytes) {
    invalid("The per-artifact limit cannot exceed total artifact storage.");
  }
  return Object.freeze({
    branding: Object.freeze({
      accentColor: color(branding.accentColor, "accentColor"),
      displayName: boundedString(branding.displayName, "displayName", 2, 160),
      primaryColor: color(branding.primaryColor, "primaryColor"),
      shortName: boundedString(branding.shortName, "shortName", 2, 48),
      supportEmail: optionalEmail(branding.supportEmail, "supportEmail"),
    }),
    policies: Object.freeze({
      defaultRetentionProfile: profileName(policies.defaultRetentionProfile),
    }),
    quotas: Object.freeze({
      maxActiveRequests: safeInteger(quotas.maxActiveRequests, "maxActiveRequests", 1, 1_000_000),
      maxArtifactBytes,
      maxArtifactBytesPerArtifact,
      maxIntegrations: safeInteger(quotas.maxIntegrations, "maxIntegrations", 0, 100),
      maxMembers: safeInteger(quotas.maxMembers, "maxMembers", 1, 100_000),
      maxWorkflows: safeInteger(quotas.maxWorkflows, "maxWorkflows", 1, 100_000),
    }),
    schema: TENANT_PROFILE_SCHEMA,
  });
}

export function validateTenantProvisionInput(value) {
  const input = strictObject(value, "tenant provisioning command", ["name", "ownerEmail", "profile", "slug"]);
  const name = boundedString(input.name, "name", 2, 160);
  const slug = boundedString(input.slug, "slug", 2, 64).toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(slug)) invalid("The tenant slug is invalid.");
  return Object.freeze({
    name,
    ownerEmail: optionalEmail(input.ownerEmail, "ownerEmail"),
    profile: input.profile === undefined ? defaultTenantProfile(name) : validateTenantProfile(input.profile),
    slug,
  });
}

export function validateTenantProfileCommand(value) {
  const input = strictObject(value, "tenant profile command", ["expectedRevision", "profile", "tenantId"]);
  return Object.freeze({
    expectedRevision: safeInteger(input.expectedRevision, "expectedRevision", 1, Number.MAX_SAFE_INTEGER),
    profile: validateTenantProfile(input.profile),
    tenantId: token(input.tenantId, "tenantId"),
  });
}

export function validateInstallationProfileCommand(value) {
  const input = strictObject(value, "installation profile command", ["expectedRevision", "profile"]);
  return Object.freeze({
    expectedRevision: safeInteger(input.expectedRevision, "expectedRevision", 1, Number.MAX_SAFE_INTEGER),
    profile: validateInstallationProfile(input.profile),
  });
}

export function validateTenantReference(value, name = "tenant command") {
  const input = strictObject(value, name, ["tenantId"]);
  return Object.freeze({ tenantId: token(input.tenantId, "tenantId") });
}

export function validateIntegrationBindingCommand(value) {
  const input = strictObject(value, "integration binding command", [
    "adapterId", "capability", "config", "credentials", "expectedRevision", "status", "tenantId",
  ]);
  const adapterId = token(input.adapterId, "adapterId");
  const adapter = BUILT_IN_ADAPTERS.find((candidate) => candidate.id === adapterId);
  if (!adapter) invalid("The integration adapter is unsupported.");
  const capability = token(input.capability, "capability");
  if (!INTEGRATION_CAPABILITIES.includes(capability) || !adapter.capabilities.includes(capability)) {
    invalid("The integration capability is unsupported by this adapter.");
  }
  const status = input.status ?? (["disabled", "scan_disabled"].includes(adapterId) ? "disabled" : "active");
  if (!["active", "disabled"].includes(status)) invalid("The integration binding status is unsupported.");
  if (["disabled", "scan_disabled"].includes(adapterId) && status !== "disabled") {
    invalid("A disabled adapter cannot be active.");
  }
  const normalized = normalizeAdapterConfiguration(adapterId, input.config, input.credentials);
  return Object.freeze({
    adapterId,
    adapterVersion: adapter.version,
    capability,
    config: normalized.config,
    credentials: normalized.credentials,
    expectedRevision: safeInteger(input.expectedRevision, "expectedRevision", 0, Number.MAX_SAFE_INTEGER),
    status,
    tenantId: token(input.tenantId, "tenantId"),
  });
}

export function integrationDestinationAllowed(profileValue, binding) {
  const profile = validateInstallationProfile(profileValue);
  if (binding.status !== "active" || binding.adapterId === "disabled") return true;
  if (!profile.adapters.allow.includes(binding.adapterId)) return false;
  if (binding.adapterId === "webhook") {
    return profile.adapters.webhookAllowedHosts.includes(new URL(binding.config.url).hostname.toLowerCase());
  }
  if (binding.adapterId === "smtp") {
    return profile.adapters.smtpAllowedHosts.includes(String(binding.config.host).toLowerCase());
  }
  if (binding.adapterId === "microsoft_graph") {
    return (profile.adapters.microsoftGraphAllowedTenantIds || []).includes(binding.config.tenantId) &&
      (profile.adapters.microsoftGraphAllowedClientIds || []).includes(binding.config.clientId) &&
      (profile.adapters.microsoftGraphAllowedSenders || []).includes(binding.config.senderEmail);
  }
  if (binding.adapterId === "https_malware_scanner") {
    return (profile.adapters.malwareScannerAllowedHosts || [])
      .includes(new URL(binding.config.url).hostname.toLowerCase());
  }
  return false;
}

function normalizeAdapterConfiguration(adapterId, configValue, credentialValue) {
  if (["disabled", "scan_disabled"].includes(adapterId)) {
    strictObject(configValue ?? {}, "disabled adapter configuration", []);
    strictObject(credentialValue ?? {}, "disabled adapter credentials", []);
    return { config: Object.freeze({}), credentials: Object.freeze({}) };
  }
  if (adapterId === "https_malware_scanner") {
    const config = strictObject(configValue, "HTTPS malware scanner configuration", [
      "timeoutSeconds", "url",
    ]);
    const credentials = strictObject(credentialValue, "HTTPS malware scanner credentials", [
      "caCertificatePem", "secret",
    ]);
    let url;
    try {
      url = new URL(boundedString(config.url, "url", 1, 2_048));
    } catch {
      invalid("The malware scanner URL is invalid.");
    }
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
      invalid("The malware scanner URL must use HTTPS without credentials, a query, or a fragment.");
    }
    return {
      config: Object.freeze({
        timeoutSeconds: safeInteger(config.timeoutSeconds, "timeoutSeconds", 5, 300),
        url: url.toString(),
      }),
      credentials: Object.freeze({
        caCertificatePem: optionalCertificateAuthorityBundle(credentials.caCertificatePem),
        secret: boundedString(credentials.secret, "secret", 32, 1_024),
      }),
    };
  }
  if (adapterId === "webhook") {
    const config = strictObject(configValue, "webhook configuration", ["url"]);
    const credentials = strictObject(credentialValue, "webhook credentials", ["secret"]);
    const url = new URL(boundedString(config.url, "url", 1, 2_048));
    if (url.protocol !== "https:" || url.username || url.password || url.hash) {
      invalid("The webhook URL must use HTTPS without credentials or a fragment.");
    }
    const secret = boundedString(credentials.secret, "secret", 32, 1_024);
    return {
      config: Object.freeze({ url: url.toString() }),
      credentials: Object.freeze({ secret }),
    };
  }
  if (adapterId === "microsoft_graph") {
    const config = strictObject(configValue, "Microsoft Graph configuration", [
      "clientId", "senderEmail", "tenantId",
    ]);
    const credentials = strictObject(credentialValue, "Microsoft Graph credentials", ["clientSecret"]);
    return {
      config: Object.freeze({
        clientId: uuid(config.clientId, "clientId"),
        senderEmail: email(config.senderEmail, "senderEmail"),
        tenantId: uuid(config.tenantId, "tenantId"),
      }),
      credentials: Object.freeze({
        clientSecret: boundedString(credentials.clientSecret, "clientSecret", 1, 2_048),
      }),
    };
  }
  const config = strictObject(configValue, "SMTP configuration", [
    "from", "host", "port", "secure", "username",
  ]);
  const credentials = strictObject(credentialValue ?? {}, "SMTP credentials", ["password"]);
  const host = boundedString(config.host, "host", 1, 253).toLowerCase();
  if (!/^(?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?|\[[0-9a-f:]+\])$/i.test(host)) {
    invalid("The SMTP host is invalid.");
  }
  const username = optionalString(config.username, "username", 320);
  const password = optionalString(credentials.password, "password", 1_024);
  if (Boolean(username) !== Boolean(password)) invalid("SMTP username and password must be configured together.");
  if (typeof config.secure !== "boolean") invalid("SMTP secure must be a boolean.");
  return {
    config: Object.freeze({
      from: boundedString(config.from, "from", 3, 320),
      host,
      port: safeInteger(config.port, "port", 1, 65_535),
      secure: config.secure,
      username,
    }),
    credentials: Object.freeze({ password }),
  };
}

function strictObject(value, name, allowedKeys) {
  if (!value || Array.isArray(value) || typeof value !== "object") invalid(`The ${name} must be an object.`);
  for (const key of Object.keys(value)) {
    if (!allowedKeys.includes(key)) invalid(`The ${name} field ${key} is unsupported.`);
  }
  return value;
}

function boundedString(value, field, minimum, maximum) {
  if (typeof value !== "string") invalid(`${field} must be a string.`);
  const normalized = value.normalize("NFC").trim();
  if (normalized.length < minimum || normalized.length > maximum || /[\u0000-\u001f\u007f]/.test(normalized)) {
    invalid(`${field} must contain ${minimum} to ${maximum} safe characters.`);
  }
  return normalized;
}

function optionalString(value, field, maximum) {
  if (value === undefined || value === null || value === "") return undefined;
  return boundedString(value, field, 1, maximum);
}

function optionalCertificateAuthorityBundle(value) {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > 131_072) {
    invalid("The scanner CA certificate bundle is invalid.");
  }
  const normalized = value.replace(/\r\n/g, "\n").trim();
  const matches = normalized.match(/-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----/g) || [];
  if (!matches.length || matches.length > 5 || matches.join("\n") !== normalized) {
    invalid("The scanner CA certificate bundle is invalid.");
  }
  try {
    for (const certificate of matches) new X509Certificate(certificate);
  } catch {
    invalid("The scanner CA certificate bundle is invalid.");
  }
  return `${matches.join("\n")}\n`;
}

function token(value, field) {
  const normalized = boundedString(value, field, 1, 128);
  if (!/^[A-Za-z0-9._:-]+$/.test(normalized)) invalid(`The ${field} is invalid.`);
  return normalized;
}

function profileName(value) {
  const normalized = boundedString(value, "defaultRetentionProfile", 1, 128);
  if (!/^[a-z][a-z0-9_-]*$/.test(normalized)) invalid("The default retention profile name is invalid.");
  return normalized;
}

function allowedHosts(value, field) {
  if (!Array.isArray(value) || value.length > 256) invalid(`The ${field} list is invalid.`);
  return Object.freeze([...new Set(value.map((entry) => {
    const normalized = boundedString(entry, field, 1, 253).toLowerCase();
    if (!/^(?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?|\[[0-9a-f:]+\])$/i.test(normalized)) {
      invalid(`The ${field} list contains an invalid host.`);
    }
    return normalized;
  }))].sort());
}

function allowedUUIDs(value, field) {
  if (!Array.isArray(value) || value.length > 256) invalid(`The ${field} list is invalid.`);
  return Object.freeze([...new Set(value.map((entry) => uuid(entry, field)))].sort());
}

function allowedEmails(value, field) {
  if (!Array.isArray(value) || value.length > 256) invalid(`The ${field} list is invalid.`);
  return Object.freeze([...new Set(value.map((entry) => email(entry, field)))].sort());
}

function uuid(value, field) {
  const normalized = typeof value === "string" ? value.normalize("NFC").trim().toLowerCase() : "";
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(normalized) ||
    normalized === "00000000-0000-0000-0000-000000000000"
  ) {
    invalid(`The ${field} must be a UUID.`);
  }
  return normalized;
}

function safeInteger(value, field, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalid(`${field} must be a whole number between ${minimum} and ${maximum}.`);
  }
  return value;
}

function color(value, field) {
  if (typeof value !== "string" || !/^#[0-9a-f]{6}$/i.test(value)) invalid(`The ${field} is invalid.`);
  return value.toLowerCase();
}

function email(value, field) {
  const normalized = boundedString(value, field, 3, 320).toLowerCase();
  if (!/^[^@\s]+@[^@\s]+$/.test(normalized)) invalid(`The ${field} is invalid.`);
  return normalized;
}

function optionalEmail(value, field) {
  if (value === undefined || value === null || value === "") return null;
  return email(value, field);
}

function invalid(message) {
  const error = new Error(message);
  error.code = "INVALID_PRODUCT_CONFIGURATION";
  throw error;
}
