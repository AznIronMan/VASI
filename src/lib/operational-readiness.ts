export type OperationalSnapshot = {
  configuration: {
    changes24Hours: number;
    installationProfilePresent: boolean;
    installationProfileRevision: number;
    lastChangeSeconds: number;
    lastSettingChangeSeconds: number;
    migrationDrift: boolean;
    migrationsApplied: number;
    migrationsExpected: number;
    settingChanges24Hours: number;
  };
  database: {
    pool: { idle: number; maximum: number; total: number; waiting: number };
    queryMilliseconds: number;
  };
  delivery: {
    activeBindings: number;
    delivered24Hours: number;
    disabledBindings: number;
    failed24Hours: number;
    gatewayFailures24Hours: number;
    recentErrorCodes: Array<{ code: string; count: number }>;
    suppressed24Hours: number;
    verifiedAdapters: number;
  };
  engineVersion: string;
  generatedAt: string;
  lifecycle: {
    oldestPendingDataRequestSeconds: number;
    pendingDataRequests: number;
    purgeBlocked24Hours: number;
    purgeDueRecords: number;
  };
  queue: {
    failed24Hours: number;
    oldestPendingSeconds: number;
    pending: number;
    running: number;
    staleRunning: number;
  };
  reasons: string[];
  schema: "vasi-operational-snapshot/v1";
  signing: {
    activeIntegrityKeys: number;
    activeOptionalKeys: number;
    untrustedKeys: number;
  };
  status: "attention" | "critical" | "ready";
  tenancy: { active: number; disabled: number };
};
