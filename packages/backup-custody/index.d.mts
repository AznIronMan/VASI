export interface CustodyRecipient {
  keyId: string;
  publicJwk: { crv: "X25519"; kty: "OKP"; x: string };
}

export declare const CUSTODY_SCHEMA: "vasi-backup-custody/v1";
export declare const CUSTODY_CONTENT_SCHEMA: "vasi-matched-backup-stream/v1";
export declare const CUSTODY_READINESS_SCHEMA: "vasi-backup-custody-readiness/v1";

export declare class BackupCustodyError extends Error {
  result: Readonly<Record<string, unknown>>;
}

export declare function parseCustodyRecipients(rawValue: string | CustodyRecipient[]): readonly CustodyRecipient[];
export declare function generateCustodyRecipient(input: {
  keyId: string;
  privateKeyFile: string;
}): Promise<CustodyRecipient>;
export declare function createCustodyEnvelope(input: Record<string, unknown>): Promise<Readonly<Record<string, unknown>>>;
export declare function createCustodyCycle(input: Record<string, unknown>): Promise<Readonly<Record<string, unknown>>>;
export declare function inspectCustodyPackage(packagePath: string): Promise<Readonly<Record<string, unknown>>>;
export declare function checkLatestCustody(input: Record<string, unknown>): Promise<Readonly<Record<string, unknown>>>;
export declare function authenticateCustodyPackage(input: Record<string, unknown>): Promise<Readonly<Record<string, unknown>>>;
export declare function extractCustodyPackage(input: Record<string, unknown>): Promise<Readonly<Record<string, unknown>>>;
