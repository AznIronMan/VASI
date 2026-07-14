-- Encrypted VASI installation settings. Bootstrap database access and the
-- encryption key remain in the local ignored data/VASI.settings SQLite file.

create table "vasi_runtime_setting" (
  "installationId" text not null,
  "scope" text not null,
  "name" text not null,
  "ciphertext" bytea not null,
  "iv" bytea not null check (octet_length("iv") = 12),
  "authTag" bytea not null check (octet_length("authTag") = 16),
  "isSecret" boolean not null,
  "version" bigint not null default 1 check ("version" > 0),
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP,
  "updatedAt" timestamptz not null default CURRENT_TIMESTAMP,
  primary key ("installationId", "scope", "name")
);

create table "vasi_runtime_setting_audit" (
  "id" text not null primary key,
  "installationId" text not null,
  "scope" text not null,
  "name" text not null,
  "action" text not null,
  "version" bigint,
  "source" text not null,
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP
);

create index "vasi_runtime_setting_audit_installation_created_idx"
  on "vasi_runtime_setting_audit" ("installationId", "createdAt" desc);

create index "vasi_runtime_setting_audit_name_idx"
  on "vasi_runtime_setting_audit" ("installationId", "scope", "name");
