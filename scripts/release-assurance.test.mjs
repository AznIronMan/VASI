import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { describe, expect, it } from "vitest";

import {
  DIRECT_EXECUTION_ENTRYPOINTS,
  inspectTrackedSource,
  runtimeDependencyAuditPaths,
  runtimeContractForImage,
  validateAutomationContract,
  validateComposeContracts,
  validateDirectExecutionContract,
  validateEdgeMonitorContract,
  validateEngineHostRuntimeContract,
  validateOperationalSchedulerContract,
  validateOperationalAlertHandoffContract,
  validatePilotAdmissionEvidenceContract,
  validatePilotGateEvidenceContract,
  validateProductionActivationContract,
  validateProductionStagingContract,
  validatePublicIngressContract,
  validateReadinessDossierVerifierContract,
  validateRuntimeImageBuildContract,
  validateVersionAlignment,
} from "./release-assurance.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("release assurance policy", () => {
  it("keeps private/runtime material out of tracked source", async () => {
    const result = await inspectTrackedSource(root);
    expect(result.forbiddenPaths).toEqual([]);
    expect(result.secretFindings).toEqual([]);
    expect(result.unboundedGatewayJSONParsers).toEqual([]);
    expect(result.files.length).toBeGreaterThan(100);
  });

  it("aligns all authoritative version declarations", async () => {
    const result = await validateVersionAlignment(root);
    expect(result.mismatches).toEqual([]);
  });

  it("keeps public and private runtime services hardened", async () => {
    const result = await validateComposeContracts(root);
    expect(result.failures).toEqual([]);
    expect(result.servicesChecked).toContain("gateway.capacity");
    expect(result.servicesChecked).toContain("engine.capacity");
    expect(result.servicesChecked).toContain("engine.database-gateway");
    expect(result.servicesChecked).toContain("engine.egress-policy");
  });

  it("keeps release automation least-privileged and commit-pinned", async () => {
    const result = await validateAutomationContract(root);
    expect(result.failures).toEqual([]);
    expect(result.jobs).toBeGreaterThan(0);
    expect(result.releaseImagesChecked).toEqual([
      "vasi",
      "vasi-database-gateway",
      "vasi-engine",
      "vasi-engine-maintenance",
      "vasi-engine-tools",
      "vasi-settings",
    ]);
  });

  it("packages every persistent least-privileged operational scheduler", async () => {
    const result = await validateOperationalSchedulerContract(root);
    expect(result.failures).toEqual([]);
    expect(result.unitsChecked).toHaveLength(37);
    expect(result.unitsChecked).toContain("vasi-edge-alert-readiness.timer");
    expect(result.unitsChecked).toContain("vasi-engine-alert-record@.service");
    expect(result.unitsChecked).toContain("vasi-gateway-alert-readiness.timer");
    expect(result.unitsChecked).toContain("vasi-edge-image-assurance.timer");
    expect(result.unitsChecked).toContain("vasi-edge-runtime-readiness.timer");
    expect(result.unitsChecked).toContain("vasi-engine-operational-readiness.timer");
    expect(result.unitsChecked).toContain("vasi-gateway-operational-readiness.timer");
    expect(result.unitsChecked).toContain("vasi-gateway-backup-check.timer");
  });

  it("keeps the durable operational-alert handoff bounded and transport-neutral", async () => {
    const result = await validateOperationalAlertHandoffContract(root);
    expect(result).toEqual({ failures: [], filesChecked: 1 });
  });

  it("keeps the direct engine host runtime exact and lifecycle-script-free", async () => {
    const result = await validateEngineHostRuntimeContract(root);
    expect(result).toEqual({ failures: [], filesChecked: 4 });
  });

  it("keeps every production image dependency stage exact and minimized", async () => {
    const result = await validateRuntimeImageBuildContract(root);
    expect(result).toEqual({ failures: [], filesChecked: 2 });
  });

  it("keeps every importable operational CLI symlink-safe and release-assurance inventoried", async () => {
    const tracked = await inspectTrackedSource(root);
    const result = await validateDirectExecutionContract(root, operationalSources(tracked));
    expect(result.failures).toEqual([]);
    expect(result.filesChecked).toBe(27);
    expect(result.cliFiles).toHaveLength(24);
    expect(result.cliFiles).toContain("scripts/activate-production-release.mjs");
    expect(result.cliFiles).toContain("scripts/stage-production-release.mjs");
    expect(result.cliFiles).toContain("scripts/readiness-trust-anchor.mjs");
    expect(result.cliFiles).toContain("scripts/pilot-gate-evidence.mjs");
    expect(result.cliFiles).toContain("scripts/verify-pilot-admission-evidence.mjs");
    expect(result.cliFiles).toContain("scripts/verify-readiness-dossier.mjs");
    expect(result.cliFiles).toContain("services/database-gateway/server.mjs");
    await expect(validateDirectExecutionContract(root, [null])).resolves.toMatchObject({
      failures: ["the direct-execution source inventory is invalid"],
      filesChecked: 0,
    });
  });

  it("keeps pilot-gate evidence deterministic, bounded, offline, and privacy-safe", async () => {
    const result = await validatePilotGateEvidenceContract(root);
    expect(result).toEqual({ failures: [], filesChecked: 11 });
  });

  it("keeps complete pilot-admission binding offline, exact, and privacy-safe", async () => {
    const result = await validatePilotAdmissionEvidenceContract(root);
    expect(result).toEqual({ failures: [], filesChecked: 7 });
  });

  it("rejects a weakened complete pilot-admission evidence contract", async () => {
    const fixture = await mkdtemp(path.join(tmpdir(), "vasi-pilot-admission-assurance-"));
    try {
      const files = [
        "docs/architecture/pilot-admission-evidence-verification.md",
        "package.json",
        "packages/pilot-admission-evidence/index.mjs",
        "packages/pilot-admission-evidence/index.test.mjs",
        "packages/pilot-admission-evidence/test-fixture.mjs",
        "scripts/verify-pilot-admission-evidence.mjs",
        "scripts/verify-pilot-admission-evidence.test.mjs",
      ];
      for (const filename of files) {
        await mkdir(path.dirname(path.join(fixture, filename)), { recursive: true });
        await cp(path.join(root, filename), path.join(fixture, filename));
      }
      const library = path.join(fixture, "packages/pilot-admission-evidence/index.mjs");
      await writeFile(
        library,
        (await readFile(library, "utf8"))
          .replace("constants.O_NOFOLLOW", "0")
          .replace('admission.status !== "admitted"', "false"),
      );
      const documentation = path.join(
        fixture,
        "docs/architecture/pilot-admission-evidence-verification.md",
      );
      await writeFile(
        documentation,
        (await readFile(documentation, "utf8"))
          .replace('`artifactVerification: "not_performed"`', "artifact verified"),
      );
      const result = await validatePilotAdmissionEvidenceContract(fixture);
      expect(result.failures).toContain(
        "the pilot-admission evidence library is missing constants.O_NOFOLLOW",
      );
      expect(result.failures).toContain(
        'the pilot-admission evidence library is missing admission.status !== "admitted"',
      );
      expect(result.failures).toContain(
        'the pilot-admission evidence documentation is missing `artifactVerification: "not_performed"`',
      );
    } finally {
      await rm(fixture, { force: true, recursive: true });
    }
  });

  it("rejects a weakened pilot-gate evidence contract", async () => {
    const fixture = await mkdtemp(path.join(tmpdir(), "vasi-pilot-gate-evidence-assurance-"));
    try {
      const files = [
        "config/pilot-gate-evidence-contract.json",
        "docs/architecture/pilot-gate-evidence-packages.md",
        "package.json",
        "packages/pilot-gate-evidence/index.mjs",
        "packages/pilot-gate-evidence/index.test.mjs",
        "packages/pilot-gate-evidence/browser-import.test.mjs",
        "scripts/pilot-gate-evidence.mjs",
        "scripts/pilot-gate-evidence.test.mjs",
        "src/components/admin/tenant-admission-panel.tsx",
        "src/lib/pilot-gate-manifest-import.test.ts",
        "src/lib/pilot-gate-manifest-import.ts",
      ];
      for (const filename of files) {
        await mkdir(path.dirname(path.join(fixture, filename)), { recursive: true });
        await cp(path.join(root, filename), path.join(fixture, filename));
      }
      const library = path.join(fixture, "packages/pilot-gate-evidence/index.mjs");
      await writeFile(
        library,
        (await readFile(library, "utf8"))
          .replaceAll("constants.O_NOFOLLOW", "0")
          .replace("before.nlink !== 1n", "false"),
      );
      const documentation = path.join(fixture, "docs/architecture/pilot-gate-evidence-packages.md");
      await writeFile(
        documentation,
        (await readFile(documentation, "utf8")).replace(
          "Integrity packaging is not approval",
          "VASI approval",
        ),
      );
      const browser = path.join(fixture, "src/lib/pilot-gate-manifest-import.ts");
      await writeFile(
        browser,
        (await readFile(browser, "utf8")).replace("gateId !== expectedGateId", "false"),
      );
      const contract = path.join(fixture, "config/pilot-gate-evidence-contract.json");
      await writeFile(
        contract,
        (await readFile(contract, "utf8")).replace('      "screen_reader",\n', ""),
      );
      const result = await validatePilotGateEvidenceContract(fixture);
      expect(result.failures).toContain(
        "the pilot-gate evidence library is missing constants.O_NOFOLLOW",
      );
      expect(result.failures).toContain(
        "the pilot-gate evidence library is missing before.nlink !== 1n",
      );
      expect(result.failures).toContain(
        "the pilot-gate evidence documentation is missing Integrity packaging is not approval",
      );
      expect(result.failures).toContain(
        "the browser-local pilot-gate verifier is missing gateId !== expectedGateId",
      );
      expect(result.failures).toContain(
        "the shared pilot-gate evidence contract is incomplete or weakened",
      );
    } finally {
      await rm(fixture, { force: true, recursive: true });
    }
  });

  it("keeps offline readiness dossier verification bounded, shared, and privacy-safe", async () => {
    const result = await validateReadinessDossierVerifierContract(root);
    expect(result).toEqual({ failures: [], filesChecked: 15 });
  });

  it("rejects a weakened offline readiness dossier verifier contract", async () => {
    const fixture = await mkdtemp(path.join(tmpdir(), "vasi-readiness-verifier-assurance-"));
    try {
      const files = [
        "docs/architecture/pilot-readiness-dossier.md",
        "package.json",
        "packages/engine-crypto/index.mjs",
        "packages/readiness-dossier/index.mjs",
        "packages/readiness-dossier/index.test.mjs",
        "scripts/readiness-trust-anchor.mjs",
        "scripts/readiness-trust-anchor.test.mjs",
        "scripts/verify-readiness-dossier.mjs",
        "scripts/verify-readiness-dossier.test.mjs",
        "services/engine/product-store.mjs",
        "services/engine/product-store.test.mjs",
        "services/engine/signing-provider.mjs",
        "src/app/api/admin/product/tenant-readiness-exports/route.test.ts",
        "src/app/api/admin/product/tenant-readiness-exports/route.ts",
        "src/lib/readiness-dossier.ts",
      ];
      for (const filename of files) {
        await mkdir(path.dirname(path.join(fixture, filename)), { recursive: true });
        await cp(path.join(root, filename), path.join(fixture, filename));
      }
      const verifier = path.join(fixture, "packages/readiness-dossier/index.mjs");
      await writeFile(
        verifier,
        (await readFile(verifier, "utf8"))
          .replace("constants.O_NOFOLLOW", "0")
          .replaceAll("verifyDetachedIntegritySeal", "acceptDetachedIntegritySeal"),
      );
      const documentation = path.join(fixture, "docs/architecture/pilot-readiness-dossier.md");
      await writeFile(
        documentation,
        (await readFile(documentation, "utf8")).replaceAll("npm run readiness:verify", "node verifier"),
      );
      const result = await validateReadinessDossierVerifierContract(fixture);
      expect(result.failures).toContain("the readiness dossier verifier is missing constants.O_NOFOLLOW");
      expect(result.failures).toContain(
        "the readiness dossier verifier is missing verifyDetachedIntegritySeal(attestation",
      );
      expect(result.failures).toContain("the offline readiness dossier verification command is undocumented");
    } finally {
      await rm(fixture, { force: true, recursive: true });
    }
  });

  it("imports every inventoried operational CLI without entering main", async () => {
    const tracked = await inspectTrackedSource(root);
    const result = await validateDirectExecutionContract(root, operationalSources(tracked));
    const modules = await Promise.all(result.cliFiles.map((filename) =>
      import(pathToFileURL(path.join(root, filename)).href)
    ));
    expect(modules).toHaveLength(24);
  });

  it("rejects a silent-no-op operational CLI comparison", async () => {
    const tracked = await inspectTrackedSource(root);
    const clean = await validateDirectExecutionContract(root, operationalSources(tracked));
    const fixture = await mkdtemp(path.join(tmpdir(), "vasi-direct-execution-assurance-"));
    try {
      const files = [
        "Dockerfile.engine",
        "scripts/direct-execution.mjs",
        "scripts/direct-execution.test.mjs",
        ...clean.cliFiles,
      ];
      for (const filename of new Set(files)) {
        await mkdir(path.dirname(path.join(fixture, filename)), { recursive: true });
        await cp(path.join(root, filename), path.join(fixture, filename));
      }
      const activation = path.join(fixture, "scripts", "activate-production-release.mjs");
      await writeFile(
        activation,
        (await readFile(activation, "utf8")).replace(
          "if (isDirectExecution(import.meta.url, process.argv[1])) {",
          [
            "if (process.argv[1] && import.meta.url === ",
            "pathToFileURL(process.argv[1]).href) {",
          ].join(""),
        ),
      );
      const result = await validateDirectExecutionContract(fixture, clean.cliFiles);
      expect(result.failures).toContain(
        "scripts/activate-production-release.mjs contains the vulnerable literal direct-execution comparison",
      );
      expect(result.failures).toContain(
        "scripts/activate-production-release.mjs is missing its direct-execution guard",
      );
    } finally {
      await rm(fixture, { force: true, recursive: true });
    }
  });

  it("keeps the canonical public ingress bounded and independently auditable", async () => {
    const result = await validatePublicIngressContract(root);
    expect(result).toEqual({
      failures: [],
      filesChecked: 16,
      routeIsolation: {
        methodCount: 54,
        namespaceMethods: { admin: 17, evidence: 4, owner: 25, request: 3, workspace: 5 },
      },
    });
  });

  it("keeps recurring public-edge assurance exact and socket-free", async () => {
    const result = await validateEdgeMonitorContract(root);
    expect(result).toEqual({ failures: [], filesChecked: 9 });
  });

  it("keeps production release activation complete, bounded, and fail-closed", async () => {
    const result = await validateProductionActivationContract(root);
    expect(result).toEqual({ failures: [], filesChecked: 6 });
  });

  it("keeps production release staging bounded, private, and fail-closed", async () => {
    const result = await validateProductionStagingContract(root);
    expect(result).toEqual({ failures: [], filesChecked: 4 });
  });

  it("rejects an ambient or host-archive production release stager", async () => {
    const fixture = await mkdtemp(path.join(tmpdir(), "vasi-production-staging-assurance-"));
    try {
      for (const filename of [
        "docs/architecture/fail-closed-release-activation.md",
        "package.json",
        "scripts/stage-production-release.mjs",
        "scripts/stage-production-release.test.mjs",
      ]) {
        await mkdir(path.dirname(path.join(fixture, filename)), { recursive: true });
        await cp(path.join(root, filename), path.join(fixture, filename));
      }
      const script = path.join(fixture, "scripts", "stage-production-release.mjs");
      await writeFile(script, `${await readFile(script, "utf8")}\nspawn("tar", ["-xf", archive]);\n`);
      const result = await validateProductionStagingContract(fixture);
      expect(result.failures).toContain(
        "the production release staging command contains prohibited archive, runtime, or ambient behavior",
      );
    } finally {
      await rm(fixture, { force: true, recursive: true });
    }
  });

  it("rejects an over-broad or destructive production release activator", async () => {
    const fixture = await mkdtemp(path.join(tmpdir(), "vasi-production-activation-assurance-"));
    try {
      await mkdir(path.join(fixture, "deployment", "activation"), { recursive: true });
      await mkdir(path.join(fixture, "scripts"), { recursive: true });
      await cp(path.join(root, "package.json"), path.join(fixture, "package.json"));
      await cp(
        path.join(root, "scripts", "activate-production-release.mjs"),
        path.join(fixture, "scripts", "activate-production-release.mjs"),
      );
      for (const role of ["gateway", "engine"]) {
        for (const suffix of ["example.json", "live.example.yaml"]) {
          await cp(
            path.join(root, "deployment", "activation", `${role}.${suffix}`),
            path.join(fixture, "deployment", "activation", `${role}.${suffix}`),
          );
        }
      }
      const script = path.join(fixture, "scripts", "activate-production-release.mjs");
      await writeFile(script, `${await readFile(script, "utf8")}\n// --remove-orphans\n`);
      const overlay = path.join(fixture, "deployment", "activation", "gateway.live.example.yaml");
      await writeFile(overlay, `${await readFile(overlay, "utf8")}    environment:\n      SECRET: exposed\n`);
      const result = await validateProductionActivationContract(fixture);
      expect(result.failures).toContain(
        "the production activation command contains prohibited destructive, privileged, or ambient state",
      );
      expect(result.failures).toContain("the sanitized gateway production activation example is invalid");
    } finally {
      await rm(fixture, { force: true, recursive: true });
    }
  });

  it("rejects a mutable or privileged recurring edge monitor", async () => {
    const fixture = await mkdtemp(path.join(tmpdir(), "vasi-edge-monitor-assurance-"));
    try {
      await mkdir(path.join(fixture, "config"), { recursive: true });
      await mkdir(path.join(fixture, "deployment", "nginx"), { recursive: true });
      await mkdir(path.join(fixture, "scripts"), { recursive: true });
      for (const filename of [
        "Dockerfile",
        "Dockerfile.engine",
        "package.json",
      ]) await cp(path.join(root, filename), path.join(fixture, filename));
      await cp(
        path.join(root, "config", "edge-monitor-policy.json"),
        path.join(fixture, "config", "edge-monitor-policy.json"),
      );
      await cp(
        path.join(root, "deployment", "nginx", "vasi-edge-monitor.example.json"),
        path.join(fixture, "deployment", "nginx", "vasi-edge-monitor.example.json"),
      );
      for (const filename of [
        "edge-monitor-common.sh",
        "edge-image-assurance.sh",
        "probe-edge-runtime.sh",
      ]) await cp(path.join(root, "scripts", filename), path.join(fixture, "scripts", filename));
      const imageScript = path.join(fixture, "scripts", "edge-image-assurance.sh");
      await writeFile(
        imageScript,
        `${(await readFile(imageScript, "utf8")).replace(
          "docker run --rm --network none --read-only",
          "docker run --rm --network host --privileged",
        )}\n-v /var/run/docker.sock:/var/run/docker.sock\n`,
      );
      const result = await validateEdgeMonitorContract(fixture);
      expect(result.failures).toContain(
        "the edge monitor scripts contain prohibited privilege or environment state",
      );
      expect(result.failures).toContain(
        "the edge evidence and auditor containers are not consistently network-isolated",
      );
    } finally {
      await rm(fixture, { force: true, recursive: true });
    }
  });

  it("rejects a weakened canonical public ingress", async () => {
    const fixture = await mkdtemp(path.join(tmpdir(), "vasi-public-ingress-assurance-"));
    try {
      await mkdir(path.join(fixture, "deployment", "nginx"), { recursive: true });
      await mkdir(path.join(fixture, "scripts"), { recursive: true });
      await mkdir(path.join(fixture, "src", "lib"), { recursive: true });
      await mkdir(path.join(fixture, "src", "app", "api", "auth", "[...all]"), { recursive: true });
      await cp(
        path.join(root, "deployment", "nginx", "vasi-public.conf.example"),
        path.join(fixture, "deployment", "nginx", "vasi-public.conf.example"),
      );
      await cp(
        path.join(root, "deployment", "nginx", "Dockerfile.overlay"),
        path.join(fixture, "deployment", "nginx", "Dockerfile.overlay"),
      );
      await cp(
        path.join(root, "scripts", "probe-public-ingress.mjs"),
        path.join(fixture, "scripts", "probe-public-ingress.mjs"),
      );
      await cp(
        path.join(root, "scripts", "probe-public-route-isolation.mjs"),
        path.join(fixture, "scripts", "probe-public-route-isolation.mjs"),
      );
      await cp(path.join(root, "src", "proxy.ts"), path.join(fixture, "src", "proxy.ts"));
      await cp(
        path.join(root, "src", "app", "api", "auth", "[...all]", "route.ts"),
        path.join(fixture, "src", "app", "api", "auth", "[...all]", "route.ts"),
      );
      for (const filename of ["access-denial.ts", "admin-access.ts", "owner-access.ts", "participant-access.ts"]) {
        await cp(path.join(root, "src", "lib", filename), path.join(fixture, "src", "lib", filename));
      }
      for (const namespace of ["admin", "evidence", "owner", "workspace"]) {
        await cp(
          path.join(root, "src", "app", "api", namespace),
          path.join(fixture, "src", "app", "api", namespace),
          { recursive: true },
        );
      }
      await cp(path.join(root, "src", "app", "r"), path.join(fixture, "src", "app", "r"), { recursive: true });
      for (const filename of [
        "src/app/admin/page.tsx",
        "src/app/admin/evidence/page.tsx",
        "src/app/owner/page.tsx",
        "src/app/workspace/page.tsx",
      ]) {
        await mkdir(path.dirname(path.join(fixture, filename)), { recursive: true });
        await cp(path.join(root, filename), path.join(fixture, filename));
      }
      const filename = path.join(fixture, "deployment", "nginx", "vasi-public.conf.example");
      await writeFile(
        filename,
        (await readFile(filename, "utf8"))
          .replace("client_max_body_size 64k", "client_max_body_size 128m")
          .replace("$remote_addr;\n        proxy_set_header X-Forwarded-Proto", "$proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto"),
      );
      await writeFile(path.join(fixture, "package.json"), JSON.stringify({
        scripts: {
          "assurance:ingress": "node scripts/probe-public-ingress.mjs",
          "assurance:routes": "node scripts/probe-public-route-isolation.mjs",
          "ingress:config": "node scripts/public-ingress-config.mjs",
        },
      }));
      const result = await validatePublicIngressContract(fixture);
      expect(result.failures).toContain(
        "the sanitized public ingress example differs from canonical rendering",
      );
      expect(result.failures.join("; ")).toContain("client_max_body_size 64k");
      expect(result.failures.join("; ")).toContain("replace x-forwarded-for");
      expect(result.failures.join("; ")).not.toContain("sensitive gateway route inventory");
      await writeFile(
        path.join(fixture, "src", "proxy.ts"),
        (await readFile(path.join(fixture, "src", "proxy.ts"), "utf8"))
          .replace('"Cache-Control": "no-store",', 'Location: "https://attacker.invalid",'),
      );
      expect((await validatePublicIngressContract(fixture)).failures.join("; ")).toContain(
        'public page method boundary is missing "Cache-Control": "no-store"',
      );
      await writeFile(
        path.join(fixture, "deployment", "nginx", "Dockerfile.overlay"),
        "FROM nginx:latest\nCOPY . /etc/nginx\n",
      );
      expect((await validatePublicIngressContract(fixture)).failures.join("; ")).toContain(
        "replace only vasi.conf on an explicit base",
      );
      const routeProbe = path.join(fixture, "scripts", "probe-public-route-isolation.mjs");
      await writeFile(
        routeProbe,
        (await readFile(routeProbe, "utf8")).replaceAll('"set-cookie"', '"cookie-disabled"'),
      );
      expect((await validatePublicIngressContract(fixture)).failures.join("; ")).toContain(
        'public sensitive-route probe is missing "set-cookie"',
      );
      const accessDenial = path.join(fixture, "src", "lib", "access-denial.ts");
      await writeFile(
        accessDenial,
        (await readFile(accessDenial, "utf8")).replace('Vary: "Host"', 'Vary: "Accept"'),
      );
      expect((await validatePublicIngressContract(fixture)).failures.join("; ")).toContain(
        'bounded gateway access-denial helper is missing Vary: "Host"',
      );
      const adminPage = path.join(fixture, "src", "app", "admin", "page.tsx");
      await writeFile(adminPage, `${await readFile(adminPage, "utf8")}\nexport const metadata = { title: "Private" };\n`);
      expect((await validatePublicIngressContract(fixture)).failures).toContain(
        "src/app/admin/page.tsx contains unauthenticated static protected-page metadata",
      );
    } finally {
      await rm(fixture, { force: true, recursive: true });
    }
  });

  it("rejects weakened production image dependency installation or pruning", async () => {
    const fixture = await mkdtemp(path.join(tmpdir(), "vasi-image-build-assurance-"));
    try {
      await cp(path.join(root, "Dockerfile"), path.join(fixture, "Dockerfile"));
      await cp(path.join(root, "Dockerfile.engine"), path.join(fixture, "Dockerfile.engine"));
      const gateway = path.join(fixture, "Dockerfile");
      const engine = path.join(fixture, "Dockerfile.engine");
      await writeFile(
        gateway,
        (await readFile(gateway, "utf8"))
          .replace(" --omit=optional --ignore-scripts --no-audit --no-fund", "")
          .replace("RUN rm -rf /app/node_modules/pg-cloudflare\n", ""),
      );
      await writeFile(
        engine,
        (await readFile(engine, "utf8")).replace("--ignore-scripts", "--foreground-scripts"),
      );
      const result = await validateRuntimeImageBuildContract(fixture);
      expect(result.failures).toContain(
        "Dockerfile production-dependencies must use the exact production dependency install",
      );
      expect(result.failures).toContain(
        "Dockerfile.engine dependencies must use the exact production dependency install",
      );
      expect(result.failures).toContain(
        "Dockerfile must remove the unrelated standalone optional dependency before USER node",
      );
    } finally {
      await rm(fixture, { force: true, recursive: true });
    }
  });

  it("rejects a weakened engine host runtime preparation contract", async () => {
    const fixture = await mkdtemp(path.join(tmpdir(), "vasi-host-runtime-assurance-"));
    try {
      await mkdir(path.join(fixture, "scripts"));
      await cp(
        path.join(root, "scripts", "prepare-engine-host-runtime.sh"),
        path.join(fixture, "scripts", "prepare-engine-host-runtime.sh"),
      );
      await cp(
        path.join(root, "scripts", "direct-execution.mjs"),
        path.join(fixture, "scripts", "direct-execution.mjs"),
      );
      await cp(
        path.join(root, "scripts", "verify-engine-host-runtime.mjs"),
        path.join(fixture, "scripts", "verify-engine-host-runtime.mjs"),
      );
      const packageSource = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
      packageSource.scripts["host:prepare:engine"] = "npm install";
      await writeFile(path.join(fixture, "package.json"), JSON.stringify(packageSource));
      const preparation = path.join(fixture, "scripts", "prepare-engine-host-runtime.sh");
      await writeFile(
        preparation,
        (await readFile(preparation, "utf8"))
          .replace("--ignore-scripts", "--foreground-scripts")
          .replace(
            "/usr/bin/install -o root -g root -m 0644 scripts/direct-execution.mjs \\\n  /usr/local/libexec/vasi/direct-execution.mjs\n",
            "",
          ),
      );
      const result = await validateEngineHostRuntimeContract(fixture);
      expect(result.failures).toContain(
        "engine host runtime preparation weakens exact production installation",
      );
      expect(result.failures).toContain(
        "package.json is missing the exact engine host runtime preparation command",
      );
      expect(result.failures).toContain(
        "engine host runtime preparation is missing /usr/bin/install -o root -g root -m 0644 scripts/direct-execution.mjs \\",
      );
    } finally {
      await rm(fixture, { force: true, recursive: true });
    }
  });

  it("rejects weakened or installation-specific scheduler state", async () => {
    const fixture = await mkdtemp(path.join(tmpdir(), "vasi-systemd-assurance-"));
    try {
      await cp(path.join(root, "deployment"), path.join(fixture, "deployment"), { recursive: true });
      const timer = path.join(fixture, "deployment", "systemd", "vasi-engine-operational-readiness.timer");
      await writeFile(timer, (await readFile(timer, "utf8")).replace("Persistent=yes", "Persistent=no"));
      const service = path.join(fixture, "deployment", "systemd", "vasi-gateway-backup-create.service");
      await writeFile(
        service,
        `${(await readFile(service, "utf8")).replace(
          "OnFailure=vasi-gateway-alert-record@%n.service\n",
          "",
        )}\nEnvironmentFile=/home/customer/.env\n`,
      );
      const alertReadiness = path.join(
        fixture,
        "deployment",
        "systemd",
        "vasi-gateway-alert-readiness.service",
      );
      await writeFile(
        alertReadiness,
        `${await readFile(alertReadiness, "utf8")}\nOnFailure=vasi-gateway-alert-record@%n.service\n`,
      );
      const nodeService = path.join(
        fixture,
        "deployment",
        "systemd",
        "vasi-engine-deployment-readiness.service",
      );
      await writeFile(
        nodeService,
        `${(await readFile(nodeService, "utf8")).replace(
          "ExecStartPre=/usr/bin/env node /usr/local/libexec/vasi/verify-engine-host-runtime.mjs\n",
          "",
        )}\nMemoryDenyWriteExecute=yes\n`,
      );
      const result = await validateOperationalSchedulerContract(fixture);
      expect(result.failures).toContain("vasi-engine-operational-readiness.timer is missing Persistent=yes");
      expect(result.failures).toContain(
        "vasi-gateway-backup-create.service contains a prohibited privilege or configuration path",
      );
      expect(result.failures).toContain(
        "vasi-gateway-backup-create.service is missing OnFailure=vasi-gateway-alert-record@%n.service",
      );
      expect(result.failures).toContain(
        "vasi-gateway-alert-readiness.service must not recursively trigger operational alerts",
      );
      expect(result.failures).toContain(
        "vasi-engine-deployment-readiness.service cannot deny executable memory to the direct Node runtime",
      );
      expect(result.failures).toContain(
        "vasi-engine-deployment-readiness.service is missing ExecStartPre=/usr/bin/env node /usr/local/libexec/vasi/verify-engine-host-runtime.mjs",
      );
    } finally {
      await rm(fixture, { force: true, recursive: true });
    }
  });

  it("rejects a transport-coupled or expanded operational-alert recorder", async () => {
    const fixture = await mkdtemp(path.join(tmpdir(), "vasi-alert-handoff-assurance-"));
    try {
      await mkdir(path.join(fixture, "scripts"));
      const target = path.join(fixture, "scripts", "operational-alert-spool.sh");
      await cp(path.join(root, "scripts", "operational-alert-spool.sh"), target);
      await writeFile(
        target,
        `${(await readFile(target, "utf8"))
          .replace("MAX_PENDING=256", "MAX_PENDING=10000")
          .replace("gateway:vasi-gateway-backup-check.service|\\\n", "")}
curl https://monitor.example.test\n`,
      );
      const result = await validateOperationalAlertHandoffContract(fixture);
      expect(result.failures).toContain(
        "the durable operational-alert handoff is missing MAX_PENDING=256",
      );
      expect(result.failures).toContain(
        "the durable operational-alert source-unit allowlist is not exact",
      );
      expect(result.failures).toContain(
        "the durable operational-alert handoff contains transport, ambient configuration, or destructive behavior",
      );
    } finally {
      await rm(fixture, { force: true, recursive: true });
    }
  });

  it("requires an explicit non-root readability contract for every release image role", () => {
    expect(runtimeContractForImage("vasi:0.51.0")).toMatchObject({
      allowedOptionalPackagePaths: [
        "node_modules/@img/colour",
        "node_modules/@img/sharp-libvips-linuxmusl-x64",
        "node_modules/@img/sharp-linuxmusl-x64",
        "node_modules/detect-libc",
        "node_modules/semver",
        "node_modules/sharp",
      ],
      entrypoints: ["server.js"],
      imageUser: "node",
      runUser: "1000:1000",
    });
    expect(runtimeContractForImage("registry.example.test/vasi-engine:0.51.0")).toMatchObject({
      entrypoints: [
        "scripts/engine-migrate.mjs",
        "services/engine/server.mjs",
        "services/integration-gateway/server.mjs",
        "services/private-ingress/server.mjs",
        "services/worker/worker.mjs",
      ],
      imageUser: "node",
      runUser: "1000:1000",
    });
    expect(runtimeContractForImage(`vasi-engine-tools@sha256:${"a".repeat(64)}`)).toMatchObject({
      entrypoints: [
        "scripts/probe-engine-egress-boundary.mjs",
        "scripts/render-database-egress-policy.mjs",
        "scripts/render-private-ingress-egress-policy.mjs",
        "scripts/settings.mjs",
      ],
      imageUser: "",
      runUser: "0:0",
    });
    expect(runtimeContractForImage("vasi-engine-maintenance:0.51.0")).toMatchObject({
      entrypoints: [
        "scripts/backup-custody.mjs",
        "scripts/backup-continuity.mjs",
        "scripts/backup.mjs",
        "scripts/probe-capacity-readiness.mjs",
        "scripts/probe-deployment-readiness.mjs",
        "scripts/probe-gateway-operational-readiness.mjs",
        "scripts/probe-operational-readiness.mjs",
        "scripts/tenant-transfer.mjs",
      ],
      imageUser: "node",
      runUser: "1000:1000",
    });
    expect(runtimeContractForImage("vasi-database-gateway:0.51.0")).toMatchObject({
      entrypoints: ["services/database-gateway/server.mjs"],
      imageUser: "node",
      runUser: "1000:1000",
    });
    expect(() => runtimeContractForImage("unreviewed-image:latest")).toThrow(/no supported runtime contract/i);
    expect(() => runtimeContractForImage("vasi:latest", [{
      entrypoints: ["../server.js"],
      image: "vasi",
      imageUser: "node",
      runUser: "1000:1000",
    }])).toThrow(/no supported runtime contract/i);
  });

  it("derives a bounded physical prohibition inventory from the exact lock graph", async () => {
    const packageJSON = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
    const packageLock = JSON.parse(await readFile(path.join(root, "package-lock.json"), "utf8"));
    const allowed = runtimeContractForImage("vasi:0.51.0").allowedOptionalPackagePaths;
    const result = runtimeDependencyAuditPaths(packageJSON, packageLock, allowed);
    expect(result.lockPackageCount).toBeGreaterThan(400);
    expect(result.prohibitedPackagePaths).toContain("node_modules/vitest");
    expect(result.prohibitedPackagePaths).toContain("node_modules/vite");
    expect(result.prohibitedPackagePaths).toContain("node_modules/pg-cloudflare");
    expect(result.prohibitedPackagePaths).not.toContain("node_modules/sharp");
    expect(result.prohibitedToolPaths).toContain("/usr/local/bin/npm");
    expect(result.prohibitedToolPaths).toContain("/usr/local/bin/npx");
    expect(() => runtimeDependencyAuditPaths(
      packageJSON,
      packageLock,
      ["node_modules/not-a-reviewed-optional-package"],
    )).toThrow(/unsupported optional-package exception/i);
  });

  it("rejects unsafe, malformed, and unbounded dependency inventories", () => {
    const packageJSON = {
      dependencies: { pg: "8.22.0" },
      devDependencies: { vitest: "4.1.10" },
    };
    const valid = {
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/pg": {},
        "node_modules/vitest": { dev: true },
      },
    };
    expect(runtimeDependencyAuditPaths(packageJSON, valid).prohibitedPackagePaths).toEqual([
      "node_modules/vitest",
    ]);
    expect(() => runtimeDependencyAuditPaths(packageJSON, {
      ...valid,
      packages: { ...valid.packages, "node_modules/../escape": { dev: true } },
    })).toThrow(/unsafe package-lock path/i);
    expect(() => runtimeDependencyAuditPaths(packageJSON, {
      ...valid,
      packages: { ...valid.packages, "node_modules/bad": { optional: "yes" } },
    })).toThrow(/malformed package-lock flags/i);
    expect(() => runtimeDependencyAuditPaths(packageJSON, {
      ...valid,
      packages: Object.fromEntries([
        ["", {}],
        ...Array.from({ length: 10000 }, (_, index) => [
          `node_modules/package-${index}`,
          { dev: true },
        ]),
      ]),
    })).toThrow(/outside its assurance bound/i);
  });
});

function operationalSources(tracked) {
  return [...new Set([
    ...tracked.files.map((entry) => entry.path),
    ...DIRECT_EXECUTION_ENTRYPOINTS,
  ])];
}
