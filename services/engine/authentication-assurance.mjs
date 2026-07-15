import {
  authenticationAssurancePolicy,
  evaluateAuthenticationAssurance,
} from "../../packages/engine-domain/workflow.mjs";
import { EngineStoreError } from "./errors.mjs";

export function requireAuthenticationAssurance(accessPolicy, actor, evaluatedAt = new Date()) {
  let evaluation;
  try {
    evaluation = evaluateAuthenticationAssurance(
      authenticationAssurancePolicy(accessPolicy),
      actor,
      evaluatedAt,
    );
  } catch {
    throw new EngineStoreError("authentication_assurance_policy_invalid", 500);
  }
  if (!evaluation.satisfied) {
    throw new EngineStoreError(
      evaluation.reason,
      evaluation.reason === "reauthentication_required" ? 401 : 403,
    );
  }
  return evaluation;
}
