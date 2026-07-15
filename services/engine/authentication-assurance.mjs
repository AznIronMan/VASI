import {
  authenticationAssurancePolicy,
  evaluateAuthenticationAssurance,
} from "../../packages/engine-domain/workflow.mjs";
import { EngineStoreError } from "./errors.mjs";

export const PARTICIPANT_DATA_AUTHENTICATION_ASSURANCE = Object.freeze({
  acceptedMethods: Object.freeze(["any_verified"]),
  maximumAgeSeconds: 900,
});

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

export function requireRecentParticipantDataAuthentication(actor, evaluatedAt = new Date()) {
  return requireAuthenticationAssurance({
    authenticationAssurance: PARTICIPANT_DATA_AUTHENTICATION_ASSURANCE,
  }, actor, evaluatedAt);
}
