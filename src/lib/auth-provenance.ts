export type SessionAuthentication = {
  method: "email_verification" | "federated" | "password" | "session_unspecified";
  provider?: string;
  provenance: "better-auth-session-create-context/v1" | "session-context-unavailable/v1";
};

export function resolveSessionAuthentication(context: {
  params?: Record<string, unknown>;
  path?: string;
} | null): SessionAuthentication {
  const path = context?.path || "";
  if (path.startsWith("/callback/") || path.startsWith("/oauth2/callback/")) {
    const provider = stringValue(context?.params?.id) ||
      stringValue(context?.params?.providerId) ||
      path.split("/").filter(Boolean).at(-1);
    return {
      method: "federated",
      provider,
      provenance: "better-auth-session-create-context/v1",
    };
  }
  if (["/sign-in/email", "/sign-in/username"].includes(path)) {
    return {
      method: "password",
      provider: "credential",
      provenance: "better-auth-session-create-context/v1",
    };
  }
  if (path === "/verify-email") {
    return {
      method: "email_verification",
      provenance: "better-auth-session-create-context/v1",
    };
  }
  return {
    method: "session_unspecified",
    provenance: "session-context-unavailable/v1",
  };
}

function stringValue(value: unknown) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}
