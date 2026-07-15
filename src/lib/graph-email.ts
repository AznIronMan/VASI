type GraphEmailEnvironment = Record<string, string | undefined>;

type GraphEmailMessage = {
  to: string;
  subject: string;
  html: string;
};

type GraphAccessToken = {
  access_token?: string;
  expires_in?: number;
};

type CachedAccessToken = {
  value: string;
  expiresAt: number;
};

const graphConfigurationKeys = [
  "GRAPH_TENANT_ID",
  "GRAPH_CLIENT_ID",
  "GRAPH_CLIENT_SECRET",
  "GRAPH_SENDER_EMAIL",
] as const;

let cachedAccessToken: CachedAccessToken | undefined;

export function hasGraphEmailConfiguration(
  environment: GraphEmailEnvironment,
) {
  return graphConfigurationKeys.every((key) => Boolean(environment[key]?.trim()));
}

export async function sendGraphEmail(
  message: GraphEmailMessage,
  environment: GraphEmailEnvironment,
  request: typeof fetch = fetch,
) {
  if (!hasGraphEmailConfiguration(environment)) {
    throw new Error("Microsoft Graph email is not fully configured.");
  }

  const accessToken = await getGraphAccessToken(environment, request);
  const sender = environment.GRAPH_SENDER_EMAIL!;
  let response: Response;
  try {
    response = await request(
      `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(sender)}/sendMail`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: {
            subject: message.subject,
            body: {
              contentType: "HTML",
              content: message.html,
            },
            toRecipients: [
              {
                emailAddress: {
                  address: message.to,
                },
              },
            ],
          },
        }),
        signal: AbortSignal.timeout(10_000),
      },
    );
  } catch (error) {
    throw new GraphEmailDeliveryError(
      "Microsoft Graph transactional email outcome is unknown.",
      "unknown",
      { cause: error },
    );
  }

  if (response.status !== 202) {
    throw new GraphEmailDeliveryError(
      "Microsoft Graph rejected the transactional email request.",
      "failed",
    );
  }
}

export class GraphEmailDeliveryError extends Error {
  constructor(
    message: string,
    public readonly outcome: "failed" | "unknown",
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

async function getGraphAccessToken(
  environment: GraphEmailEnvironment,
  request: typeof fetch,
) {
  if (cachedAccessToken && cachedAccessToken.expiresAt > Date.now()) {
    return cachedAccessToken.value;
  }

  const tenantId = environment.GRAPH_TENANT_ID!;
  const response = await request(
    `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: environment.GRAPH_CLIENT_ID!,
        client_secret: environment.GRAPH_CLIENT_SECRET!,
        grant_type: "client_credentials",
        scope: "https://graph.microsoft.com/.default",
      }),
      signal: AbortSignal.timeout(10_000),
    },
  );

  if (!response.ok) {
    throw new Error("Microsoft Graph token acquisition failed.");
  }

  const token = (await response.json()) as GraphAccessToken;
  if (!token.access_token || !token.expires_in || token.expires_in <= 60) {
    throw new Error("Microsoft Graph returned an invalid access token response.");
  }

  cachedAccessToken = {
    value: token.access_token,
    expiresAt: Date.now() + (token.expires_in - 60) * 1_000,
  };

  return cachedAccessToken.value;
}

export function resetGraphTokenCacheForTests() {
  cachedAccessToken = undefined;
}
