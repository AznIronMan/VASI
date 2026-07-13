import { importPKCS8, SignJWT } from "jose";

const APPLE_AUDIENCE = "https://appleid.apple.com";
const APPLE_SECRET_LIFETIME_SECONDS = 180 * 24 * 60 * 60;

export async function generateAppleClientSecret({
  clientId,
  teamId,
  keyId,
  privateKey,
  now = Math.floor(Date.now() / 1000),
}: {
  clientId: string;
  teamId: string;
  keyId: string;
  privateKey: string;
  now?: number;
}) {
  const normalizedPrivateKey = privateKey.replaceAll("\\n", "\n");
  const signingKey = await importPKCS8(normalizedPrivateKey, "ES256");

  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: keyId })
    .setIssuer(teamId)
    .setSubject(clientId)
    .setAudience(APPLE_AUDIENCE)
    .setIssuedAt(now)
    .setExpirationTime(now + APPLE_SECRET_LIFETIME_SECONDS)
    .sign(signingKey);
}
