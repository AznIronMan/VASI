type HeaderReader = Pick<Headers, "get">;

export function requestHostname(headers: HeaderReader) {
  const host = headers.get("host")?.trim().toLowerCase();
  if (!host) return undefined;

  try {
    return new URL(`http://${host}`).hostname;
  } catch {
    return undefined;
  }
}

export function isRequestForOrigin(headers: HeaderReader, origin: string) {
  return requestHostname(headers) === new URL(origin).hostname.toLowerCase();
}

export function hasExpectedMutationOrigin(headers: HeaderReader, origin: string) {
  const value = headers.get("origin");
  if (!value) return false;

  try {
    return new URL(value).origin === new URL(origin).origin;
  } catch {
    return false;
  }
}

export function isCrossSiteRequest(headers: HeaderReader) {
  const site = headers.get("sec-fetch-site");
  return Boolean(site && site !== "same-origin" && site !== "none");
}
