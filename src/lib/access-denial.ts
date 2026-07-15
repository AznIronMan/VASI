const NO_STORE_HEADERS = Object.freeze({
  "Cache-Control": "no-store",
});

export function hiddenResourceResponse() {
  return new Response(null, {
    headers: {
      ...NO_STORE_HEADERS,
      Vary: "Host",
    },
    status: 404,
  });
}

export function accessDenialResponse(error: string, status: 401 | 403) {
  if (!error || error.length > 160 || /[\r\n]/.test(error)) {
    throw new Error("The access-denial message is outside its bound.");
  }
  return Response.json({ error }, { headers: NO_STORE_HEADERS, status });
}
