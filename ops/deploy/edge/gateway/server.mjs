import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

import { classifyRequest } from './policy.mjs';

const required = (name) => {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
};

const parseHttpsOrigin = (name) => {
  const url = new URL(required(name));
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error(`${name} must be an HTTPS origin without credentials, path, query, or fragment`);
  }
  return url;
};

const ipv4ToInteger = (address) => {
  if (net.isIPv4(address) === false) {
    throw new Error(`Unsupported trusted proxy address: ${address}`);
  }
  return address.split('.').reduce((value, octet) => (value * 256 + Number(octet)) >>> 0, 0);
};

const parseIpv4Cidr = (value) => {
  const [address, rawPrefix = '32'] = value.trim().split('/');
  const prefix = Number(rawPrefix);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error(`Invalid trusted proxy CIDR: ${value}`);
  }
  const numericAddress = ipv4ToInteger(address);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { network: numericAddress & mask, mask };
};

const normalizeRemoteAddress = (address) => (address?.startsWith('::ffff:') ? address.slice(7) : address || '');

const canonicalUrl = parseHttpsOrigin('VASI_PUBLIC_ORIGIN');
const originUrl = parseHttpsOrigin('VASI_ORIGIN_URL');
const trustedProxyCidrs = required('VASI_TRUSTED_PROXY_CIDRS').split(',').map(parseIpv4Cidr);
const originCa = fs.readFileSync(required('VASI_ORIGIN_CA_FILE'));
// biome-ignore lint/nursery/noUndeclaredEnvVars: This standalone deployment gateway does not run through Turborepo.
const oauthUrl = new URL(process.env.VASI_OAUTH2_PROXY_URL || 'http://oauth2-proxy:4180');
const listenPort = Number(process.env.PORT || 8080);
// biome-ignore lint/nursery/noUndeclaredEnvVars: This standalone deployment gateway does not run through Turborepo.
const pdfUploadLimitMib = Number(process.env.VASI_PDF_UPLOAD_LIMIT_MIB || 10);
const forbiddenCookieDomains = new Set(
  required('VASI_FORBIDDEN_COOKIE_DOMAINS')
    .split(',')
    .map((domain) => domain.trim().replace(/^\./, '').toLowerCase())
    .filter(Boolean),
);

if (
  oauthUrl.protocol !== 'http:' ||
  oauthUrl.pathname !== '/' ||
  oauthUrl.search ||
  oauthUrl.hash ||
  oauthUrl.username ||
  oauthUrl.password
) {
  throw new Error('VASI_OAUTH2_PROXY_URL must be an internal HTTP origin');
}

if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) {
  throw new Error('PORT must be a valid TCP port');
}

if (!Number.isInteger(pdfUploadLimitMib) || pdfUploadLimitMib < 1 || pdfUploadLimitMib > 100) {
  throw new Error('VASI_PDF_UPLOAD_LIMIT_MIB must be an integer from 1 through 100');
}

const pdfUploadBodyLimit = (pdfUploadLimitMib + 2) * 1024 * 1024;

const isTrustedProxy = (remoteAddress) => {
  const normalized = normalizeRemoteAddress(remoteAddress);
  if (!net.isIPv4(normalized)) {
    return false;
  }
  const numericAddress = ipv4ToInteger(normalized);
  return trustedProxyCidrs.some(({ network, mask }) => (numericAddress & mask) === network);
};

const verifiedClientIp = (request) => {
  const value = request.headers['x-forwarded-for'];
  if (typeof value !== 'string' || value.includes(',')) {
    return null;
  }
  const candidate = value.trim();
  return net.isIP(candidate) ? candidate : null;
};

const hasRequestBody = (request) => {
  const transferEncoding = request.headers['transfer-encoding'];
  const contentLength = request.headers['content-length'];
  if (transferEncoding) {
    return true;
  }
  if (contentLength === undefined) {
    return false;
  }
  return !/^0+$/.test(String(contentLength).trim());
};

const logEvent = ({ event, requestId, method, policy, status }) => {
  process.stdout.write(`${JSON.stringify({ event, requestId, method, policy, status })}\n`);
};

const send = (response, status, body, requestId, extraHeaders = {}) => {
  if (response.headersSent) {
    response.destroy();
    return;
  }
  const payload = body ? Buffer.from(body) : Buffer.alloc(0);
  response.writeHead(status, {
    'cache-control': 'no-store',
    'content-length': payload.length,
    'content-type': 'text/plain; charset=utf-8',
    'x-content-type-options': 'nosniff',
    'x-request-id': requestId,
    ...extraHeaders,
  });
  response.end(payload);
};

const removeRequestHopHeaders = (headers) => {
  const sanitized = { ...headers };
  for (const name of [
    'authorization',
    'cf-connecting-ip',
    'connection',
    'fastly-client-ip',
    'forwarded',
    'host',
    'proxy-authorization',
    'proxy-connection',
    'te',
    'trailer',
    'true-client-ip',
    'upgrade',
    'via',
    'x-cluster-client-ip',
    'x-client-ip',
    'x-envoy-external-address',
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-port',
    'x-forwarded-proto',
    'x-real-ip',
  ]) {
    delete sanitized[name];
  }
  for (const name of Object.keys(sanitized)) {
    if (name.startsWith('x-forwarded-') || name.startsWith('x-auth-request-') || name.startsWith('x-original-')) {
      delete sanitized[name];
    }
  }
  return sanitized;
};

const removeResponseHopHeaders = (headers) => {
  const sanitized = { ...headers };
  for (const name of [
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'server',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
    'x-auth-request-access-token',
    'x-auth-request-email',
    'x-auth-request-groups',
    'x-auth-request-preferred-username',
    'x-auth-request-user',
    'x-powered-by',
  ]) {
    delete sanitized[name];
  }
  for (const name of Object.keys(sanitized)) {
    if (name.startsWith('x-auth-request-')) {
      delete sanitized[name];
    }
  }
  return sanitized;
};

const cookieDomainViolation = (setCookieHeaders) => {
  for (const value of setCookieHeaders || []) {
    const match = /;\s*domain=([^;]+)/i.exec(value);
    if (!match) {
      continue;
    }
    const domain = match[1].trim().replace(/^\./, '').toLowerCase();
    if ([...forbiddenCookieDomains].some((forbidden) => domain === forbidden || domain.endsWith(`.${forbidden}`))) {
      return true;
    }
  }
  return false;
};

const combineSetCookies = (headers, pendingCookies = []) => {
  const upstreamCookies = headers['set-cookie'] || [];
  const combined = [...pendingCookies, ...upstreamCookies];
  if (combined.length > 0) {
    headers['set-cookie'] = combined;
  } else {
    delete headers['set-cookie'];
  }
};

const rateBuckets = new Map();
const RATE_LIMITS = {
  public_auth: { perMinute: 20, burst: 5 },
  public_trpc: { perMinute: 120, burst: 20 },
  token: { perMinute: 120, burst: 20 },
};

const isRateLimited = (clientIp, rateClass) => {
  const policy = RATE_LIMITS[rateClass];
  if (!policy) {
    return false;
  }
  const now = Date.now();
  const key = `${rateClass}:${clientIp}`;
  const capacity = policy.perMinute + policy.burst;
  const current = rateBuckets.get(key) || { tokens: capacity, updatedAt: now };
  const replenished = Math.min(capacity, current.tokens + ((now - current.updatedAt) * policy.perMinute) / 60_000);
  const limited = replenished < 1;
  rateBuckets.set(key, {
    tokens: limited ? replenished : replenished - 1,
    updatedAt: now,
  });

  if (rateBuckets.size > 20_000) {
    for (const [entryKey, entry] of rateBuckets) {
      if (entry.updatedAt < now - 10 * 60_000) {
        rateBuckets.delete(entryKey);
      }
    }
    while (rateBuckets.size > 20_000) {
      rateBuckets.delete(rateBuckets.keys().next().value);
    }
  }
  return limited;
};

const proxyOAuth = (request, response, requestId, clientIp) => {
  const method = request.method || 'GET';
  const oauthPath = (request.url || '').split('?', 1)[0];
  const allowedMethods = oauthPath.startsWith('/oauth2/static/')
    ? new Set(['GET', 'HEAD'])
    : oauthPath === '/oauth2/callback' || oauthPath === '/oauth2/sign_out'
      ? new Set(['GET', 'POST'])
      : oauthPath === '/oauth2/start' || oauthPath === '/oauth2/sign_in'
        ? new Set(['GET'])
        : null;

  if (!allowedMethods || !allowedMethods.has(method)) {
    send(response, 404, 'Not found\n', requestId);
    return;
  }

  if (new Set(['POST', 'PUT', 'PATCH', 'DELETE']).has(method) && request.headers.origin !== canonicalUrl.origin) {
    send(response, 403, 'Forbidden\n', requestId);
    return;
  }

  const contentLength = request.headers['content-length'];
  if (
    contentLength !== undefined &&
    (!/^\d+$/.test(String(contentLength)) || Number(contentLength) > 2 * 1024 * 1024)
  ) {
    send(response, 413, 'Payload too large\n', requestId);
    return;
  }

  const headers = removeRequestHopHeaders(request.headers);
  Object.assign(headers, {
    host: canonicalUrl.host,
    'x-forwarded-for': clientIp,
    'x-forwarded-host': canonicalUrl.host,
    'x-forwarded-port': '443',
    'x-forwarded-proto': 'https',
    'x-real-ip': clientIp,
    'x-request-id': requestId,
  });

  const upstream = http.request(
    {
      hostname: oauthUrl.hostname,
      port: oauthUrl.port || 80,
      method,
      path: request.url,
      headers,
      timeout: 60_000,
    },
    (upstreamResponse) => {
      const responseHeaders = removeResponseHopHeaders(upstreamResponse.headers);
      if (cookieDomainViolation(responseHeaders['set-cookie'])) {
        upstreamResponse.destroy();
        send(response, 502, 'Bad gateway\n', requestId);
        return;
      }
      responseHeaders['x-request-id'] = requestId;
      response.writeHead(upstreamResponse.statusCode || 502, responseHeaders);
      upstreamResponse.pipe(response);
    },
  );

  upstream.on('timeout', () => upstream.destroy(new Error('oauth_timeout')));
  upstream.on('error', () => send(response, 502, 'Bad gateway\n', requestId));
  let received = 0;
  let exceeded = false;
  request.on('data', (chunk) => {
    if (exceeded) {
      return;
    }
    received += chunk.length;
    if (received > 2 * 1024 * 1024) {
      exceeded = true;
      upstream.destroy();
      send(response, 413, 'Payload too large\n', requestId);
      return;
    }
    if (!upstream.write(chunk)) {
      request.pause();
      upstream.once('drain', () => request.resume());
    }
  });
  request.on('end', () => {
    if (!exceeded) {
      upstream.end();
    }
  });
  request.on('aborted', () => upstream.destroy());
};

const authenticateStaff = (request, requestId, clientIp) =>
  new Promise((resolve) => {
    const authRequest = http.request(
      {
        hostname: oauthUrl.hostname,
        port: oauthUrl.port || 80,
        method: 'GET',
        path: '/oauth2/auth',
        headers: {
          cookie: request.headers.cookie || '',
          host: canonicalUrl.host,
          'x-forwarded-for': clientIp,
          'x-forwarded-host': canonicalUrl.host,
          'x-forwarded-port': '443',
          'x-forwarded-proto': 'https',
          'x-forwarded-uri': request.url || '/',
          'x-real-ip': clientIp,
          'x-request-id': requestId,
        },
        timeout: 10_000,
      },
      (authResponse) => {
        authResponse.resume();
        authResponse.on('end', () =>
          resolve({
            authenticated: authResponse.statusCode === 202 || authResponse.statusCode === 200,
            cookies: authResponse.headers['set-cookie'] || [],
          }),
        );
      },
    );
    authRequest.on('timeout', () => authRequest.destroy(new Error('auth_timeout')));
    authRequest.on('error', () => resolve({ authenticated: false, cookies: [], unavailable: true }));
    authRequest.end();
  });

const readinessProbe = () =>
  Promise.all([
    new Promise((resolve) => {
      const probe = http.get(
        {
          hostname: oauthUrl.hostname,
          port: oauthUrl.port || 80,
          path: '/ping',
          timeout: 3_000,
        },
        (probeResponse) => {
          probeResponse.resume();
          probeResponse.on('end', () => resolve(probeResponse.statusCode === 200));
        },
      );
      probe.on('timeout', () => probe.destroy(new Error('oauth_probe_timeout')));
      probe.on('error', () => resolve(false));
    }),
    new Promise((resolve) => {
      const probe = https.get(
        {
          hostname: originUrl.hostname,
          port: originUrl.port || 443,
          path: '/healthz',
          headers: { host: originUrl.host },
          ca: originCa,
          rejectUnauthorized: true,
          servername: originUrl.hostname,
          timeout: 3_000,
        },
        (probeResponse) => {
          probeResponse.resume();
          probeResponse.on('end', () => resolve(probeResponse.statusCode === 200));
        },
      );
      probe.on('timeout', () => probe.destroy(new Error('origin_probe_timeout')));
      probe.on('error', () => resolve(false));
    }),
  ]).then((results) => results.every(Boolean));

const proxyToOrigin = ({ request, response, requestId, clientIp, decision, authCookies }) => {
  const contentLength = request.headers['content-length'];
  if (
    contentLength !== undefined &&
    (!/^\d+$/.test(String(contentLength)) || Number(contentLength) > decision.bodyLimit)
  ) {
    send(response, 413, 'Payload too large\n', requestId);
    return;
  }

  const headers = removeRequestHopHeaders(request.headers);
  Object.assign(headers, {
    host: canonicalUrl.host,
    'x-forwarded-for': clientIp,
    'x-forwarded-host': canonicalUrl.host,
    'x-forwarded-port': '443',
    'x-forwarded-proto': 'https',
    'x-real-ip': clientIp,
    'x-request-id': requestId,
  });

  const extendedTimeout =
    decision.bodyLimit > 2 * 1024 * 1024 || /\/(?:download|item\.pdf)(?:\/|$)/.test(request.url || '');
  const upstream = https.request(
    {
      hostname: originUrl.hostname,
      port: originUrl.port || 443,
      method: request.method,
      path: request.url,
      headers,
      ca: originCa,
      rejectUnauthorized: true,
      servername: originUrl.hostname,
      timeout: extendedTimeout ? 300_000 : 60_000,
    },
    (upstreamResponse) => {
      const responseHeaders = removeResponseHopHeaders(upstreamResponse.headers);
      const combinedLogout = request.method === 'POST' && (request.url || '').split('?', 1)[0] === '/api/auth/signout';
      const portalLogoutCookie =
        combinedLogout && (upstreamResponse.statusCode || 500) < 400
          ? ['__Host-vasi_staff=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax']
          : [];
      combineSetCookies(responseHeaders, [...authCookies, ...portalLogoutCookie]);

      if (cookieDomainViolation(responseHeaders['set-cookie'])) {
        upstreamResponse.destroy();
        logEvent({
          event: 'cookie_domain_violation',
          requestId,
          method: request.method,
          policy: decision.policy,
          status: 502,
        });
        send(response, 502, 'Bad gateway\n', requestId);
        return;
      }

      if (typeof responseHeaders.location === 'string') {
        try {
          const location = new URL(responseHeaders.location, canonicalUrl);
          if (location.hostname === originUrl.hostname) {
            responseHeaders.location = `${canonicalUrl.origin}${location.pathname}${location.search}${location.hash}`;
            logEvent({
              event: 'origin_location_rewritten',
              requestId,
              method: request.method,
              policy: decision.policy,
              status: upstreamResponse.statusCode,
            });
          }
        } catch {
          delete responseHeaders.location;
        }
      }

      responseHeaders['x-request-id'] = requestId;
      response.writeHead(upstreamResponse.statusCode || 502, responseHeaders);
      upstreamResponse.pipe(response);
      upstreamResponse.on('end', () =>
        logEvent({
          event: 'request',
          requestId,
          method: request.method,
          policy: decision.policy,
          status: upstreamResponse.statusCode,
        }),
      );
    },
  );

  upstream.on('timeout', () => upstream.destroy(new Error('origin_timeout')));
  upstream.on('error', () => send(response, 502, 'Bad gateway\n', requestId));

  let received = 0;
  let exceeded = false;
  request.on('data', (chunk) => {
    if (exceeded) {
      return;
    }
    received += chunk.length;
    if (received > decision.bodyLimit) {
      exceeded = true;
      upstream.destroy();
      send(response, 413, 'Payload too large\n', requestId);
      return;
    }
    if (!upstream.write(chunk)) {
      request.pause();
      upstream.once('drain', () => request.resume());
    }
  });
  request.on('end', () => {
    if (!exceeded) {
      upstream.end();
    }
  });
  request.on('aborted', () => upstream.destroy());
};

const server = http.createServer(async (request, response) => {
  const requestId = randomUUID();
  const method = request.method || 'GET';

  if (request.url === '/healthz' && (method === 'GET' || method === 'HEAD')) {
    const body = method === 'HEAD' ? '' : '{"status":"ok"}\n';
    send(response, 200, body, requestId, { 'content-type': 'application/json; charset=utf-8' });
    return;
  }

  if (
    request.url === '/readyz' &&
    (method === 'GET' || method === 'HEAD') &&
    normalizeRemoteAddress(request.socket.remoteAddress) === '127.0.0.1'
  ) {
    const ready = await readinessProbe();
    const body = method === 'HEAD' ? '' : ready ? '{"status":"ready"}\n' : '{"status":"unavailable"}\n';
    send(response, ready ? 200 : 503, body, requestId, { 'content-type': 'application/json; charset=utf-8' });
    return;
  }

  if (!isTrustedProxy(request.socket.remoteAddress)) {
    send(response, 403, 'Forbidden\n', requestId);
    return;
  }

  const clientIp = verifiedClientIp(request);
  if (!clientIp || String(request.headers.host || '').toLowerCase() !== canonicalUrl.host.toLowerCase()) {
    send(response, 400, 'Bad request\n', requestId);
    return;
  }

  if ((request.headers.connection || '').toLowerCase().includes('upgrade') || request.headers.upgrade) {
    send(response, 400, 'Bad request\n', requestId);
    return;
  }

  if ((request.url || '').startsWith('/oauth2/')) {
    proxyOAuth(request, response, requestId, clientIp);
    return;
  }

  const decision = classifyRequest({
    method,
    rawTarget: request.url,
    canonicalOrigin: canonicalUrl.origin,
    origin: request.headers.origin,
    hasBody: hasRequestBody(request),
    pdfUploadBodyLimit,
  });

  if (decision.policy === 'method_not_allowed') {
    send(response, 405, 'Method not allowed\n', requestId, { allow: decision.allowedMethods.join(', ') });
    return;
  }

  if (decision.policy === 'malformed' || decision.policy === 'origin_rejected') {
    send(response, decision.policy === 'origin_rejected' ? 403 : 400, 'Bad request\n', requestId);
    return;
  }

  if (decision.policy === 'blocked') {
    send(response, 404, 'Not found\n', requestId);
    return;
  }

  const declaredLength = request.headers['content-length'];
  if (
    declaredLength !== undefined &&
    (!/^\d+$/.test(String(declaredLength)) || Number(declaredLength) > decision.bodyLimit)
  ) {
    send(response, 413, 'Payload too large\n', requestId);
    return;
  }

  if (isRateLimited(clientIp, decision.rateClass)) {
    send(response, 429, 'Too many requests\n', requestId, { 'retry-after': '60' });
    return;
  }

  let authCookies = [];
  if (decision.policy === 'staff') {
    const auth = await authenticateStaff(request, requestId, clientIp);
    if (auth.unavailable) {
      send(response, 503, 'Service unavailable\n', requestId);
      return;
    }
    authCookies = auth.cookies;
    if (!auth.authenticated) {
      if ((request.url || '').startsWith('/api/')) {
        send(response, 401, 'Authentication required\n', requestId, { 'set-cookie': authCookies });
      } else {
        const returnTo = `${canonicalUrl.origin}${request.url || '/'}`;
        send(response, 302, '', requestId, {
          location: `/oauth2/start?rd=${encodeURIComponent(returnTo)}`,
          'set-cookie': authCookies,
        });
      }
      return;
    }
  }

  proxyToOrigin({ request, response, requestId, clientIp, decision, authCookies });
});

server.on('upgrade', (_request, socket) => {
  socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
});

server.on('clientError', (_error, socket) => {
  socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
});

server.listen(listenPort, '0.0.0.0', () => {
  process.stdout.write(`${JSON.stringify({ event: 'listening', port: listenPort })}\n`);
});
