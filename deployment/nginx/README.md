# Nginx public ingress reference

`vasi-public.conf.example` is a sanitized, valid Nginx `http`-context include.
Do not edit it into an installation-specific file or add certificates, private
addresses, or customer hostnames to this directory.

The generated HTTP server redirects to the validated configured public host,
not `$host` or another request-derived value. The application independently
rejects non-GET/HEAD page methods; do not replace that contract with an opaque
edge include or broad method rule that also intercepts reviewed API routes.

Render an installation file with the tracked command and explicit non-secret
deployment inputs:

```bash
npm run ingress:config -- render \
  --public-host vsign.example.com \
  --gateway-upstream-name vasi_public_gateway \
  --gateway-upstream-address 127.0.0.1:3000 \
  --public-certificate /etc/nginx/certs/vsign.example.com.crt \
  --public-certificate-key /etc/nginx/certs/vsign.example.com.key
```

Add `--retired-host` and the two retired-certificate path arguments only while
an old public engine hostname still resolves. The resulting servers return 404
and contain no upstream route.

After installing the rendered file, validate the exact effective state:

```bash
nginx -t
nginx -T 2>&1 | npm run ingress:config -- audit \
  --config - \
  --public-host vsign.example.com \
  --gateway-upstream-name vasi_public_gateway
```

The edge host and certificate lifecycle are deployment-owned. Do not place
certificate keys in the repository, renderer arguments, environment files, or
audit output; only their already-configured filesystem paths belong in Nginx.

On a shared edge, build the rendered `vasi.conf` as a narrow overlay on an
explicitly approved and locally retained immutable base image:

```bash
docker build --file deployment/nginx/Dockerfile.overlay \
  --build-arg BASE_IMAGE=approved-edge-base:immutable-release \
  --tag approved-edge:vasi-release /protected/overlay-context
```

The context contains only the rendered `vasi.conf` and the tracked overlay
Dockerfile. Do not rebuild a shared edge from a mutable upstream tag during a
VASI change: that can alter unrelated binaries, certificates, and virtual
hosts. Validate the candidate with `nginx -t`, audit its `nginx -T`, scan an
exported image tar without a Docker socket, and retain the exact prior image ID
and launch contract for rollback.

For supported recurring proof, install the tracked edge systemd units and a
root-owned mode-0600 copy of `vasi-edge-monitor.example.json`. The daily image
cycle scans the exact live image and retains bounded digest-bound evidence; the
15-minute runtime cycle proves container/restart/listener state, effective
Nginx policy, public and retired HTTPS behavior, and a fresh passing scan.
Neither scanner nor auditor container receives the Docker socket, and the host
does not need Node. See
`docs/architecture/recurring-public-edge-assurance.md` for the complete
configuration, installation, and alerting contract.
