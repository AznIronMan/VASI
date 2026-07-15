# Nginx public ingress reference

`vasi-public.conf.example` is a sanitized, valid Nginx `http`-context include.
Do not edit it into an installation-specific file or add certificates, private
addresses, or customer hostnames to this directory.

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
