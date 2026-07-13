# Deployment Templates

This directory is reserved for public-safe, generic VASI Docker/Compose and
reverse-proxy templates.

The imported Documenso baseline includes upstream Docker and Compose examples;
they are not the VASI production contract. The generic
[private-origin template](origin/README.md) uses a pinned VASI image, external
PostgreSQL, secret mounts, internal-CA TLS, a private application network, and
an internal health endpoint without publishing live host details.

The public staff/recipient edge is a separate deployment and must implement
`docs/operator/edge-route-policy.md` before production cutover. The generic
[staff-auth edge contract](edge/README.md) provides a pinned OIDC forward-auth
service and a tested deny-by-default route gateway without live host details.
