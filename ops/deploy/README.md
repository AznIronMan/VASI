# Deployment Templates

This directory is reserved for public-safe, generic VASI Docker/Compose and
reverse-proxy templates.

No runnable template exists yet because the Documenso upstream baseline has not
been selected or imported. Future templates will separate the public edge/auth
gateway from the internal-only VASI application origin. They must be
version-pinned, contain no live host details or secrets, use persistent storage,
and match `docs/operator/deployment.md`.
