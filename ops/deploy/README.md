# Deployment Templates

This directory is reserved for public-safe, generic VASI Docker/Compose and
reverse-proxy templates.

The imported Documenso baseline includes upstream Docker and Compose examples,
but no runnable VASI-specific template exists yet. Future VASI templates will
separate the public edge/auth gateway from the internal-only application origin.
They must use a pinned VASI image, contain no live host details or secrets, use
the approved external PostgreSQL and persistent storage contract, and match
`docs/operator/deployment.md`.
