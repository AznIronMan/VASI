# PDF Signing Identity And Timestamping

VASI seals completed PDFs with a dedicated X.509 identity stored as a protected
PKCS#12 bundle. This identity is separate from public edge TLS, private origin
TLS, OIDC credentials, and application encryption keys.

## Production Decision Gate

The tracked runtime supports a locally mounted PKCS#12 identity, but the final
production issuer and trust model are not selected merely by creating a key.
Choose between a self-signed identity and an appropriate CA/trust-service path
based on the relying parties' PDF-reader trust requirements, issuance and
renewal cost, revocation, custody, recovery, and legal policy.

A self-signed certificate can prove that a PDF has not changed since VASI
signed it, but ordinary PDF readers will not automatically trust its issuer.
Any self-signed staging identity must therefore be labelled untrusted and must
not be represented as a production-trusted or qualified signature.

## Runtime And Startup Checks

The PKCS#12 bundle and its passphrase are mounted as different `0400` secrets.
The production entrypoint fails closed unless the bundle:

- is present and readable;
- can be decrypted with the mounted passphrase;
- contains a certificate whose public key matches its private key; and
- remains valid for at least 30 days.

Run the same inspection independently before startup:

```sh
docker compose --env-file /protected/vasi-origin.env --profile tools run --rm signing-check
```

The check prints only public certificate metadata and a SHA-256 fingerprint.
It does not establish CA trust, revocation status, certificate-policy fitness,
or control of the signing process. Record the approved fingerprint out of band
and compare it during deployment.

## Timestamp Policy

`NEXT_PRIVATE_SIGNING_TIMESTAMP_AUTHORITY` remains empty until an RFC 3161
service and its failure behavior are approved and tested. With no TSA, the PDF
has a cryptographic document signature but no independent trusted signing-time
assertion. If a TSA is enabled, test its chain, availability, authentication,
privacy exposure, failover behavior, renewal, long-term validation material,
and the application's behavior when every configured TSA is unavailable.

## Acceptance And Rotation

Before production use, complete a synthetic workflow and verify the signature
in at least one independent PDF validator. Confirm the VASI signing reason and
contact metadata, certificate chain and expected reader warning/trust state,
whole-document coverage, timestamp presence or deliberate absence, and that a
post-signing byte change invalidates verification.

Rotate the bundle and passphrase together. Back up the private identity only in
the separately encrypted recovery store, retain the public certificate chain
needed to validate historical documents, alert well before expiry, and maintain
a compromise procedure that covers revocation where supported, replacement,
incident scoping, and communication to relying parties.
