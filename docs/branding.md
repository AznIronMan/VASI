# VASI Brand Implementation

VASI is **Verified Authorized Signing Infrastructure**, a Clark & Burke LLC
service maintained by Street Kings Productions. The short product name is
`VASI`; `CNB` identifies the Clark & Burke organization behind it.

## Owned Source

The tracked monogram is an unchanged copy of the public Clark & Burke asset at
`https://www.cnb.llc/assets/cnb_logo_512.png`, retrieved on 2026-07-12. All
tracked copies have SHA-256 digest:

```text
2c3b65e7d80be469a60d849d3587ad13bd3eb229b25109f99314b3517df6a536
```

Copies exist for the application/PWA, email preview, and shared asset package:

- `apps/remix/public/static/vasi-logo.png`
- `packages/email/static/vasi-logo.png`
- `packages/assets/vasi/cnb-logo.png`

The responsive wordmark and compact icon are repository-native SVG React
components. They combine the C&B monogram structure with the VASI name and do
not require a third-party font or remote asset at runtime.

## Palette And Accessibility

The palette follows Clark & Burke's public site:

| Role | Value | Use |
| --- | --- | --- |
| Primary | `#00A6D6` | Light-mode actions, links, focus rings |
| Primary dark | `#007FA6` | Darker link/hover emphasis |
| Accent | `#086B84` | Strong secondary emphasis |
| Accent dark | `#04495C` | Deep accent and scale endpoint |
| Accent light | `#5CCBE8` | Dark-mode primary action |
| Charcoal | `#151819` | Primary foreground and dark surface |
| Light surface | `#F6F8F9` | Neutral light surface |

Primary cyan with charcoal text has a 6.31:1 contrast ratio. The dark-mode
accent with charcoal has a 9.49:1 ratio. White text is not used on primary cyan
because that pair reaches only 2.83:1. Existing red/destructive, recipient-role,
and neutral semantic colors remain distinct from the brand color.

Inter remains the application font because it is already bundled, readable,
and used by the CNB site. PDF signature handwriting retains the upstream
Caveat font because it represents a signing control rather than brand text.

## Surface Inventory

The maintained VASI overlay covers:

- desktop/mobile application navigation and public profile headers;
- sign-in, account, support, error, and recipient page titles and text;
- favicon, touch icon, PWA manifest, metadata, and share metadata;
- application primary color scale, field emphasis, focus rings, and default
  email color tokens;
- transactional email logo, VASI/CNB sender language, support contact, company
  footer, upstream attribution, and corresponding-source link;
- 2FA relying-party/issuer names and downloaded recovery filenames;
- PDF audit-log and signing-certificate branding;
- synthetic examples and preview defaults, which use reserved `example.com`
  identities rather than upstream staff or customer-like addresses.

`NEXT_PRIVATE_SMTP_FROM_NAME`, `NEXT_PRIVATE_SMTP_FROM_ADDRESS`, and
`NEXT_PUBLIC_SUPPORT_EMAIL` remain deployment configuration. Production
startup rejects the upstream Documenso sender defaults and requires explicit
approved values.

## Attribution And Truth

User-facing VASI surfaces identify Clark & Burke without suggesting Documenso
endorses VASI. Transactional email retains a visible link to Documenso
Community Edition and to the VASI corresponding source. Repository licenses,
notices, package names, compatibility headers, migration identities, and
upstream source comments remain unchanged where they are technical truth rather
than presentation.

PDF certificates continue to report the actual signing certificate identity,
signing method, recipient data, device metadata, timestamps, and audit facts.
The VASI wordmark never substitutes for certificate trust or signer evidence.

The electronic-signature disclosure avoids guaranteeing enforceability and
directs uncertain recipients to the sender or qualified counsel.

## Upstream Update Checklist

After every upstream merge:

1. Search user-facing application, email, manifest, metadata, and PDF code for
   new `Documenso` strings or `/static/logo.png` references.
2. Preserve package names, license notices, protocol headers, and other
   compatibility identifiers that are not presentation.
3. Reapply the small VASI wordmark, palette, email footer, and PDF asset paths
   only where upstream changed the corresponding surface.
4. Run translation extraction and inspect catalog changes.
5. Build and visually verify staff desktop/mobile, recipient desktop/mobile,
   email HTML/text, audit PDF, signing certificate, favicon, and dark mode.
6. Confirm keyboard focus, contrast, signer intent, recipient role, document
   status, consent, and certificate/audit facts remain clear.
