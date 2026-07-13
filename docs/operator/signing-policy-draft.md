# Signing Policy Approval Draft

Status: **draft — production use is not approved**

This document converts VASI's technical controls into decisions that the
business owner and qualified legal/privacy reviewers must approve. It is an
operational control sheet, not legal advice. Blank approval fields and any
`TBD` value are release blockers.

## Approval Record

| Responsibility | Named approver | Decision date | Review date |
| --- | --- | --- | --- |
| Business owner | TBD | TBD | TBD |
| Legal/document policy | TBD | TBD | TBD |
| Privacy/records | TBD | TBD | TBD |
| Security/identity | TBD | TBD | TBD |
| Service operations | TBD | TBD | TBD |

## Default-Deny Document Eligibility

Until the approval record is complete, VASI may be used only with synthetic
test documents. Each production document class needs a named owner,
jurisdiction, signer population, retention rule, authentication tier, and
approved template/workflow.

Candidate initial scope, subject to approval:

- ordinary Clark & Burke internal acknowledgements and approvals;
- ordinary business-to-business agreements where every party has agreed to
  transact electronically; and
- low-risk vendor/customer forms for which the document owner has confirmed
  that no special execution, delivery, witnessing, notarization, filing, or
  identity requirement applies.

VASI must refuse or escalate these classes unless counsel approves a specific
workflow and all additional controls exist:

- wills, codicils, testamentary trusts, adoption, divorce, and other family-law
  matters;
- Uniform Commercial Code records outside the electronically permitted scope;
- court orders, notices, pleadings, briefs, or other official court documents;
- foreclosure, eviction, repossession, utility cancellation, insurance-benefit
  cancellation, product recall, or hazardous-material notices;
- deeds, title transfers, powers of attorney, notarized/witnessed instruments,
  government filings, or documents requiring an original or special delivery;
- consumer disclosures where electronic-delivery consent requirements have not
  been separately implemented and tested;
- health, financial, employment, education, minor, biometric, or similarly
  regulated/sensitive records without a specific privacy/security review; and
- any document requiring a qualified/advanced signature, remote online notary,
  identity proofing, or trust-service workflow that VASI does not provide.

The federal E-SIGN exclusions are listed in
[15 U.S.C. § 7003](https://uscode.house.gov/view.xhtml?req=%28title%3A15+section%3A7003+edition%3Aprelim%29).
Oregon's current electronic-transactions scope and exclusions are in
[ORS Chapter 84](https://www.oregonlegislature.gov/bills_laws/ors/ors084.html).
These references do not replace document-specific legal review.

## Signer Assurance Tiers

| Tier | Intended risk | Required VASI controls | Current posture |
| --- | --- | --- | --- |
| Test | Synthetic/nonbinding | Reserved identities and synthetic PDFs only | Available before production |
| A | Approved low-risk workflow | Unique recipient email/token, explicit intent action, audit trail, final copy | Candidate; owner approval required |
| B | Approved moderate-risk workflow | Tier A plus a separately delivered recipient access code or approved account authentication | Candidate; full edge test required |
| C | High-risk/specially regulated | Approved identity proofing, certificate/trust service, witnessing/notary, or other policy-specific controls | Refuse; not implemented |

Email possession is not government-ID proofing. Staff OIDC authenticates CNB
staff at the edge but does not establish an external recipient's civil identity.
The sender must select the approved tier before sending and may not downgrade a
template to bypass its policy.

## Consent And Signing Ceremony

Every approved workflow must provide and test:

- the sender's VASI/CNB identity and a support/escalation route;
- the document title, recipient role, requested action, and ability to review
  the complete document before acting;
- a clear affirmative signing/approval action and an available reject/decline
  path;
- disclosure that the action creates an electronic record and a way to obtain
  the completed record;
- no preselected consent, misleading legal guarantee, hidden material term, or
  forced acceptance unrelated to the document;
- a final copy accessible to each entitled party in a reproducible form; and
- evidence of the exact document version, action, authentication method,
  timestamps, and delivery result.

Where law requires consumer information to be provided in writing, the
electronic-record consent process can require affirmative consent, paper-copy
and withdrawal information, hardware/software disclosures, and a demonstration
that the consumer can access the record. See
[15 U.S.C. § 7001(c)](https://uscode.house.gov/view.xhtml?edition=prelim&num=0&req=granuleid%3AUSC-prelim-title15-section7001).
VASI's ordinary signature-intent disclosure is not, by itself, approval for
such a consumer-delivery workflow.

## Evidence Package

The approved evidence package must retain or reproducibly export:

- the original and final PDFs and every included attachment;
- the final PDF signature, signer certificate and public chain, timestamp token
  when approved, and whole-document hash;
- envelope/template identifiers and immutable version facts;
- recipient role, requested action, authentication method, delivery/open/action
  timestamps, rejection/void reason, and completion state;
- audit events and normalized client metadata necessary for the approved use;
- sender/organisation identity and relevant administrator changes; and
- delivery evidence showing that entitled parties were offered or received the
  final record.

Raw passwords, access codes, recipient tokens, OIDC tokens, session cookies,
private keys, and SMTP credentials are never evidence-package content.

## Retention, Hold, Deletion, And Export

The approvers must replace every `TBD` below. No default application behavior is
treated as an approved records schedule.

| Data class | Online period | Backup period | Deletion trigger | Legal-hold behavior | Owner |
| --- | --- | --- | --- | --- | --- |
| Draft/abandoned documents | TBD | TBD | TBD | Hold blocks deletion | TBD |
| Completed documents/evidence | TBD | TBD | TBD | Hold blocks deletion | TBD |
| Recipient identity/access metadata | TBD | TBD | TBD | Preserve only approved evidence | TBD |
| Security/admin audit events | TBD | TBD | TBD | Hold/incident rule TBD | TBD |
| Failed/completed job state | TBD | TBD | TBD | Not a legal record unless selected | TBD |
| Operational logs | TBD | TBD | Age out after redacted incident need | Preserve selected incident evidence | TBD |
| Signing public chains/timestamps | At least historical verification need | TBD | Policy decision | Hold blocks deletion | TBD |
| Secret recovery copies | Credential/key lifecycle | TBD | Secure destruction after verified rotation | Incident hold as directed | TBD |

Deletion from the live database does not imply immediate deletion from retained
backups. Legal hold must be authorized, scoped, recorded, reviewable, and
released by an approved owner. Export must verify authorization, include only
the approved evidence set, use an encrypted transfer, and leave an audit event.

## Required Acceptance Cases

Before approval, use synthetic data to prove:

1. Tier A and every enabled Tier B method succeed only for the intended
   recipient and cannot be replayed across envelopes.
2. Review, affirmative action, rejection, voiding, completion, and final-copy
   delivery create the expected evidence without raw secrets.
3. A policy-ineligible or Tier C request is refused operationally rather than
   being sent with weaker controls.
4. Draft deletion, completed-record retention, account deactivation, export,
   legal-hold blocking/release, and eventual backup expiry match this schedule.
5. Accessibility and paper/manual alternatives are documented for workflows
   that require them.
6. The business, legal/privacy, security, and operations approvers record an
   explicit go/no-go decision for the exact production release.
