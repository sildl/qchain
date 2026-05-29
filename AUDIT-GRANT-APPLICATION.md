# Grant Application — QChain External Security Audit

A narrative for grant applications seeking funding for an external
security audit of QChain. This document is a SOURCE for grant
applications, not the application itself — most grant programs have
their own format, and this content should be adapted to each.

## Project summary (one paragraph)

QChain is a post-quantum research blockchain that combines
CRYSTALS-Dilithium signatures, IBM Quantum Network QRNG for leader
election, and hand-rolled zk-STARK proofs (Goldilocks AIR via
Winterfell) for shielded payments. Beyond its cryptographic
primitives, the project is distinctive for its audit-readiness
discipline: a 23-entry threat model with explicit status taxonomy,
differential testing of cryptographic constants, five self-disclosed
bugs documented as features rather than hidden, and traceability
from every defended claim to specific code and tests. The codebase
has reached the state where in-house review has plausibly reached
its limit and external review would produce the most information
per hour spent. This grant request funds that external review.

## What the grant funds specifically

Direct payment to a qualified third-party security audit firm to
conduct a written security review of QChain's cryptographic and
protocol design. Primary focus: the zk-STARK circuits used for
shielded payments. Secondary focus: protocol-level soundness of the
multi-pool composition (mixer + STARK-anon pool + M4 anon pool).

The deliverable to the funder is the audit report itself, made
public as part of the project's record. The funder receives credit
in the project's documentation and in the audit report.

## Budget

| Item | Amount (USD) |
|---|---:|
| Audit firm engagement (primary scope) | 30,000–60,000 |
| Optional remediation re-review | 5,000–15,000 |
| Indirect costs (administrative, legal review of engagement letter, communication) | 0–5,000 |
| **Total request** | **35,000–80,000** |

The range reflects uncertainty about which audit firm is selected.
The lower end of the range corresponds to a smaller-firm engagement
focused only on the AIRs; the upper end corresponds to a more
comprehensive review by a higher-end firm. The final budget will be
the firm's quote based on the project's
[`AUDIT-SOW.md`](AUDIT-SOW.md).

If the grant amount is fixed and lower than the range above, the
audit scope will be adjusted to match (e.g., a focused review of
only the highest-priority AIR rather than the full circuit set).
The project will not accept a half-resourced engagement that
produces a low-quality report.

## Project evidence (what the funder is funding the audit OF)

Quantitative:

- **468 tests** across three implementation layers, all green
- **40 maintained Markdown documents** describing every milestone
- **23 numbered threats** in the threat model; 20 actively defended
- **5 self-disclosed bugs/defects** found and fixed by the
  project's own audit-readiness work
- **Three independently-implemented verification layers** for the
  cryptographic constants (algebraic self-checks, regression
  vectors, snapshot-cross-reference harness)
- Roughly **13,000 lines of non-test code** across three workspaces
  (Rust AIR core, PyO3 bindings, Python chain)

Qualitative:

- A five-tier threat status taxonomy (`[FORMAL]`, `[FORMAL, MODULO]`,
  `[DEFENDED]`, `[HEURISTIC]`, `[NOT DEFENDED]`) that distinguishes
  defenses by epistemic strength rather than treating "secure /
  insecure" as binary
- Cross-references from every defended claim to specific code paths
  and specific tests
- Differential testing of the zk-STARK trace against an independent
  Python re-execution of Rescue-Prime, specifically targeting the
  "AIR is wrong but positive examples pass" failure mode
- Honest-scope sections in every component README, listing what is
  deliberately not defended and why
- A written publication ([`PUBLICATION.md`](PUBLICATION.md), 13
  pages) consolidating the audit-readiness arc

## Why this project is worth auditing

For a grant program evaluating this application:

1. **The audit-readiness work has produced an artifact that
   genuinely makes external audit productive.** Most cryptographic
   projects, when audited, consume the first week of the engagement
   on "what is this codebase." Here, that work is already done.
   The audit firm's hours are spent on actual security analysis,
   not codebase orientation.

2. **The zk-STARK shielded-payments space is undersupplied with
   public audits.** Most public chains' shielded-payment circuits
   have been audited (Zcash, Aleo, etc.), but the broader research-
   stage zk-STARK community has fewer public reference audits for
   AIR-style circuits. A public audit of QChain's AIRs becomes a
   reference for other researchers doing similar work.

3. **The project's discipline of self-disclosure is unusual.**
   Five disclosed bugs include a critical-in-production coinbase
   inflation flaw and a transparent-tx replay bug found by
   property testing. A project that disclosed these voluntarily
   creates higher-trust conditions for the audit firm to find
   more.

4. **The deliverable is public.** The audit report is published
   in full, with the firm credited. This is good for the audit
   ecosystem: more public reports raise the quality bar across
   the field.

5. **The follow-up is committed.** Audit findings will receive
   public responses (accept-and-fix / accept-and-document / dispute-
   with-reason), and accepted-and-fix items become subsequent
   ROADMAP items. The audit is not a one-time event ending in a
   PDF; it's the start of a documented follow-up cycle.

## What the project is NOT asking the grant to fund

To be explicit, so the grant program's evaluation is correctly
calibrated:

- Not funding development of new features.
- Not funding a token launch (the project has no token).
- Not funding marketing, conferences, or user acquisition.
- Not funding the project maintainer's salary or stipend (separate
  request if pursued).
- Not funding hardware, infrastructure, or hosting.
- Not funding the audit firm to do production-readiness review
  (out of scope; the project is a research artifact).
- Not funding a "comprehensive" audit that would cover all 40
  Markdown documents. The audit is focused on cryptographic
  surfaces.

This grant pays for exactly one thing: an external security firm's
hours, spent on a documented set of cryptographic questions, ending
in a written public report.

## Why this project, why now

**Why this project:** The project's posture — research-grade
cryptographic implementation with explicit audit-readiness
discipline — is rare. Most projects in this design space either
(a) have an embedded audit team and don't need external grants, or
(b) are early-stage and not yet audit-ready. QChain sits in the
middle: serious enough to deserve audit, independent enough to need
external funding for it.

**Why now:** The audit-readiness arc has just shipped its last
engineering item (Differential AIR Phase 3, closing the constants
cross-reference gap). The project is in the state for which an audit
produces the most information per hour. Delaying the audit risks
the project drifting (new code reduces the value of the audit
preparation; abandonment loses everything). Conducting the audit
NOW preserves the value of the audit-readiness work.

## Track record

The project has run a multi-pass audit-readiness arc over roughly
twelve months. Highlights:

- **Audit-followup hardening pass.** Five separate passes fixing
  issues that a hypothetical external auditor would have found
  early. Found and fixed coinbase inflation (critical in production).
- **Differential AIR validation pass (three phases).** Trace-content
  cross-check (Phase 1), full round-by-round Python re-execution
  (Phase 2), and constants cross-reference (Phase 3). Specifically
  targeted at the AIR-correctness failure mode the audit will
  re-examine.
- **Property-based testing pass.** Used Hypothesis to find a
  transparent-tx replay bug that positive-example tests missed.
- **Threat-model formalization pass.** Introduced the five-tier
  status taxonomy and cross-references from every threat to code
  and tests.
- **Wallet encryption pass.** Argon2id + AES-GCM at rest, closing
  T21 (Wallet key compromise).
- **Rate limiting pass.** Per-peer per-message-type network rate
  limits and per-IP dashboard limits. Closed T15, T23. As a side
  effect, exposed an infinite-loop protocol bug in the gossip
  fork-resolution path.
- **Dashboard authentication pass.** Bearer-token auth on all `/api/*`
  and `/ws` endpoints. Closed T22 fully.
- **Publication pass.** Externally-facing 13-page retrospective
  ([`PUBLICATION.md`](PUBLICATION.md)) consolidating the work for
  outside readers.

Each pass produced an implementation, a test suite, and a Markdown
document. The discipline has held across the full arc; the
documentation describes both what was built and (in honest-scope
sections) what was deliberately not built.

The README and other repository documents can be reviewed at any
time. The publication PDF is the most accessible single document.

## Deliverable to the grant program

Within 90 days of grant disbursement:

1. **Audit firm engagement letter signed.** (Within first 30 days.)
2. **Audit conducted and report drafted.** (By day 75.)
3. **Audit report published in full** in the project repository,
   with the grant program credited in both the report and the
   project's documentation.
4. **A response to each finding** published alongside the report
   (accept-and-fix, accept-and-document, or dispute-with-reason).
5. **A short report to the grant program** summarizing the
   engagement: what was audited, what was found, what was fixed,
   what remains as documented honest-scope. ~1500 words.

If the audit timeline runs long (e.g., a re-review pass is
needed), the deliverable timeline extends in proportion, but no
later than 180 days from grant disbursement.

## Grant program fit

This request fits grant programs that:

- Support open-source cryptographic security work
- Fund audits as direct deliverables (rather than only development)
- Value public reports over private engagements
- Care about post-quantum, zero-knowledge, or applied cryptography

Programs known to fit some or all of these criteria include
(non-exhaustive, currency-of-each must be verified by applicant):

- **Ethereum Foundation Grants** — has supported zk-circuit audits
  in the past; check current categories
- **Protocol Labs Research Grants (IPFS / Filecoin / drand
  foundations)** — supports cryptographic research and audit work
- **NLnet** — supports open-source security work, including audits
- **Open Technology Fund** — supports privacy / security tooling
- **NSF SaTC small grants** — for academic-affiliated projects
- **National-level digital security grant programs** — varies by
  country

The applicant should verify current call-for-proposals and
eligibility for each before applying.

## Contact

(Maintainer contact details, populated per application.)

GitHub: <https://github.com/sildl/qchain>

---

*This narrative is the source content for grant applications. Adapt
to each grant program's specific format; specific budget numbers
within the ranges above should be set based on actual quotes from
audit firms approached.*
