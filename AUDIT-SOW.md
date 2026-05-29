# Audit Statement of Work

A scoping document for security audit firms considering an engagement
on QChain. Designed to make quoting easier by stating up front what
work is needed, what's in scope, and what deliverables matter.

The detailed technical entry point for the audit itself is
[`AUDIT-PACKAGE.md`](AUDIT-PACKAGE.md). This document is procurement-
layer; read it before quoting.

## 1. About QChain

QChain is a post-quantum research blockchain built with audit-
readiness discipline. It uses CRYSTALS-Dilithium signatures, IBM
Quantum Network QRNG for leader election, and zk-STARK proofs
(Goldilocks AIR via Winterfell) for shielded payments. It is not a
production blockchain; it is a research artifact, designed to be
reviewed and used as a reference for cryptographic engineering
discipline.

The project has run a multi-pass internal audit-readiness arc that
produced:

- 468 tests across three implementation layers, all green
- 40 maintained Markdown documents
- A 23-entry threat model with explicit status taxonomy
- Five self-disclosed bugs/defects found and fixed in the arc
- Differential testing of the Rescue-Prime constants in three layers
- Cross-references from every defended threat to specific code and tests

The project is at the state where in-house review has plausibly
reached its limit and external review would produce the most
information per hour spent.

Full context: [`PUBLICATION.md`](PUBLICATION.md) (13-page
retrospective on the audit-readiness arc).

## 2. What we're asking auditors to do

The primary deliverable is a security review of the project's
cryptographic and protocol design, NOT a code-quality audit. We
are particularly interested in:

### Primary scope (highest priority)

**zk-STARK circuit correctness.** The `qstark/` Rust workspace contains
the AIRs for shielded payment proofs (mixer withdrawal, STARK-anon
spend, M4 anon spend). These are the project's highest-stakes
cryptographic surfaces. Specific questions for the auditor:

- Do the AIRs correctly enforce the statements documented in the
  project? (We do not currently have formal `STATEMENT.md` files —
  the auditor should reconstruct the statements from the code and
  flag any divergence between the AIR and the project's
  prose-level claims.)
- Are the transition constraint polynomials correct? Are they
  complete (no missing constraints) and sound (no spurious
  acceptances)?
- Are the boundary constraints correctly enforcing the public-input
  bindings (root, nullifier, leaf, amount)?
- Are the public/private input separations correct?
- Are there any obvious places where the AIR could accept a proof
  for a statement not equivalent to the intended one?

The project's differential AIR work (Phases 1–3) catches three
specific classes of bug; the auditor's job is to find bugs those
phases don't catch.

**Protocol-level soundness of the multi-pool composition.** QChain has
three privacy mechanisms (M4 anon pool, mixer pool, STARK-anon pool)
that coexist on one chain. Specific questions:

- Can value be inflated by moving notes across pools?
- Can a nullifier be reused across pools?
- Can the mixer's anchored-historical-root mechanism be defeated by
  any combination of cross-pool transitions?
- Are the assumptions documented in `THREAT-MODEL.md` actually the
  necessary and sufficient assumptions, or are there hidden ones?

### Secondary scope

**Cryptographic primitive selection and configuration.** Specifically:

- Is the Rescue-Prime parameter set (Goldilocks, state width 12, 7
  rounds, alpha=7) appropriate for the security levels claimed?
- Is the field choice consistent with the soundness claims of the
  STARK proofs (FRI parameters, conjectured soundness)?
- Is the Dilithium variant used (and via what library) appropriate?

**Wallet encryption-at-rest implementation.** Argon2id (m=64MiB, t=3,
p=4) + AES-256-GCM. Configuration choices and side-channel
considerations.

**Dashboard authentication and rate limiting.** Bearer-token + per-IP
sliding-window rate limit. Realistic threat model coverage.

### Tertiary scope (optional, lower priority)

- Persistence schema design (versioning, on-load validation)
- Network layer (gossip protocol robustness, partition behavior)
- Operational concerns (key management, deployment posture)

### Out of scope

The following are explicitly NOT requested:

- **Performance / throughput optimization.** The project is not
  optimized for performance and does not need to be.
- **Production readiness review.** The project is a research demo.
  An audit assessing it against production criteria (BFT consensus,
  TLS, operational tooling) would be applying the wrong standard.
- **Token / economic / governance analysis.** The project has no
  token, no economics, no governance.
- **UI / UX review.** The dashboard is a debug interface.
- **Third-party dependency audit.** Winterfell, Dilithium reference
  implementation, FastAPI, cryptography, argon2-cffi — these are
  trusted dependencies. An audit of THEM is a separate engagement.
- **Formal verification.** Cool if it happens but not what this
  engagement is for; would be a separate longer project (item 2.4
  on the project ROADMAP).

## 3. Specific deliverables expected

1. **A written security review report**, public-shareable. Sections
   suggested:
   - Executive summary
   - Methodology
   - Findings, each with: severity, affected component, technical
     description, recommended remediation
   - Statements on items deliberately left unverified, with reasons
   - Overall assessment

2. **A list of findings with severities.** The project will respond
   to each (accept-and-fix, accept-and-document, dispute-with-reason).

3. **Optional: re-review after remediation.** If significant findings
   require re-checking, a follow-up pass.

We will publish the report in full as part of the project, with any
quotes from it attributed to the audit firm. The audit firm's name
and the report's findings become part of the project's public record.

## 4. Estimated scope

Approximate sizes by component (lines of code, excluding tests):

| Component | Lines | Audit relevance |
|---|---:|---|
| `qstark/` (Rust AIR core) | ~4500 | High — primary scope |
| `qchain/crypto/` | ~2200 | High — primary scope |
| `qchain/chain/` (transactions, blockchain, pools) | ~3500 | Medium — secondary scope |
| `qchain/network/` (P2P) | ~1200 | Low — tertiary scope |
| `qchain/dashboard/` (FastAPI server) | ~1500 | Low — tertiary scope |
| `qchain/tests/` | ~7000 | Reference material (read for context) |

Roughly 13K lines of non-test code, split heavily toward primary-
scope cryptographic surfaces. Auditor effort should concentrate
there.

The project's own documentation (40 Markdown files) is intended to
make the audit more efficient — much of the context the auditor
would normally reconstruct is already documented.

## 5. Estimated timeline

A reasonable engagement would cover roughly:

- **2–3 weeks** of reading and analysis, focused on the AIRs
- **1–2 weeks** of formal write-up
- **1 week** of remediation re-review (optional)

We don't have a hard deadline, but engagement should be conducted
in calendar weeks, not calendar months. Stretching a review across
many months loses focus and produces a lower-quality report.

## 6. Estimated budget

The project is preparing to apply for grant funding to cover the
audit. Our best estimate of a reasonable engagement cost is in the
range typical for medium-complexity zk circuit audits — approximately
USD 30,000 to 80,000 depending on firm and scope. We do not have
pre-allocated funds; the budget will be determined by the firm's
quote and our grant capacity.

If the engagement scope or budget is mismatched with our resources,
we welcome a counter-proposal: a smaller scope, a phased engagement,
or a fixed-fee partial review. The relevant question is "what would
produce the most useful security information given our resources,"
not "match the full scope above at any price."

## 7. Why engage with this project

For an audit firm evaluating whether to take this engagement, the
following may be relevant:

- The project has done unusual preparatory work. Threat model,
  honest-scope documentation, differential testing, and self-
  disclosed findings reduce the "discover the codebase" overhead
  that normally eats the first week of an audit.
- The project is publishable. The findings (or absence thereof)
  become a public record, which serves the audit firm's portfolio.
- The cryptographic surface is interesting. Multi-pool STARK
  shielding with multiple AIRs is a non-trivial target; a clean
  audit of it would be a genuine reference.
- The project is honest about what it isn't (a production
  blockchain). The audit's job isn't to bless deployment; it's to
  validate the research claims.

For a firm whose specialty is production deployment review, this
engagement is a mismatch. For a firm focused on cryptographic design
and zk circuit correctness, it's a good fit.

## 8. How to engage

To open an engagement discussion, email the project maintainer (see
the GitHub repository for current contact) with:

- A quote or range based on the scope above
- An estimated start and end date
- The names of the team members who would do the review
- Reference work the firm has done in zk circuit auditing
- Any modifications to the scope you'd propose

The project will respond with confirmation, a SoW signing
process, and (assuming the budget is in range) onboarding to the
codebase.

## 9. Preparation already done

The auditor receives, on engagement start, the following
already-prepared materials:

| Document | What it is |
|---|---|
| [`AUDIT-PACKAGE.md`](AUDIT-PACKAGE.md) | Single-entry document with claims C1–C10 and code cross-references |
| [`THREAT-MODEL.md`](THREAT-MODEL.md) | 23 numbered threats with status taxonomy and per-threat code references |
| [`AUDITOR-ONBOARDING.md`](AUDITOR-ONBOARDING.md) | Practical first-day questions (build, run, where to start) |
| [`PUBLICATION.md`](PUBLICATION.md) | 13-page retrospective on the audit-readiness arc |
| Component READMEs | 40 Markdown documents, one per milestone or pass |
| Test suites | 468 tests serving as executable specification |

The auditor should not need to spend day one figuring out what
the codebase is. They should start with a focused question (e.g.,
"is the mixer withdrawal AIR sound?") and use the docs as a guide.

## 10. What follows the audit

The audit report becomes part of the project's public record. Each
finding is responded to with one of:

- **Accept and fix.** A subsequent code pass addresses the finding.
- **Accept and document.** The finding is real but out of scope; it
  becomes a numbered honest-scope item in the threat model.
- **Dispute with reason.** The project disagrees; the disagreement
  is documented alongside the original finding.

The project's discipline of self-disclosure extends to audit
findings: nothing is hidden, and the response to each finding is
public.

After the audit, the ROADMAP may add items based on the findings
(item 1.1 "External audit engagement" then transitions from
"recommended" to "completed, see <link>"). Subsequent passes
implement the accepted-and-fix items.

## Summary

The project is ready for external review. The work above has been
done in-house to make external review productive. The expected
output is a written security report, public-shareable, that
materially raises the trustworthiness of the project's
cryptographic claims.
