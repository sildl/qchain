# Audit Outreach

Target list and message templates for engaging audit firms and grant
programs. The applicant sends these themselves; this document
provides starting material.

**Important: verify currency.** All audit firms and grant programs
listed below were known to be active in cryptographic / zk audit
work as of recent years. Active engagement status, current contact
addresses, current grant rounds, and pricing change frequently. The
applicant must verify each target's current state before sending.

## Audit firms — known-credible in zk / cryptographic audits

Listed with notes on fit. The applicant should verify recent
publications and check that the firm's current focus matches.

### Firms with explicit zk circuit audit experience

| Firm | Notes |
|---|---|
| **Trail of Bits** | Large established firm; significant zk and cryptographic audit experience including circom and AIR-based circuits. Generally higher end of price range. |
| **Zellic** | Audits ZK rollups and proof systems; published reports on zk projects. Active in the AIR / STARK space. |
| **Veridise** | Specializes in formal verification of zk circuits. Tooling-driven approach. Strong fit if you want their custom analysis tools used. |
| **Least Authority** | Long history of zk-circuit auditing (Zcash heritage); deep cryptographic background. Generally smaller-scale engagements. |
| **Spearbit** | Distributed audit collective; matches projects with individual reviewers. More flexible on scope and pricing. |
| **Cantina** | Marketplace model: project posts the audit and reviewers compete to find bugs. Different model from a traditional engagement. |
| **OpenZeppelin** | Established firm; more EVM-focused traditionally but does ZK work. Verify current zk capacity. |
| **Halborn** | Broad crypto security firm; has done some zk work. Verify zk-specific experience. |
| **Hexens** | Active in zk space; published reports on multiple zk projects. |
| **Sigma Prime** | Research-grade audits; consensus and cryptographic specialty. Strong for protocol-level analysis. |

### Firms more focused on individual researchers

Several well-known independent researchers do audit work and may be
reachable directly. Names rotate; check active Twitter/Mastodon
profiles in the cryptographic-engineering space. Look specifically
for researchers who:

- Have published zk-circuit audit reports recently
- Are affiliated with a known firm OR explicitly available for
  independent engagements
- Have AIR / STARK background (not just SNARK / circom)

### Selection criteria

For QChain specifically, prioritize firms whose recent work
includes:

- AIR-based or STARK-based circuit audits (most relevant)
- Goldilocks-field arithmetic (specific to your stack)
- Multi-pool protocol analysis (mixer + STARK-anon + M4 anon
  composition)
- Public report format (you want a public deliverable)

Deprioritize firms that:

- Primarily audit EVM smart contracts (different skill set)
- Focus on production-readiness audits (mismatched scope)
- Don't publish report formats publicly (you need to know what
  you're paying for)

## Grant programs — known-credible for cryptographic security work

The following programs have funded audit or cryptographic security
work in the past. **All must be verified for current status and
open calls.**

### Ethereum Foundation Grants

- **Site:** ecosystem.ethereum.foundation
- **Categories to check:** ESP (Ecosystem Support Program); ZK,
  cryptography, and security tracks
- **Fit:** Has historically supported zk circuit audits and
  applied cryptography research. Post-quantum work may be a
  good thematic fit given EF's interest in long-term security.
- **Verify:** Whether non-EVM projects are eligible in current
  rounds.

### Protocol Labs Research Grants

- **Site:** research.protocol.ai
- **Categories to check:** Cryptography, security
- **Fit:** Has supported cryptographic audits and primitive
  research. Less directly applicable to blockchain projects
  unless connected to IPFS / Filecoin / drand ecosystem.
- **Verify:** Current call status and eligibility for non-PL
  projects.

### NLnet Foundation

- **Site:** nlnet.nl
- **Categories to check:** NGI0 fund (security, privacy);
  NGI Search for cryptographic tooling
- **Fit:** Strong fit for open-source security tooling and
  audits. Tends to fund smaller, more targeted engagements.
- **Verify:** Current open calls and budget caps.

### Open Technology Fund

- **Site:** opentech.fund
- **Categories to check:** Internet Freedom Fund, Core
  Infrastructure Fund
- **Fit:** Tighter on internet-freedom / human-rights framing.
  Verify whether a research blockchain qualifies.
- **Verify:** Eligibility; this program has specific use-case
  alignment requirements.

### NSF Safe and Trustworthy Cyberspace (SaTC)

- **Site:** nsf.gov / SaTC program page
- **Categories to check:** Small / medium grants in cryptography
- **Fit:** US-academic-affiliated projects only. If the project
  has university affiliation, strong fit.
- **Verify:** Current solicitation; eligibility for non-academic
  PIs.

### Sovereign / national-level digital security funding

Many countries have national programs for open-source digital
security. Examples (verify currency):

- **Germany:** Sovereign Tech Fund (sovereigntechfund.de)
- **EU:** various Horizon Europe digital-security calls
- **France:** CNRS / INRIA collaborative funding
- **Various:** national CERT / cybersecurity agencies sometimes
  fund audits of open-source projects

The applicant should check the funding landscape in their
country first; national programs often have higher acceptance
rates than international ones for in-country projects.

### Specific zk-focused programs

The zk research community has occasional dedicated audit funding.
Check:

- **Aleo Foundation** (snarkOS / Leo grants — may include adjacent
  zk audit work)
- **Polygon Labs Grants** (zk-focused tracks)
- **Mina Foundation** (research grants in zk and applied
  cryptography)
- **StarkWare ecosystem grants** (especially for AIR-related work,
  given your stack)
- **Privacy and Scaling Explorations (PSE)** at Ethereum Foundation
  (zk circuit work specifically)

These rotate availability; verify current status.

## Message templates

### Template A: Audit firm outreach

Send to the firm's general contact, sales, or business email. Keep
short.

> Subject: Audit engagement inquiry — QChain (post-quantum
> research blockchain with zk-STARK shielded payments)
>
> Hi,
>
> I'm reaching out about an audit engagement for QChain, a post-
> quantum research blockchain with shielded payments built on
> zk-STARKs (Goldilocks AIR via Winterfell). The project has done
> substantial audit-readiness preparation — 468 tests, 23-entry
> threat model with status taxonomy, differential testing of the
> cryptographic constants in three layers, and five self-disclosed
> bugs documented as part of the record.
>
> I'm preparing to apply for grant funding to cover the audit and
> would like a quote so I can size the application correctly.
>
> The full scope and codebase context are in two documents I can
> share:
>
> - AUDIT-SOW.md (scope, deliverables, timeline)
> - PUBLICATION.md (13-page retrospective on the project)
>
> Estimated codebase: ~13,000 lines non-test code, heavily weighted
> toward the cryptographic surfaces (Rust AIR core + Python proof
> orchestration). Primary scope is zk-STARK circuit correctness;
> secondary is multi-pool protocol soundness.
>
> Would you have capacity for an engagement of this size in the
> next 3–6 months? If so, I can send the SoW for your review.
>
> Repository: https://github.com/sildl/qchain
>
> Thanks,
> [name]

### Template B: Grant program outreach (when contact-before-applying is appropriate)

Some grant programs have lower-friction inquiry channels (program
officer email, office hours, application-coaching calls). Use these
before submitting a full application if the program offers them.

> Subject: Pre-application inquiry — security audit grant for
> QChain research blockchain
>
> Hi [program officer name, if known],
>
> I'm preparing a grant application to [program] for funding to
> conduct an external security audit of QChain, a post-quantum
> research blockchain with zk-STARK shielded payments. Before
> submitting, I wanted to check whether this kind of request fits
> your current funding priorities.
>
> Specifically:
>
> - The request is to fund a third-party audit firm (not internal
>   development).
> - Budget range USD 35–80K depending on firm.
> - Deliverable is a public security report.
> - Project is open-source research-stage, not commercial.
>
> If this kind of request is in scope for [program]'s current
> round, I'd value any guidance on:
>
> - Whether the project's stage (research-grade, with substantial
>   audit-readiness preparation already done) is the right fit
> - Whether you prefer the audit firm to be selected before
>   application, or whether application can precede firm
>   selection
> - Whether you have feedback on the budget range
>
> Quick reference materials:
>
> - SUMMARY.pdf (1 page)
> - PUBLICATION.pdf (13 pages; the project retrospective)
> - GitHub: https://github.com/sildl/qchain
>
> If a brief call would be more useful than email, I'm available
> at your convenience.
>
> Thanks,
> [name]

### Template C: Cold outreach to an individual auditor / researcher

For independent reviewers approached directly. Even more concise.

> Subject: Audit of zk-STARK shielded-payment circuits — would
> you be available?
>
> Hi [name],
>
> I've followed your work on [specific recent audit / paper / talk].
> I'm working on QChain, a post-quantum research blockchain with
> zk-STARK shielded payments (Goldilocks AIR via Winterfell), and
> I'm looking for a security review focused on the circuit
> correctness.
>
> The project has done unusually thorough audit-readiness
> preparation (threat model with status taxonomy, differential
> testing in three layers, public publication of the work), so
> the engagement should be productive on first pass.
>
> Would you be available for an engagement of this kind in the
> next few months, either independently or through [your firm]?
> If so, I can send a scope document and an estimate of size.
>
> Repository: https://github.com/sildl/qchain
> Publication: [link to PUBLICATION.pdf]
>
> Thanks,
> [name]

## Outreach strategy

### Phase 1 — quotes (weeks 1–3)

Send Template A to 5–8 audit firms. Goal: collect quotes and
estimated timelines. Do NOT promise selection at this stage; you
need the quotes to inform the grant application.

Expect roughly half to respond. Of those, some will decline (out
of scope, no capacity, etc.); a few will provide quotes or
schedule calls.

### Phase 2 — pre-application inquiries (weeks 2–4, parallel)

Send Template B to 3–5 grant programs that look like fits. Goal:
verify the request is in scope and learn each program's preferred
application format. Do NOT submit full applications yet.

### Phase 3 — applications (weeks 4–8)

Based on Phase 1 quotes and Phase 2 feedback, submit 2–3 full
grant applications to the programs that look most likely. Use the
budget from a specific firm quote, not the wide range.

### Phase 4 — selection (weeks 8–16)

When a grant is awarded, finalize the firm selection. Sign
engagement letter, schedule kickoff, share access to the codebase
and audit-package documents.

## Things to NOT do

- **Don't pre-select a firm before getting the grant.** Grants
  often require evidence of firm selection but should not commit
  to a specific firm until funding is secured.
- **Don't apply to grant programs in bulk without verification.**
  Each application that's out-of-scope wastes the reviewer's time
  and hurts your future applications to that program.
- **Don't oversell.** The project's evidence is concrete (test
  counts, threat model, self-disclosures). Stick to it. Adding
  marketing language to a research-grade application damages
  credibility.
- **Don't underprice.** A cheap audit may produce a shallow
  report. Either get a real-priced audit or no audit; a token
  audit serves no one.
- **Don't accept an audit firm that refuses to commit to a
  public report.** A private report doesn't serve the project's
  audit-readiness goals.
- **Don't pursue audits during active code changes.** The audit
  should target a frozen state. Plan to not ship significant
  code changes during the audit window.

## After the audit

Document everything publicly. This is part of the project's
discipline:

1. Publish the audit report in full.
2. Publish a response to each finding (accept-and-fix /
   accept-and-document / dispute-with-reason).
3. Mark ROADMAP 1.1 as completed with a link to the report.
4. If accepted-and-fix items remain, add them as new ROADMAP
   items and ship them in subsequent passes.
5. Update PUBLICATION.md to reference the audit findings and
   responses (this becomes section 9 or 10 of the publication).
6. Credit the audit firm and the grant program in the project
   documentation.

The audit is not the end of audit-readiness work. It's the start
of the public-record cycle of "external finding → project
response → documented outcome."
