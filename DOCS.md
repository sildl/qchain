# DOCS.md — Reading-Order Guide

The repository has two documentation tiers: a small set of **active
reference documents** at the root (12 files, all current), and a
larger set of **historical milestone READMEs** under
`docs/milestones/` (32 files, kept as evidence of how the project
was built but not needed for first-time orientation).

Reading them alphabetically is the wrong order; this document gives
the right order(s) for several audiences.

## If you have 60 seconds

[`SUMMARY.md`](SUMMARY.md) — one page. Or `SUMMARY.pdf` for the
typeset version.

## If you have 25 minutes (first-time external reader)

1. [`README.md`](README.md) — what this is, where to start
2. [`PROJECT-PRESENTATION.md`](PROJECT-PRESENTATION.md) — public-
   facing 10-page overview (or `.pdf`)
3. [`PUBLICATION.md`](PUBLICATION.md) — 13-page audit-readiness
   retrospective (or `PUBLICATION.pdf`)

These three cover the project end-to-end. Most readers can stop
here.

## If you're auditing the project

In order:

1. [`AUDIT-PACKAGE.md`](AUDIT-PACKAGE.md) — claims C1–C10 with
   code references
2. [`THREAT-MODEL.md`](THREAT-MODEL.md) — 23 numbered threats with
   status taxonomy
3. [`AUDITOR-ONBOARDING.md`](AUDITOR-ONBOARDING.md) — practical
   first-day reference (build, run, where to look)
4. [`docs/milestones/DIFFERENTIAL-AIR-README.md`](docs/milestones/DIFFERENTIAL-AIR-README.md),
   [`-PHASE2-README.md`](docs/milestones/DIFFERENTIAL-AIR-PHASE2-README.md),
   [`-PHASE3-README.md`](docs/milestones/DIFFERENTIAL-AIR-PHASE3-README.md)
   — the AIR-correctness evidence

## If you're applying for / awarding a grant for the audit

1. [`PUBLICATION.md`](PUBLICATION.md) — the retrospective
2. [`AUDIT-GRANT-APPLICATION.md`](AUDIT-GRANT-APPLICATION.md) —
   narrative source for grant applications
3. [`AUDIT-SOW.md`](AUDIT-SOW.md) — what the audit firm is being
   asked to do
4. [`AUDIT-OUTREACH.md`](AUDIT-OUTREACH.md) — target lists and
   message templates

## If you want to understand how the project was built

The 32 milestone READMEs under [`docs/milestones/`](docs/milestones/)
each describe one pass: what was built, what was decided, what was
self-found, what was left open. They are kept as evidence of the
audit-readiness discipline. Read in chronological order if you want
the full arc; cherry-pick if you want depth on a specific topic.

The milestones group roughly into:

| Era | Files | What it covers |
|---|---|---|
| Foundation | M8.5 through M8.11 | The original chain + first STARK-anon work + the four M8.5 gaps closed |
| Chain hardening | M8.10, PERSISTENCE, HARDENING-WITHDRAW-AMOUNT, UI-DENOMINATION-DISPLAY | Replay validation, restart-safety, polish |
| Privacy layer | M10-Phase1..4, MIXER-TIMING | Mixer pool design + same-block timing defense (T13) |
| Audit-readiness arc | AUDIT-NOTES, AUDIT-FOLLOWUP, PROPERTY-TESTING, DIFFERENTIAL-AIR-{README,PHASE2,PHASE3}, WALLET-KEY-ENCRYPTION, RATE-LIMITING, WALLET-NOTE-LIFECYCLE, DASHBOARD-AUTH | The 11-pass arc that produced the current audit-ready state |
| Evidence | BENCHMARK-STARK-ANON | One-time phase-level proving benchmark (evidence of understanding, not optimization motivation) |

The single best document for understanding all of this in
consolidated form is [`PUBLICATION.md`](PUBLICATION.md) — that's
what it was written for.

## Active reference documents at root (12 files)

| File | Purpose |
|---|---|
| `README.md` | Landing page |
| `SUMMARY.md` / `.pdf` | One-page summary |
| `PROJECT-PRESENTATION.md` / `.pdf` | 10-page public-facing presentation |
| `PUBLICATION.md` / `.pdf` | 13-page audit-readiness retrospective (the master document) |
| `ROADMAP.md` | Past, present, and anti-roadmap |
| `THREAT-MODEL.md` | T1–T23 with status, code refs, test refs |
| `AUDIT-PACKAGE.md` | Single-entry doc for auditors (C1–C10) |
| `AUDIT-SOW.md` | Statement of Work for audit firms |
| `AUDITOR-ONBOARDING.md` | Day-one practical reference |
| `AUDIT-GRANT-APPLICATION.md` | Grant application source narrative |
| `AUDIT-OUTREACH.md` | Outreach contacts and message templates |
| `DOCS.md` | This file |
