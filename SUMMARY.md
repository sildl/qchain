---
title: "QChain — One-Page Summary"
date: "2026-05"
geometry: margin=0.6in
fontsize: 10pt
linkcolor: blue
header-includes: |
    \pagenumbering{gobble}
    \usepackage{parskip}
    \setlength{\parskip}{4pt}
    \usepackage{titlesec}
    \titlespacing*{\section}{0pt}{6pt}{2pt}
    \titlespacing*{\subsection}{0pt}{4pt}{2pt}
---

# QChain

A research blockchain combining post-quantum signatures (CRYSTALS-Dilithium),
quantum-randomness-driven leader election (IBM Quantum Network QRNG), and a
hand-rolled zk-STARK system (Goldilocks AIR via Winterfell) for shielded payments.

## What state is it in

| Metric                                  | Value |
| --------------------------------------- | ----: |
| Total tests (Rust + PyO3 + Python)      |   443 |
| Maintained Markdown documents           |    37 |
| Numbered threats with explicit status   |    23 |
| Threats `[DEFENDED]` or stronger        |    20 |
| Threats `[NOT DEFENDED]` (documented)   |     2 |
| Self-found bugs/defects, all disclosed  |     5 |

All tests green. Code: <https://github.com/sildl/qchain>

## What's interesting about it

The cryptographic primitives are well-known. What's unusual is the
**engineering discipline applied to documenting and testing the system**:

- Every defended attack carries explicit code references and tests.
- Every limitation is a numbered threat with one of five status markers:
  `[FORMAL]`, `[FORMAL, MODULO]`, `[DEFENDED]`, `[HEURISTIC]`,
  `[NOT DEFENDED]` — distinguishing "defended under a cryptographic
  assumption" from "defended by application-layer mechanism" from
  "explicitly out of scope."
- Five bugs found and fixed by the project's own audit-readiness work,
  including a coinbase-inflation flaw, a transparent-tx replay bug
  (caught by Hypothesis property testing), and an infinite-loop protocol
  bug surfaced when rate limiting was added.
- Differential testing cross-checks the zk-STARK trace against an
  independent Python re-execution of Rescue-Prime, targeting the
  "circuit is wrong but positive examples still work" failure mode.

## What it is not

A production blockchain. No BFT proof-of-stake. No peer authentication or
TLS. No formal proof of AIR correctness (differential testing is the
project's best evidence, not a proof). No peer-reviewed cryptographic
construction. The project is a **research demo** built with the discipline
of something more serious, and made deliberately legible to someone
considering external engagement.

## What would help most

An independent review of the STARK circuits for shielded payments by a
formal-methods specialist or cryptographer. Several threats marked
`[FORMAL, MODULO]` ride on AIR correctness as their non-formal assumption
— the highest-leverage external contribution.

## Read more

`PUBLICATION.md` / `.pdf` (13-page retrospective) · `AUDIT-PACKAGE.md`
(claims C1–C10) · `THREAT-MODEL.md` (23-threat status table) · `DOCS.md`
(reading order)

