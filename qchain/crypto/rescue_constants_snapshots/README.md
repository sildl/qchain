# Constants snapshots

This directory holds independent constants snapshots for Layer 3 of
the Phase 3 cross-reference. Each snapshot is a JSON file matching
the schema in `DIFFERENTIAL-AIR-PHASE3-README.md`.

When a snapshot is present, `test_rescue_constants_phase3.py::
TestLayer3SnapshotCrossReference::test_all_present_snapshots_match`
diffs our constants against it. A disagreement fails the test
loudly.

The directory is intentionally empty in this pass. See
`DIFFERENTIAL-AIR-PHASE3-README.md` for the snapshot acquisition
procedure.

Naming convention: `<project>_<version_or_commit>.json`. For
example: `miden_v0.10.0.json` or `miden_8a3b1c2.json`.
