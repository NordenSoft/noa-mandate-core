# Corrections

This public log records durable corrections to claims that affect implementers or relying parties.
It intentionally omits private review transcripts, local harness paths, internal task identifiers,
operator notes, and unreleased vulnerability details. Security-sensitive corrections are published
with a fixed release or coordinated advisory.

## Current corrections

### Conformance parity is not implementation independence

The repository contains five language-specific verifier implementations. The current conformance
runners establish verdict parity for the covered vectors through the comparison topology documented
in [conformance/MATRIX.md](conformance/MATRIX.md). They do not establish organizational independence,
independent requirements analysis, or independent decision paths.

### Structural validation is not the whole verifier

JSON Schema is structural assistance. Conformance also depends on canonical bytes, signature scope,
key and algorithm handling, chain semantics, deterministic errors, version behavior, and the
applicable positive and negative vectors.

### A signed statement is not proof that the statement is true

A valid signature identifies a key that signed exact bytes. It does not by itself establish current
authorization, human understanding, physical completion, completeness, exactly-once execution, or
truth in an external system. The maintained claim boundary is [NON-CLAIMS.md](NON-CLAIMS.md).

### Same-process verification is not an enforcement boundary

The in-process TypeScript API does not protect a verdict from code already executing in the same
JavaScript realm. A separate verifier process can protect the computation from a data-only document,
but a compromised caller can still discard or misreport the result. Relying parties should verify in
a process and trust context they control.

### Published status is external state

A package present in this repository is not necessarily published. Current release claims must be
checked against the package registry and an immutable release artifact; repository paths, tags, and
local version strings are not publication evidence on their own.

## Maintenance rule

A correction must state the corrected public claim and point to stable normative text or reproducible
public evidence. Do not add private incident timelines, reviewer identities, unpublished exploit
recipes, internal topology, or mutable local measurements to this file.
