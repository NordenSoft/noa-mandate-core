#!/usr/bin/env python3
"""Strict-bytes corpus reader for the Go, Rust and C# conformance runners (stdlib only).

  strict-bytes-cases.py list <manifest.json>
      Validate conformance/vectors/strict-bytes/manifest.json and print one tab-separated line per case:
      name, chain file, keyring file, native exit, native status, strict exit, strict status, strict
      discriminator. A native case that is not asserted prints "-" for its exit and status; a strict case
      with no pinned discriminator prints "-" for it.
      Exit 1 (printing nothing on stdout) when the manifest is missing or unreadable, when its case set is
      not exactly the authored set below, or when any pinned file (every case, both COSE envelopes, both
      JCS literal files) is missing or its SHA-256 differs from the pin — a runner that cannot read the
      corpus must fail, never pass on zero cases.

  strict-bytes-cases.py result <verifier stdout>
      Print "<status> <discriminator>": the JSON result's string "status", then NON_CANONICAL_BYTES when
      its "detail" (or TS "reason") starts with it, else "-". Print "INVALID INVALID" when the output is
      not one JSON object with a string "status". The runner compares the status with the authored one
      (security round 1, finding 2: an exit code and a discriminator alone would accept a result that
      says VALID beside them).

The expectations come from the manifest, which records them as authored constants (scripts/gen-vectors.ts
section 12); this helper never derives one from a verifier run.
"""
import hashlib
import json
import os
import sys

AUTHORED = {
    "canonical", "extra-space", "member-order", "escaped-string", "trailing-lf", "pretty",
    "leading-space", "trailing-crlf", "bom", "invalid-utf8", "reversed-order",
    "wrong-signature-canonical", "wrong-signature-noncanonical",
}
STATUSES = {"VALID", "UNVERIFIED", "TAMPERED", "MALFORMED", "UNTRUSTED"}
DISC = "NON_CANONICAL_BYTES"


def _exit_code(v):
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise ValueError("exit code must be a non-negative integer")
    return v


def _status(v):
    if v not in STATUSES:
        raise ValueError("unknown status %r" % (v,))
    return v


def _pin(base, name, digest):
    with open(os.path.join(base, name), "rb") as fh:
        if hashlib.sha256(fh.read()).hexdigest() != digest:
            raise ValueError("SHA-256 differs from the manifest pin: " + name)


def list_cases(manifest_path):
    base = os.path.dirname(manifest_path)
    with open(manifest_path, "rb") as fh:
        manifest = json.loads(fh.read().decode("utf-8"))
    cases = manifest["cases"]
    names = [c["name"] for c in cases]
    if len(names) != len(set(names)) or set(names) != AUTHORED:
        raise ValueError("case set differs from the authored set: %s" % sorted(set(names) ^ AUTHORED))
    keyring = os.path.join(base, manifest["keyring"])
    if not os.path.isfile(keyring):
        raise ValueError("keyring missing: " + keyring)
    cose = manifest["cose"]
    if sorted(c["file"] for c in cose) != ["canonical.cose", "extra-space.cose"]:
        raise ValueError("COSE entries differ from the authored pair")
    for c in cose:
        _pin(base, c["file"], c["sha256"])
    lit = manifest["jcsLiteral"]
    _pin(base, lit["input"], lit["inputSha256"])
    _pin(base, lit["expected"], lit["expectedSha256"])
    rows = []
    for c in cases:
        _pin(base, c["file"], c["sha256"])
        if c["native"] is None:
            native_exit, native_status = "-", "-"
        else:
            native_exit, native_status = str(_exit_code(c["native"]["exit"])), _status(c["native"]["status"])
        strict_exit, strict_status = str(_exit_code(c["strict"]["exit"])), _status(c["strict"]["status"])
        disc = c["strict"]["discriminator"]
        if disc not in (None, DISC):
            raise ValueError("unknown discriminator in " + c["name"])
        path = os.path.join(base, c["file"])
        rows.append("\t".join([c["name"], path, keyring, native_exit, native_status, strict_exit, strict_status, disc or "-"]))
    return rows


def result(out):
    try:
        v = json.loads(out)
    except ValueError:
        return "INVALID INVALID"
    if not isinstance(v, dict) or not isinstance(v.get("status"), str) or v["status"] not in STATUSES:
        return "INVALID INVALID"
    text = v.get("detail", v.get("reason", ""))
    return v["status"] + " " + (DISC if isinstance(text, str) and text.startswith(DISC) else "-")


def main(argv):
    if len(argv) == 3 and argv[1] == "list":
        try:
            rows = list_cases(argv[2])
        except (OSError, ValueError, KeyError, TypeError) as e:
            sys.stderr.write("strict-bytes corpus unreadable: %s\n" % e)
            return 1
        sys.stdout.write("".join(r + "\n" for r in rows))
        return 0
    if len(argv) == 3 and argv[1] == "result":
        print(result(argv[2]))
        return 0
    sys.stderr.write("usage: strict-bytes-cases.py list <manifest.json> | result <verifier stdout>\n")
    return 4


if __name__ == "__main__":
    sys.exit(main(sys.argv))
