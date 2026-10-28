#!/usr/bin/env python3
"""Strict-bytes corpus reader for the Go, Rust and C# conformance runners (stdlib only).

  strict-bytes-cases.py list <manifest.json>
      Validate conformance/vectors/strict-bytes/manifest.json and print one tab-separated line per case:
      name, chain file, keyring file, native exit (or "-"), strict exit, strict discriminator (or "-").
      Exit 1 (printing nothing on stdout) when the manifest is missing or unreadable, when its case set is
      not exactly the authored set below, or when a file is missing or its SHA-256 differs from the pin —
      a runner that cannot read the corpus must fail, never pass on zero cases.

  strict-bytes-cases.py disc <verifier stdout>
      Print NON_CANONICAL_BYTES when the verifier's JSON result carries a "detail" (or TS "reason") that
      starts with it, "-" when it does not, and INVALID when the output is not one JSON object with a
      string "status".

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
DISC = "NON_CANONICAL_BYTES"


def _exit_code(v):
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise ValueError("exit code must be a non-negative integer")
    return v


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
    rows = []
    for c in cases:
        path = os.path.join(base, c["file"])
        with open(path, "rb") as fh:
            if hashlib.sha256(fh.read()).hexdigest() != c["sha256"]:
                raise ValueError("SHA-256 differs from the manifest pin: " + c["file"])
        native = "-" if c["native"] is None else str(_exit_code(c["native"]["exit"]))
        strict = str(_exit_code(c["strict"]["exit"]))
        disc = c["strict"]["discriminator"]
        if disc not in (None, DISC):
            raise ValueError("unknown discriminator in " + c["name"])
        rows.append("\t".join([c["name"], path, keyring, native, strict, disc or "-"]))
    return rows


def discriminator(out):
    try:
        v = json.loads(out)
    except ValueError:
        return "INVALID"
    if not isinstance(v, dict) or not isinstance(v.get("status"), str):
        return "INVALID"
    text = v.get("detail", v.get("reason", ""))
    return DISC if isinstance(text, str) and text.startswith(DISC) else "-"


def main(argv):
    if len(argv) == 3 and argv[1] == "list":
        try:
            rows = list_cases(argv[2])
        except (OSError, ValueError, KeyError, TypeError) as e:
            sys.stderr.write("strict-bytes corpus unreadable: %s\n" % e)
            return 1
        sys.stdout.write("".join(r + "\n" for r in rows))
        return 0
    if len(argv) == 3 and argv[1] == "disc":
        print(discriminator(argv[2]))
        return 0
    sys.stderr.write("usage: strict-bytes-cases.py list <manifest.json> | disc <verifier stdout>\n")
    return 4


if __name__ == "__main__":
    sys.exit(main(sys.argv))
