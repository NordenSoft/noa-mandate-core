# Timestamp-order warning parity: reads one verifier's JSON result for the conformance runners.
#
# impl-go/conformance_test.sh, impl-rust/conformance.sh and impl-csharp/conformance.sh run the Python
# reference (impl-py/noa_verify.py) and their own verifier on the same chain, then compare the
# timestamp-order warnings the two printed. docs/receipt-spec.md §5 makes "warnings" an additive member
# of the CLI's JSON result: absent when the run reported no warning, otherwise an array of strings in
# the order the run reported them. A text search for the codes cannot hold a result to that: it reads
# {"warnings": "ts-backwards: seq 1"}, or the same code under another key, exactly like the array.
# This script parses the result and holds it to the documented shape:
#
#   - the output is exactly one JSON object; a duplicate key or a non-finite number is refused;
#   - "warnings", when present, is an array of strings;
#   - no timestamp-order code ("ts-backwards: seq N", "ts-not-comparable: seq N") stands anywhere else
#     in the result, as a whole string or as a key.
#
# Only then are the codes read from "warnings", in their order. The other warnings are not compared;
# they differ between verifiers by design (spec §5). A longer text that merely contains a code, such
# as a "detail" sentence, is not a code.
#
# Usage:
#   python3 conformance/warning-parity.py codes OUTPUT
#       prints the ordered codes as one JSON array and exits 0, or prints "INVALID: <reason>" and
#       exits 1. The runners read both verifiers' results this way and compare the two printed lines.
#   python3 conformance/warning-parity.py --selftest
#       reads a fixed table of correct results and wrong shapes (a string in place of the array among
#       them) and exits 0 only when every one is read as expected. Each runner runs it before its cases.
import json
import re
import sys

CODE = re.compile(r"ts-(?:backwards|not-comparable): seq [0-9]+")


class ShapeError(Exception):
    """The output is not a verifier result of the documented shape."""


def _kind(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, list):
        return "an array"
    return "an object"


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ShapeError(f"duplicate key {json.dumps(key)}")
        result[key] = value
    return result


def _refuse_constant(name):
    raise ShapeError(f"non-finite number {name}")


def _stray_code(value, where):
    """Where a timestamp-order code stands in value as a whole string or as a key; None if nowhere."""
    if isinstance(value, str):
        return where if CODE.fullmatch(value) else None
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{where}[{json.dumps(key)}]"
            if CODE.fullmatch(key):
                return f"{path} (the key)"
            found = _stray_code(item, path)
            if found is not None:
                return found
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found = _stray_code(item, f"{where}[{index}]")
            if found is not None:
                return found
    return None


def codes(output):
    """The ordered timestamp-order codes of one verifier result; ShapeError when the shape is wrong."""
    try:
        result = json.loads(output, object_pairs_hook=_unique_keys, parse_constant=_refuse_constant)
    except json.JSONDecodeError as e:
        raise ShapeError(f"not one JSON document ({e.msg} at line {e.lineno} column {e.colno})") from None
    if not isinstance(result, dict):
        raise ShapeError(f"the result is {_kind(result)}, not an object")
    warnings = result.get("warnings", [])
    if not isinstance(warnings, list):
        raise ShapeError(f'"warnings" is {_kind(warnings)}, not an array')
    for index, item in enumerate(warnings):
        if not isinstance(item, str):
            raise ShapeError(f'"warnings"[{index}] is {_kind(item)}, not a string')
    rest = {key: value for key, value in result.items() if key != "warnings"}
    stray = _stray_code(rest, "the result")
    if stray is not None:
        raise ShapeError(f'a timestamp-order code outside "warnings", at {stray}')
    return [item for item in warnings if CODE.fullmatch(item)]


ONE = '{"status": "VALID", "warnings": ["ts-backwards: seq 1"]}'
TWO = '{"status": "VALID", "warnings": ["ts-backwards: seq 1", "ts-backwards: seq 2"]}'
REFUSED = None

# (case, verifier output, the codes it must yield or REFUSED). Each wrong shape differs from a correct
# result in one respect; removing any one rule above changes the outcome of at least one case, and an
# unexpected exception fails the self-test as well.
SELFTEST = [
    ("no warnings member", '{"status": "VALID", "detail": "2 receipts, chain c"}', []),
    ("an empty array", '{"status": "VALID", "warnings": []}', []),
    ("two codes in their order", TWO, ["ts-backwards: seq 1", "ts-backwards: seq 2"]),
    ("two codes in the other order", '{"status": "VALID", "warnings": ["ts-backwards: seq 2", "ts-backwards: seq 1"]}', ["ts-backwards: seq 2", "ts-backwards: seq 1"]),
    ("an indented result", '{\n  "status": "VALID",\n  "warnings": [\n    "ts-not-comparable: seq 3"\n  ]\n}', ["ts-not-comparable: seq 3"]),
    ("another warning, and a code inside a longer detail", '{"status": "VALID", "detail": "3 receipts, chain c | ts-backwards: seq 1", "warnings": ["a caveat", "ts-backwards: seq 1"]}', ["ts-backwards: seq 1"]),
    ("a string in place of the array", '{"status": "VALID", "warnings": "ts-backwards: seq 1"}', REFUSED),
    ("an object in place of the array", '{"status": "VALID", "warnings": {"0": "ts-backwards: seq 1"}}', REFUSED),
    ("null in place of the array", '{"status": "VALID", "warnings": null}', REFUSED),
    ("a number in the array", '{"status": "VALID", "warnings": ["ts-backwards: seq 1", 2]}', REFUSED),
    ("an array in the array", '{"status": "VALID", "warnings": [["ts-backwards: seq 1"]]}', REFUSED),
    ("a code under another key", '{"status": "VALID", "warnings": ["ts-backwards: seq 1"], "notes": ["ts-backwards: seq 2"]}', REFUSED),
    ("a code as the whole detail", '{"status": "VALID", "detail": "ts-backwards: seq 2", "warnings": ["ts-backwards: seq 1"]}', REFUSED),
    ("a code as a key", '{"status": "VALID", "warnings": ["ts-backwards: seq 1"], "ts-backwards: seq 2": true}', REFUSED),
    ("a code nested under another key", '{"status": "VALID", "warnings": ["ts-backwards: seq 1"], "x": {"y": ["ts-not-comparable: seq 2"]}}', REFUSED),
    ("a duplicate warnings key", '{"status": "VALID", "warnings": ["ts-backwards: seq 2"], "warnings": ["ts-backwards: seq 1"]}', REFUSED),
    ("a non-finite number", '{"status": "VALID", "warnings": ["ts-backwards: seq 1"], "n": NaN}', REFUSED),
    ("an array at the top level", "[" + ONE + "]", REFUSED),
    ("two JSON documents", ONE + "\n" + ONE, REFUSED),
    ("no output", "", REFUSED),
]


def selftest():
    failures = 0
    for case, output, expected in SELFTEST:
        try:
            got = codes(output)
            shown = json.dumps(got)
        except ShapeError as e:
            got, shown = REFUSED, f"INVALID: {e}"
        if got == expected:
            print(f"  ok     {case}: {shown}")
        else:
            failures += 1
            want = "INVALID" if expected is REFUSED else json.dumps(expected)
            print(f"  WRONG  {case}: {shown}, expected {want}")
    correct = sum(1 for _, _, expected in SELFTEST if expected is not REFUSED)
    print(f"warning-parity self-test: {len(SELFTEST) - failures} of {len(SELFTEST)} read as expected "
          f"({correct} correct results, {len(SELFTEST) - correct} wrong shapes)")
    return 0 if failures == 0 and 0 < correct < len(SELFTEST) else 1


def main(argv):
    if len(argv) == 3 and argv[1] == "codes":
        try:
            found = codes(argv[2])
        except (ShapeError, RecursionError) as e:
            print(f"INVALID: {e}")
            return 1
        print(json.dumps(found))
        return 0
    if len(argv) == 2 and argv[1] == "--selftest":
        return selftest()
    sys.stderr.write("usage: python3 warning-parity.py codes OUTPUT | python3 warning-parity.py --selftest\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
