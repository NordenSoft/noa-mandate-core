package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The opt-in strict-bytes profile through the byte-entry API (verifyChainBytes), against the AUTHORED
// expectations of conformance/vectors/strict-bytes/manifest.json (scripts/gen-vectors.ts section 12).
// The CLI path is covered by conformance_test.sh; this pins the API wrapper the CLI shares its gate with.

const strictBytesDir = "../conformance/vectors/strict-bytes"

type sbOutcome struct {
	Status        string  `json:"status"`
	Exit          int     `json:"exit"`
	Discriminator *string `json:"discriminator"`
}

type sbCase struct {
	Name   string     `json:"name"`
	File   string     `json:"file"`
	Native *sbOutcome `json:"native"`
	Strict sbOutcome  `json:"strict"`
}

func TestStrictBytesManifestThroughVerifyChainBytes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(strictBytesDir, "manifest.json"))
	if err != nil {
		t.Fatalf("strict-bytes manifest unreadable: %v", err)
	}
	var m struct {
		Keyring string   `json:"keyring"`
		Cases   []sbCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("strict-bytes manifest: %v", err)
	}
	if len(m.Cases) != 13 {
		t.Fatalf("strict-bytes manifest: %d cases, want the 13 authored cases", len(m.Cases))
	}
	krBytes, err := os.ReadFile(filepath.Join(strictBytesDir, m.Keyring))
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	keyring, err := parseStrict(string(krBytes))
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	for _, c := range m.Cases {
		data, err := os.ReadFile(filepath.Join(strictBytesDir, c.File))
		if err != nil {
			t.Fatalf("%s: %v", c.File, err)
		}
		status, detail := verifyChainBytes(data, keyring, nil, nil, nil, profileStrictBytes)
		if status != c.Strict.Status {
			t.Errorf("%s strict: status %s (%s), want %s", c.Name, status, detail, c.Strict.Status)
		}
		if c.Strict.Discriminator != nil && !strings.HasPrefix(detail, *c.Strict.Discriminator) {
			t.Errorf("%s strict: detail %q must start with %s", c.Name, detail, *c.Strict.Discriminator)
		}
		if c.Native != nil {
			nStatus, nDetail := verifyChainBytes(data, keyring, nil, nil, nil, profileNative)
			if nStatus != c.Native.Status {
				t.Errorf("%s native: status %s (%s), want %s", c.Name, nStatus, nDetail, c.Native.Status)
			}
		}
	}
	if s, d := verifyChainBytes([]byte("[]"), nil, nil, nil, nil, "strict"); s != statusMalformed || d == "" {
		t.Errorf("an unknown profile must be MALFORMED, got %s %q", s, d)
	}
}

// TestStrictBytesGateReadsOneSnapshot rewrites the CALLER's buffer between the parse and the
// comparison — the window security round 1 (finding 1) named. member-order.json and canonical.json
// have the same length and the same parsed value, so a gate that compared the live buffer would parse
// the non-canonical bytes, then compare the canonical bytes swapped in, and accept. Reading one
// snapshot, it must still refuse the bytes it parsed.
func TestStrictBytesGateReadsOneSnapshot(t *testing.T) {
	nonCanonical, err := os.ReadFile(filepath.Join(strictBytesDir, "member-order.json"))
	if err != nil {
		t.Fatalf("member-order.json: %v", err)
	}
	canonical, err := os.ReadFile(filepath.Join(strictBytesDir, "canonical.json"))
	if err != nil {
		t.Fatalf("canonical.json: %v", err)
	}
	if len(nonCanonical) != len(canonical) || bytes.Equal(nonCanonical, canonical) {
		t.Fatalf("fixture precondition: same length, different bytes (got %d and %d)", len(nonCanonical), len(canonical))
	}
	buf := bytes.Clone(nonCanonical)
	swapped := false
	v, detail := admitChainBytesObserved(buf, profileStrictBytes, func() { copy(buf, canonical); swapped = true })
	if !swapped {
		t.Fatal("the observer did not run between parse and comparison")
	}
	if v != nil || !strings.HasPrefix(detail, nonCanonicalBytes) {
		t.Fatalf("a swap after the parse must not be accepted: value=%v detail=%q", v != nil, detail)
	}
}

// TestJCSStrictBytesLiteral feeds the shared authored input through this port's own strict parser and
// canonicalizer and requires the authored expected bytes exactly.
func TestJCSStrictBytesLiteral(t *testing.T) {
	input, err := os.ReadFile(filepath.Join(strictBytesDir, "jcs-literal-input.json"))
	if err != nil {
		t.Fatalf("jcs-literal-input.json: %v", err)
	}
	want, err := os.ReadFile(filepath.Join(strictBytesDir, "jcs-literal-expected.json"))
	if err != nil {
		t.Fatalf("jcs-literal-expected.json: %v", err)
	}
	v, err := parseStrict(string(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := jcs(v)
	if err != nil {
		t.Fatalf("jcs: %v", err)
	}
	if !bytes.Equal([]byte(got), want) {
		t.Fatalf("JCS literal bytes differ\n got  %q\n want %q", got, want)
	}
}

// TestUTF16KeySortAstralBeforePrivateUse is the discriminating case TestUTF16KeySort lacks: U+1F600
// (UTF-16 D83D DE00) sorts BEFORE U+E000 in UTF-16 order, although it sorts after it by code point.
func TestUTF16KeySortAstralBeforePrivateUse(t *testing.T) {
	keys := []string{"", "\U0001F600"}
	sortUTF16(keys)
	if keys[0] != "\U0001F600" || keys[1] != "" {
		t.Fatalf("UTF-16 sort: got %q, want astral before U+E000", keys)
	}
}
