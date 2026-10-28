package main

import (
	"bytes"
	"unicode/utf8"
)

// The opt-in strict-bytes verifier profile. "native" (the default) verifies parsed values and never
// judges the received encoding. "strict-bytes" additionally requires the ORIGINAL bytes of a bare
// chain file to equal UTF8(jcs(parsed array)) — the complete array in presented order, brackets and
// separators included — before any receipt check. Nothing is trimmed, BOM-stripped, translated or
// repaired first. A mismatch is MALFORMED with a detail starting NON_CANONICAL_BYTES; equality hands
// the same parsed tree to the unchanged verifyChain, so a canonical input gets the native verdict.
const (
	profileNative      = "native"
	profileStrictBytes = "strict-bytes"
	nonCanonicalBytes  = "NON_CANONICAL_BYTES"
)

func validProfile(p string) bool {
	return p == profileNative || p == profileStrictBytes
}

// admitChainBytes decodes (strict UTF-8), strict-parses and, under strict-bytes, compares the whole
// input once. It returns the parsed tree, or "" plus the MALFORMED detail of a refusal.
func admitChainBytes(data []byte, profile string) (*Value, string) {
	if !validProfile(profile) {
		return nil, "profile must be native or strict-bytes"
	}
	// The parser also rejects invalid UTF-8 inside strings; this check covers every byte, so the
	// comparison below is never reached with a sequence the parser might have read leniently.
	if !utf8.Valid(data) {
		return nil, "input is not valid UTF-8"
	}
	v, err := parseStrict(string(data))
	if err != nil {
		return nil, err.Error()
	}
	if profile == profileStrictBytes {
		canonical, err := jcs(v)
		if err != nil {
			return nil, nonCanonicalBytes + ": receipts: the parsed input has no JCS serialization"
		}
		if !bytes.Equal([]byte(canonical), data) {
			return nil, nonCanonicalBytes + ": receipts: the input bytes are not the UTF-8 JCS serialization of the parsed chain"
		}
	}
	return v, ""
}

// verifyChainBytes is the byte-entry wrapper of verifyChain: the same verdicts, plus the opt-in
// strict-bytes gate above. It returns the status and, for a gate refusal, its detail. The trust
// inputs are parsed values exactly as verifyChain takes them; their acceptance rules are unchanged.
func verifyChainBytes(data []byte, keyring, identity, checkpoint *Value, warnings *[]string, profile string) (string, string) {
	receipts, detail := admitChainBytes(data, profile)
	if detail != "" {
		return statusMalformed, detail
	}
	return verifyChain(receipts, keyring, identity, checkpoint, warnings), ""
}
