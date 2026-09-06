package main

import "testing"

func historicalKeyring(t *testing.T, entry string) *Value {
	t.Helper()
	document, err := parseStrict(`{"spec":"noa.signing-key-lifecycle/0.1","keys":{"k":` + entry + `}}`)
	if err != nil {
		t.Fatalf("fixture did not parse: %v", err)
	}
	return document
}

func TestHistoricalLifecycleIntervalAndRfc3339Case(t *testing.T) {
	upper, ok := parseInstant("2026-01-01T00:00:01.000000001Z")
	if !ok {
		t.Fatal("uppercase RFC 3339 instant was rejected")
	}
	lower, ok := parseInstant("2026-01-01t00:00:01.000000001z")
	if !ok || !upper.Equal(lower) {
		t.Fatal("RFC 3339 lowercase t/z did not resolve to the same instant")
	}

	legacy, ok := parseHistoricalKeyring(historicalKeyring(t,
		`{"publicKey":"public","retiredAt":"2026-01-02T00:00:00.000000002Z"}`))
	if !ok || legacy.validFrom["k"] != nil {
		t.Fatal("legacy two-field lifecycle gained a fabricated activation bound")
	}

	window, ok := parseHistoricalKeyring(historicalKeyring(t,
		`{"publicKey":"public","validFrom":"2026-01-01t00:00:01.000000001z","retiredAt":"2026-01-02t00:00:00.000000002z"}`))
	if !ok || window.validFrom["k"] == nil {
		t.Fatal("valid lowercase explicit lifecycle window was rejected")
	}

	for _, entry := range []string{
		`{"publicKey":"public","validFrom":"2026-01-02T00:00:00.000000002Z","retiredAt":"2026-01-02T00:00:00.000000002Z"}`,
		`{"publicKey":"public","validFrom":"2026-01-02T00:00:00.000000003Z","retiredAt":"2026-01-02T00:00:00.000000002Z"}`,
	} {
		if _, ok := parseHistoricalKeyring(historicalKeyring(t, entry)); ok {
			t.Fatalf("invalid lifecycle interval accepted: %s", entry)
		}
	}
}
