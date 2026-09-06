package main

import (
	"bytes"
	"time"
)

const historicalSpec = "noa.historical-verification/0.1"
const lifecycleSpec = "noa.signing-key-lifecycle/0.1"

type historicalEvidence struct {
	Retirement   string `json:"retirement"`
	Witness      string `json:"witness"`
	Availability string `json:"availability"`
}

type historicalDimensions struct {
	Integrity                  string             `json:"integrity"`
	Completeness               string             `json:"completeness"`
	Attribution                string             `json:"attribution"`
	OrganizationalIndependence string             `json:"organizationalIndependence"`
	Evidence                   historicalEvidence `json:"evidence"`
}

type historicalPolicy struct {
	VerifierVersion string `json:"verifierVersion"`
	Purpose         string `json:"purpose"`
}

type historicalResult struct {
	Spec                 string               `json:"spec"`
	Policy               historicalPolicy     `json:"policy"`
	Classification       string               `json:"classification"`
	Code                 string               `json:"code"`
	Dimensions           historicalDimensions `json:"dimensions"`
	Chain                *string              `json:"chain"`
	Count                int                  `json:"count"`
	AttributedThroughSeq *int64               `json:"attributedThroughSeq"`
	AsOf                 *string              `json:"asOf"`
}

type historicalTrust struct {
	keyring   *Value
	retired   map[string]bool
	validFrom map[string]*string
	retiredAt map[string]*string
	lifecycle bool
}

func histDimensions(integrity, completeness, attribution, retirement, witness, availability string) historicalDimensions {
	return historicalDimensions{
		Integrity: integrity, Completeness: completeness, Attribution: attribution,
		OrganizationalIndependence: "UNVERIFIED",
		Evidence:                   historicalEvidence{Retirement: retirement, Witness: witness, Availability: availability},
	}
}

func histResult(classification, code string, dimensions historicalDimensions, chain *string, count int, seq *int64, asOf *string) historicalResult {
	return historicalResult{
		Spec:           historicalSpec,
		Policy:         historicalPolicy{VerifierVersion: historicalSpec, Purpose: "historical-audit"},
		Classification: classification, Code: code, Dimensions: dimensions, Chain: chain, Count: count,
		AttributedThroughSeq: seq, AsOf: asOf,
	}
}

func parseInstant(value string) (time.Time, bool) {
	if !rfc3339Instant(value) {
		return time.Time{}, false
	}
	// RFC 3339 permits lowercase `t` and `z`, while Go's layout parser accepts only the uppercase
	// spellings. Normalize only those two grammar-equivalent separators after the shared lexical and
	// calendar validator has accepted the original bytes.
	normalized := []byte(value)
	if normalized[10] == 't' {
		normalized[10] = 'T'
	}
	if normalized[len(normalized)-1] == 'z' {
		normalized[len(normalized)-1] = 'Z'
	}
	t, err := time.Parse(time.RFC3339Nano, string(normalized))
	return t, err == nil
}

func parseHistoricalKeyring(document *Value) (*historicalTrust, bool) {
	if document == nil || !document.isObj() {
		return nil, false
	}
	looksLifecycle := (document.get("spec").isStr() && document.get("spec").Str == lifecycleSpec) ||
		(document.has("keys") && !document.get("keys").isStr())
	if !looksLifecycle {
		flat := &Value{Kind: KindObject, Obj: make(map[string]*Value, len(document.Obj))}
		for kid, publicKey := range document.Obj {
			if kid == "" || !publicKey.isStr() || publicKey.Str == "" {
				return nil, false
			}
			flat.Obj[kid] = &Value{Kind: KindString, Str: publicKey.Str}
		}
		return &historicalTrust{keyring: flat, retired: map[string]bool{}, validFrom: map[string]*string{}, retiredAt: map[string]*string{}, lifecycle: false}, true
	}
	if len(document.Obj) != 2 || !document.has("spec") || !document.has("keys") ||
		!document.get("spec").isStr() || document.get("spec").Str != lifecycleSpec || !document.get("keys").isObj() || len(document.get("keys").Obj) == 0 {
		return nil, false
	}
	flat := &Value{Kind: KindObject, Obj: make(map[string]*Value, len(document.get("keys").Obj))}
	trust := &historicalTrust{keyring: flat, retired: map[string]bool{}, validFrom: map[string]*string{}, retiredAt: map[string]*string{}, lifecycle: true}
	for kid, entry := range document.get("keys").Obj {
		if kid == "" || !entry.isObj() || (len(entry.Obj) != 2 && len(entry.Obj) != 3) || !entry.has("publicKey") || !entry.has("retiredAt") ||
			(len(entry.Obj) == 3 && !entry.has("validFrom")) ||
			!entry.get("publicKey").isStr() || entry.get("publicKey").Str == "" {
			return nil, false
		}
		flat.Obj[kid] = &Value{Kind: KindString, Str: entry.get("publicKey").Str}
		if entry.has("validFrom") {
			activation := entry.get("validFrom")
			if activation.isNull() {
				trust.validFrom[kid] = nil
			} else {
				if !activation.isStr() {
					return nil, false
				}
				if _, ok := parseInstant(activation.Str); !ok {
					return nil, false
				}
				copy := activation.Str
				trust.validFrom[kid] = &copy
			}
		} else {
			// Legacy two-field lifecycle entries declared no lower bound. Never fabricate one.
			trust.validFrom[kid] = nil
		}
		retirement := entry.get("retiredAt")
		if retirement.isNull() {
			trust.retiredAt[kid] = nil
		} else {
			if !retirement.isStr() {
				return nil, false
			}
			if _, ok := parseInstant(retirement.Str); !ok {
				return nil, false
			}
			copy := retirement.Str
			trust.retiredAt[kid] = &copy
			trust.retired[kid] = true
		}
		if trust.validFrom[kid] != nil && trust.retiredAt[kid] != nil {
			activationTime, _ := parseInstant(*trust.validFrom[kid])
			retirementTime, _ := parseInstant(*trust.retiredAt[kid])
			if !activationTime.Before(retirementTime) {
				return nil, false
			}
		}
	}
	return trust, true
}

func verifyHistoricalChain(receipts, receiptRoot, checkpoint, checkpointRoot, identity *Value) historicalResult {
	witness := "NOT_PROVIDED"
	availability := "NOT_PROVIDED"
	if checkpoint != nil {
		witness, availability = "PROVIDED", "AVAILABLE"
	}
	count := 0
	var chain *string
	if receipts != nil && receipts.Kind == KindArray {
		count = len(receipts.Arr)
		if count > 0 && receipts.Arr[0].isObj() && receipts.Arr[0].get("scope").isObj() && receipts.Arr[0].get("scope").get("chain").isStr() {
			value := receipts.Arr[0].get("scope").get("chain").Str
			chain = &value
		}
	}
	receiptTrust, ok := parseHistoricalKeyring(receiptRoot)
	if !ok {
		return histResult("INVALID", "RECEIPT_ROOT_INVALID", histDimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", "NOT_PROVIDED", witness, availability), nil, 0, nil, nil)
	}
	retirement := "NOT_PROVIDED"
	if receiptTrust.lifecycle {
		retirement = "PROVIDED"
	}

	// CONTROL G2-RETIREMENT-INTEGRITY-GO: a historical-only static projection feeds the unchanged
	// verifier without a checkpoint. It authenticates retained bytes and grants no current authority.
	status := verifyChain(receipts, receiptTrust.keyring, identity, nil)
	if status != statusValid {
		if status == statusTampered {
			return histResult("INVALID", "RECEIPT_INTEGRITY_FAILURE", histDimensions("BROKEN", "UNANSWERED", "UNATTRIBUTABLE", retirement, witness, availability), chain, count, nil, nil)
		}
		if status == statusUntrusted {
			return histResult("INVALID", "RECEIPT_IDENTITY_UNTRUSTED", histDimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", retirement, witness, availability), chain, count, nil, nil)
		}
		return histResult("INVALID", "RECEIPT_MALFORMED", histDimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", retirement, witness, availability), chain, count, nil, nil)
	}

	bySeq := make(map[int64]*Value, len(receipts.Arr))
	for _, receipt := range receipts.Arr {
		bySeq[receipt.get("chain").get("seq").Int] = receipt
	}
	head := bySeq[int64(len(receipts.Arr)-1)]
	if checkpoint == nil {
		return histResult("UNVERIFIED", "NO_WITNESS", histDimensions("INTACT", "UNANSWERED", "UNATTRIBUTABLE", retirement, "NOT_PROVIDED", "NOT_PROVIDED"), chain, count, nil, nil)
	}
	if checkpointRoot == nil {
		return histResult("UNVERIFIED", "WITNESS_ROOT_NOT_PROVIDED", histDimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count, nil, nil)
	}
	witnessTrust, ok := parseHistoricalKeyring(checkpointRoot)
	if !ok {
		return histResult("UNVERIFIED", "WITNESS_ROOT_INVALID", histDimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count, nil, nil)
	}
	if !checkpointShapeOK(checkpoint) {
		return histResult("INVALID", "WITNESS_MALFORMED", histDimensions("BROKEN", "UNANSWERED", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count, nil, nil)
	}
	cpVerdict := verifyCheckpoint(checkpoint, witnessTrust.keyring)
	if cpVerdict == "unverified" {
		return histResult("UNVERIFIED", "WITNESS_KEY_NOT_TRUSTED", histDimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count, nil, nil)
	}
	if cpVerdict != "ok" {
		return histResult("INVALID", "WITNESS_INTEGRITY_FAILURE", histDimensions("BROKEN", "UNANSWERED", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count, nil, nil)
	}

	witnessKid := checkpoint.get("sig").get("kid").Str
	witnessPublic := witnessTrust.keyring.get(witnessKid)
	witnessMaterial, err := spkiToRaw(witnessPublic.Str)
	if err != nil {
		return histResult("UNVERIFIED", "WITNESS_ROOT_INVALID", histDimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count, nil, nil)
	}
	// CONTROL G2-WITNESS-KEY-SEPARATION-GO: compare decoded key bytes, including relabelled kids.
	for _, receipt := range receipts.Arr {
		receiptKid := receipt.get("sig").get("kid").Str
		receiptMaterial, err := spkiToRaw(receiptTrust.keyring.get(receiptKid).Str)
		if err != nil {
			return histResult("UNVERIFIED", "RECEIPT_ROOT_INVALID", histDimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count, nil, nil)
		}
		if witnessKid == receiptKid || bytes.Equal(witnessMaterial, receiptMaterial) {
			return histResult("UNVERIFIED", "WITNESS_KEY_NOT_SEPARATE", histDimensions("INTACT", "UNANSWERED", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count, nil, nil)
		}
	}
	if witnessTrust.retired[witnessKid] {
		return histResult("UNVERIFIED", "WITNESS_KEY_RETIRED", histDimensions("INTACT", "UNANSWERED", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count, nil, nil)
	}

	if checkpoint.get("chain").Str != *chain {
		return histResult("CONFLICT", "CHECKPOINT_CONFLICT", histDimensions("INTACT", "CONFLICT", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count, nil, nil)
	}
	cpSeq := checkpoint.get("highestSeq").Int
	if cpSeq > head.get("chain").get("seq").Int {
		return histResult("CONFLICT", "CHECKPOINT_AHEAD", histDimensions("INTACT", "CONFLICT", "UNATTRIBUTABLE", retirement, "PROVIDED", "MISSING_RELATIVE_TO_CHECKPOINT"), chain, count, nil, nil)
	}
	checkpointed, found := bySeq[cpSeq]
	if !found || checkpointed.get("chain").get("hash").Str != checkpoint.get("headHash").Str {
		return histResult("CONFLICT", "CHECKPOINT_CONFLICT", histDimensions("INTACT", "CONFLICT", "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count, nil, nil)
	}
	completeness := "PREFIX_ANCHORED"
	if cpSeq == head.get("chain").get("seq").Int {
		completeness = "HEAD_ANCHORED"
	}
	cpTime, parsedCheckpointTime := parseInstant(checkpoint.get("ts").Str)
	checkpointBeforeActivation := false
	checkpointAfterRetirement := !parsedCheckpointTime
	for seq := int64(0); seq <= cpSeq; seq++ {
		kid := bySeq[seq].get("sig").get("kid").Str
		validFrom := receiptTrust.validFrom[kid]
		if validFrom != nil {
			activationTime, parsed := parseInstant(*validFrom)
			if !parsedCheckpointTime || !parsed || cpTime.Before(activationTime) {
				checkpointBeforeActivation = true
			}
		}
		retiredAt := receiptTrust.retiredAt[kid]
		if retiredAt != nil {
			retirementTime, parsed := parseInstant(*retiredAt)
			if !parsedCheckpointTime || !parsed || !cpTime.Before(retirementTime) {
				checkpointAfterRetirement = true
			}
		}
	}
	if checkpointBeforeActivation {
		return histResult("UNVERIFIED", "CHECKPOINT_BEFORE_ACTIVATION", histDimensions("INTACT", completeness, "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count, nil, nil)
	}
	if checkpointAfterRetirement {
		return histResult("UNVERIFIED", "CHECKPOINT_AFTER_RETIREMENT", histDimensions("INTACT", completeness, "UNATTRIBUTABLE", retirement, "PROVIDED", "AVAILABLE"), chain, count, nil, nil)
	}
	classification := "PARTIAL"
	if completeness == "HEAD_ANCHORED" {
		classification = "VERIFIED"
	}
	asOf := checkpoint.get("ts").Str
	return histResult(classification, completeness, histDimensions("INTACT", completeness, "ATTRIBUTABLE_AS_OF", retirement, "PROVIDED", "AVAILABLE"), chain, count, &cpSeq, &asOf)
}
