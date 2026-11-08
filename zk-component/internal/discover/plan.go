// Package discover is the optional adversarial-fixture discovery extension. A
// planner (deterministic mutation enumeration, or a model behind the Adaption
// Responses API) proposes STRUCTURED MUTATION PLANS against the PTV routine
// response; a local interpreter with an allowlist of actions builds the mutated
// response with keys the fixture permits; the repaired verifier decides; a
// separate specification oracle says what the correct decision is. No model
// verdict is ever used as ground truth and no planner can execute shell commands.
package discover

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Op is one allowlisted mutation.
type Op string

const (
	OpDropField        Op = "drop_field"        // field
	OpSetNull          Op = "set_null"          // field
	OpSetEmptyBstr     Op = "set_empty_bstr"    // field
	OpSetText          Op = "set_text"          // field, value
	OpSetInt           Op = "set_int"           // field, int_value
	OpAddProof         Op = "add_proof"         // (bytes "x")
	OpShiftTimestamp   Op = "shift_timestamp"   // int_value seconds
	OpReplaceNonce     Op = "replace_nonce"     // fresh random nonce in payload
	OpTruncateEvidence Op = "truncate_evidence" // int_value bytes to keep
	OpFlipByte         Op = "flip_byte"         // target: envelope|evidence|quote|quote_sig; int_value index (negative from end)
	OpSignWith         Op = "sign_with"         // value: enrolled|unenrolled
	OpQuoteSignWith    Op = "quote_sign_with"   // value: enrolled|unenrolled
	OpQuoteNonce       Op = "quote_nonce"       // value: issued|random
	OpQuotePCR         Op = "quote_pcr"         // value: reference|other
	OpQuoteMagic       Op = "quote_magic"       // value: tpm_generated|zero
	OpQuoteType        Op = "quote_type"        // value: quote|certify
	OpQuoteHash        Op = "quote_hash"        // value: sha256|sha1
	OpEvidenceFormat   Op = "evidence_format"   // value string
	OpWrongAttester    Op = "wrong_attester"    // value: dep-B|unknown
	OpEnvelopeUntagged Op = "envelope_untagged" // strip CBOR tag 18
	OpAlgHeader        Op = "alg_header"        // value: ES256|ES384|none
)

var allowed = map[Op]bool{OpDropField: true, OpSetNull: true, OpSetEmptyBstr: true, OpSetText: true, OpSetInt: true, OpAddProof: true, OpShiftTimestamp: true, OpReplaceNonce: true, OpTruncateEvidence: true, OpFlipByte: true, OpSignWith: true, OpQuoteSignWith: true, OpQuoteNonce: true, OpQuotePCR: true, OpQuoteMagic: true, OpQuoteType: true, OpQuoteHash: true, OpEvidenceFormat: true, OpWrongAttester: true, OpEnvelopeUntagged: true, OpAlgHeader: true}

var payloadFields = map[string]bool{"ptv_version": true, "msg_type": true, "nonce": true, "attester_id": true, "triage_band": true, "evidence": true, "proof": true, "timestamp": true}

// Mutation is one step of a plan.
type Mutation struct {
	Op       Op     `json:"op"`
	Field    string `json:"field,omitempty"`
	Value    string `json:"value,omitempty"`
	IntValue int    `json:"int_value,omitempty"`
	Target   string `json:"target,omitempty"`
}

// Plan is what a planner proposes.
type Plan struct {
	ID          string     `json:"id"`
	Family      string     `json:"family"`    // planner's semantic label (not trusted for counting)
	Rationale   string     `json:"rationale"` // free text, informational only
	Mutations   []Mutation `json:"mutations"`
	Permissions []string   `json:"permissions"` // what the plan assumes; must be a subset of the fixture's
}

// Capabilities a fixture grants to the interpreter.
type Capabilities struct {
	EnrolledSigner bool `json:"enrolled_signer"` // may sign with the enrolled (software stand-in) AK
	Unenrolled     bool `json:"unenrolled_keys"`
}

// Validate checks a plan against the allowlist and the fixture capabilities.
func (p *Plan) Validate(caps Capabilities) error {
	if len(p.Mutations) == 0 {
		return errors.New("empty plan")
	}
	if len(p.Mutations) > 6 {
		return errors.New("more than 6 mutations")
	}
	for _, m := range p.Mutations {
		if !allowed[m.Op] {
			return fmt.Errorf("op %q not in allowlist", m.Op)
		}
		switch m.Op {
		case OpDropField, OpSetNull, OpSetEmptyBstr, OpSetText, OpSetInt:
			if !payloadFields[m.Field] {
				return fmt.Errorf("field %q not a PTV_PROVE_RESP field", m.Field)
			}
		case OpSignWith, OpQuoteSignWith:
			switch m.Value {
			case "enrolled":
				if !caps.EnrolledSigner {
					return errors.New("plan assumes enrolled signer access the fixture does not grant")
				}
			case "unenrolled":
				if !caps.Unenrolled {
					return errors.New("plan assumes unenrolled keys the fixture does not grant")
				}
			default:
				return fmt.Errorf("sign_with value %q", m.Value)
			}
		case OpFlipByte:
			if m.Target != "envelope" && m.Target != "evidence" && m.Target != "quote" && m.Target != "quote_sig" {
				return fmt.Errorf("flip_byte target %q", m.Target)
			}
		}
	}
	for _, perm := range p.Permissions {
		switch perm {
		case "enrolled_signer":
			if !caps.EnrolledSigner {
				return errors.New("plan requires enrolled_signer")
			}
		case "unenrolled_keys":
			if !caps.Unenrolled {
				return errors.New("plan requires unenrolled_keys")
			}
		case "":
		default:
			return fmt.Errorf("plan requires unavailable permission %q", perm)
		}
	}
	return nil
}

// Canonical returns a signature for deduplication: the sorted, normalized set of
// mutations (cosmetic differences such as rationale text or order do not count).
func (p *Plan) Canonical() string {
	parts := make([]string, 0, len(p.Mutations))
	for _, m := range p.Mutations {
		parts = append(parts, fmt.Sprintf("%s|%s|%s|%d|%s", m.Op, m.Field, m.Value, m.IntValue, m.Target))
	}
	sort.Strings(parts)
	h := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(h[:8])
}

// MustJSON is a helper for logs.
func MustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
