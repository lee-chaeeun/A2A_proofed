package discover

import "fmt"

// Planner proposes plans. Both planners receive the same schema description and
// capability statement; neither executes anything.
type Planner interface {
	Name() string
	Propose(n int) ([]Plan, error)
}

// Mock is the deterministic baseline: enumerate single mutations, then pairs,
// in a fixed order up to n plans. This is the "deterministic mutation/fuzzing
// with a stated budget" comparison arm.
type Mock struct{}

func (Mock) Name() string { return "mock-enumeration" }

func singles() []Mutation {
	var ms []Mutation
	for _, f := range []string{"ptv_version", "msg_type", "nonce", "attester_id", "triage_band", "evidence", "timestamp"} {
		ms = append(ms, Mutation{Op: OpDropField, Field: f}, Mutation{Op: OpSetNull, Field: f}, Mutation{Op: OpSetEmptyBstr, Field: f}, Mutation{Op: OpSetText, Field: f, Value: "x"})
	}
	ms = append(ms,
		Mutation{Op: OpSetInt, Field: "msg_type", IntValue: 1}, Mutation{Op: OpSetInt, Field: "msg_type", IntValue: 3},
		Mutation{Op: OpSetInt, Field: "triage_band", IntValue: 1}, Mutation{Op: OpSetInt, Field: "triage_band", IntValue: 2},
		Mutation{Op: OpSetText, Field: "ptv_version", Value: "1.0"}, Mutation{Op: OpSetText, Field: "ptv_version", Value: "1.1"},
		Mutation{Op: OpAddProof}, Mutation{Op: OpShiftTimestamp, IntValue: 299}, Mutation{Op: OpShiftTimestamp, IntValue: 301}, Mutation{Op: OpShiftTimestamp, IntValue: -3600},
		Mutation{Op: OpReplaceNonce}, Mutation{Op: OpTruncateEvidence, IntValue: 10}, Mutation{Op: OpTruncateEvidence, IntValue: 100},
		Mutation{Op: OpFlipByte, Target: "envelope", IntValue: -1}, Mutation{Op: OpFlipByte, Target: "envelope", IntValue: 5}, Mutation{Op: OpFlipByte, Target: "evidence", IntValue: 20}, Mutation{Op: OpFlipByte, Target: "quote", IntValue: -1}, Mutation{Op: OpFlipByte, Target: "quote_sig", IntValue: -1},
		Mutation{Op: OpSignWith, Value: "unenrolled"}, Mutation{Op: OpSignWith, Value: "enrolled"}, Mutation{Op: OpQuoteSignWith, Value: "unenrolled"},
		Mutation{Op: OpQuoteNonce, Value: "random"}, Mutation{Op: OpQuotePCR, Value: "other"}, Mutation{Op: OpQuoteMagic, Value: "zero"}, Mutation{Op: OpQuoteType, Value: "certify"}, Mutation{Op: OpQuoteHash, Value: "sha1"},
		Mutation{Op: OpEvidenceFormat, Value: "eat"}, Mutation{Op: OpEvidenceFormat, Value: "a2aid-tpm2-quote-v1"}, Mutation{Op: OpWrongAttester, Value: "dep-B"}, Mutation{Op: OpWrongAttester, Value: "unknown"},
		Mutation{Op: OpEnvelopeUntagged}, Mutation{Op: OpAlgHeader, Value: "ES384"}, Mutation{Op: OpAlgHeader, Value: "none"},
	)
	return ms
}

func (Mock) Propose(n int) ([]Plan, error) {
	s := singles()
	var out []Plan
	for i, m := range s {
		if len(out) >= n {
			break
		}
		out = append(out, Plan{ID: fmt.Sprintf("mock-%03d", i), Family: string(m.Op), Mutations: []Mutation{m}, Permissions: []string{"enrolled_signer", "unenrolled_keys"}})
	}
	for i := 0; i < len(s) && len(out) < n; i++ {
		for j := i + 1; j < len(s) && len(out) < n; j++ {
			out = append(out, Plan{ID: fmt.Sprintf("mock-pair-%03d-%03d", i, j), Family: string(s[i].Op) + "+" + string(s[j].Op), Mutations: []Mutation{s[i], s[j]}, Permissions: []string{"enrolled_signer", "unenrolled_keys"}})
		}
	}
	return out, nil
}
