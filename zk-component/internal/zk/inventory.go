package zk

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// InventorySchema is the schema of run-inventory.json (declared BEFORE execution).
const InventorySchema = 1

// FixtureSpec is the static definition of one matrix fixture: which business request
// it evaluates, under which contract, into which ledger, against which expected image
// id, and whether it performs its own A2A exchange. The order is the execution order.
type FixtureSpec struct {
	Fixture         string `json:"fixture"`
	RequestID       string `json:"request_id"`
	Contract        string `json:"contract"`
	PinnedVersion   uint32 `json:"pinned_version"`
	LedgerGroup     string `json:"ledger_group"` // fixtures sharing a group share ledgers (Z1 and Z11)
	WrongImage      bool   `json:"wrong_expected_image_id"`
	NetworkExchange bool   `json:"network_exchange"` // a new A2A task is dispatched for this fixture
	ReusesRequest   string `json:"reuses_request,omitempty"`
	ReusesBytesOf   string `json:"reuses_receipt_bytes_of,omitempty"`
}

// FixtureSpecs is the fixed matrix in execution order (13 fixtures).
var FixtureSpecs = []FixtureSpec{
	{Fixture: "Z1", RequestID: "Z1", Contract: "pinned", PinnedVersion: 1, LedgerGroup: "Z1", NetworkExchange: true},
	{Fixture: "Z11", RequestID: "Z1", Contract: "pinned", PinnedVersion: 1, LedgerGroup: "Z1", ReusesRequest: "Z1", ReusesBytesOf: "Z1"},
	{Fixture: "Z9a", RequestID: "Z1", Contract: "pinned", PinnedVersion: 1, LedgerGroup: "Z9a", ReusesRequest: "Z1", ReusesBytesOf: "Z1"},
	{Fixture: "Z9b", RequestID: "Z1", Contract: "pinned", PinnedVersion: 1, LedgerGroup: "Z9b", WrongImage: true, ReusesRequest: "Z1", ReusesBytesOf: "Z1"},
	{Fixture: "Z2", RequestID: "Z2", Contract: "current", PinnedVersion: 2, LedgerGroup: "Z2", NetworkExchange: true},
	{Fixture: "Z3", RequestID: "Z3-B", Contract: "pinned", PinnedVersion: 1, LedgerGroup: "Z3", NetworkExchange: true},
	{Fixture: "Z3P", RequestID: "Z3P-B", Contract: "pinned", PinnedVersion: 1, LedgerGroup: "Z3P", NetworkExchange: true},
	{Fixture: "Z4", RequestID: "Z4", Contract: "current", PinnedVersion: 2, LedgerGroup: "Z4", NetworkExchange: true},
	{Fixture: "Z5", RequestID: "Z5", Contract: "current", PinnedVersion: 2, LedgerGroup: "Z5", NetworkExchange: true},
	{Fixture: "Z6", RequestID: "Z6", Contract: "pinned", PinnedVersion: 1, LedgerGroup: "Z6", NetworkExchange: true},
	{Fixture: "Z7", RequestID: "Z7", Contract: "current", PinnedVersion: 1, LedgerGroup: "Z7", ReusesRequest: "Z6", ReusesBytesOf: "Z6"},
	{Fixture: "Z8", RequestID: "Z8", Contract: "current", PinnedVersion: 2, LedgerGroup: "Z8", NetworkExchange: true},
	{Fixture: "Z10", RequestID: "Z10", Contract: "pinned", PinnedVersion: 1, LedgerGroup: "Z10", NetworkExchange: true},
}

// InventoryEntry is one expected evaluation (fixture × policy).
type InventoryEntry struct {
	EvaluationID     string `json:"evaluation_id"`
	Ordinal          int    `json:"ordinal"`
	Fixture          string `json:"fixture"`
	Policy           string `json:"policy"`
	RequestID        string `json:"request_id"`
	Contract         string `json:"contract"`
	PinnedVersion    uint32 `json:"pinned_version"`
	LedgerID         string `json:"ledger_id"`
	ExpectedImageID  string `json:"expected_image_id_hex"`
	NetworkExchange  bool   `json:"network_exchange"`
	ReusesRequest    string `json:"reuses_request,omitempty"`
	ReusesBytesOf    string `json:"reuses_receipt_bytes_of,omitempty"`
	PredictedApprove bool   `json:"predicted_approve"`
	VerifyFails      bool   `json:"predicted_verify_fails"`
	Title            string `json:"title,omitempty"`
}

// Inventory is the declared set of evaluations of one run.
type Inventory struct {
	Schema        int              `json:"inventory_schema"`
	Kind          string           `json:"kind"` // "run" (written before execution) | "legacy" (declared afterwards for schema-1 runs)
	DeclaredAt    string           `json:"declared_at"`
	RunID         string           `json:"run_id,omitempty"`
	PinnedImageID string           `json:"pinned_image_id_hex"`
	WrongImageID  string           `json:"wrong_image_id_hex"` // the deliberately wrong id used by Z9b
	Fixtures      []string         `json:"fixtures"`
	Policies      []string         `json:"policies"`
	Evaluations   []InventoryEntry `json:"evaluations"`
	Note          string           `json:"note"`
}

// WrongImageID derives the deliberately wrong expected image id of fixture Z9b from
// the pinned id (first hex digit changed; '0' becomes '1', anything else '0').
func WrongImageID(pinned string) string {
	if pinned == "" {
		return ""
	}
	b := []byte(pinned)
	if b[0] == '0' {
		b[0] = '1'
	} else {
		b[0] = '0'
	}
	return string(b)
}

// BuildInventory declares the 13 × 4 evaluations for a pinned image id and the frozen
// predictions. kind is "run" or "legacy".
func BuildInventory(kind, runID, pinned string, pred predictions) (*Inventory, error) {
	if !imageIDRe.MatchString(pinned) {
		return nil, fmt.Errorf("pinned image id must be 64 hex characters")
	}
	inv := &Inventory{Schema: InventorySchema, Kind: kind, DeclaredAt: time.Now().UTC().Format(time.RFC3339), RunID: runID, PinnedImageID: pinned, WrongImageID: WrongImageID(pinned), Policies: append([]string(nil), Policies...)}
	ord := 0
	for _, f := range FixtureSpecs {
		p, ok := pred.Fixtures[f.Fixture]
		if !ok {
			return nil, fmt.Errorf("predictions lack fixture %s", f.Fixture)
		}
		inv.Fixtures = append(inv.Fixtures, f.Fixture)
		for _, pol := range Policies {
			ord++
			img := pinned
			if f.WrongImage {
				img = inv.WrongImageID
			}
			inv.Evaluations = append(inv.Evaluations, InventoryEntry{EvaluationID: f.Fixture + "/" + pol, Ordinal: ord, Fixture: f.Fixture, Policy: pol, RequestID: f.RequestID, Contract: f.Contract, PinnedVersion: f.PinnedVersion, LedgerID: f.LedgerGroup + "/" + pol, ExpectedImageID: img, NetworkExchange: f.NetworkExchange, ReusesRequest: f.ReusesRequest, ReusesBytesOf: f.ReusesBytesOf, PredictedApprove: p.Approve[pol], VerifyFails: p.VerifyFails, Title: p.Title})
		}
	}
	switch kind {
	case "run":
		inv.Note = "Declared BEFORE execution: every fixture × policy evaluation the run must produce exactly once, with its request, contract, ledger and the expected image id the requester pins (Z9b deliberately wrong). The offline oracle takes these facts from here, never from decision rows."
	case "legacy":
		inv.Note = "Declared on 2026-11-08 AFTER the schema-1 runs, from ZK_COMPONENT_PLAN.md's fixture table, fixtures/zk/predictions.json and the pinned image id recorded in the run provenance. Used only by the separately identified legacy replay/audit view of schema-1 runs; it adds no field those runs did not record."
	default:
		return nil, errors.New("inventory kind must be run or legacy")
	}
	return inv, nil
}

// WriteInventory writes the declared inventory as JSON.
func WriteInventory(path string, inv *Inventory) error {
	b, err := json.MarshalIndent(inv, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// LoadInventory reads and structurally validates an inventory: schema, non-empty,
// unique evaluation ids and (fixture, policy) keys, known policies and contracts,
// 64-hex image ids, non-empty request and ledger ids, ordinals 1..n in order.
func LoadInventory(path string) (*Inventory, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var inv Inventory
	if err := json.Unmarshal(b, &inv); err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	if inv.Schema != InventorySchema {
		return nil, fmt.Errorf("inventory schema %d unsupported", inv.Schema)
	}
	if inv.Kind != "run" && inv.Kind != "legacy" {
		return nil, fmt.Errorf("inventory kind %q unknown", inv.Kind)
	}
	if len(inv.Evaluations) == 0 {
		return nil, errors.New("inventory declares no evaluations")
	}
	if !imageIDRe.MatchString(inv.PinnedImageID) {
		return nil, errors.New("inventory pinned image id is not 64 hex characters")
	}
	seenID := map[string]bool{}
	seenKey := map[string]bool{}
	for i, e := range inv.Evaluations {
		if e.Ordinal != i+1 {
			return nil, fmt.Errorf("inventory ordinal %d at position %d", e.Ordinal, i+1)
		}
		if e.EvaluationID == "" || e.EvaluationID != e.Fixture+"/"+e.Policy {
			return nil, fmt.Errorf("inventory evaluation id %q must be <fixture>/<policy>", e.EvaluationID)
		}
		if seenID[e.EvaluationID] {
			return nil, fmt.Errorf("inventory duplicates evaluation %s", e.EvaluationID)
		}
		seenID[e.EvaluationID] = true
		k := e.Fixture + "\x00" + e.Policy
		if seenKey[k] {
			return nil, fmt.Errorf("inventory duplicates key %s/%s", e.Fixture, e.Policy)
		}
		seenKey[k] = true
		if !KnownPolicy(e.Policy) {
			return nil, fmt.Errorf("inventory evaluation %s has unknown policy", e.EvaluationID)
		}
		if e.Contract != string(Pinned) && e.Contract != string(Current) {
			return nil, fmt.Errorf("inventory evaluation %s has unknown contract %q", e.EvaluationID, e.Contract)
		}
		if e.RequestID == "" || e.LedgerID == "" || e.PinnedVersion == 0 {
			return nil, fmt.Errorf("inventory evaluation %s lacks request/ledger/version", e.EvaluationID)
		}
		if !imageIDRe.MatchString(e.ExpectedImageID) {
			return nil, fmt.Errorf("inventory evaluation %s expected image id is not 64 hex characters", e.EvaluationID)
		}
	}
	return &inv, nil
}
