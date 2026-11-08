package discover

import "testing"

// The mock planner's whole single-mutation space must produce zero findings on the
// repaired verifier, and the identity plans must be accepted (oracle positive).
func TestMockEnumerationNoFindings(t *testing.T) {
	lab := NewLab(Capabilities{EnrolledSigner: true, Unenrolled: true})
	plans, _ := Mock{}.Propose(len(singles()))
	var identity, accepted, findings int
	for _, p := range plans {
		o := lab.Execute(p)
		if !o.Valid {
			t.Fatalf("mock produced an invalid plan: %s", o.Invalid)
		}
		if o.Identity {
			identity++
			if o.Verifier != "accept" {
				t.Fatalf("identity plan %s rejected: %s %s", p.ID, o.Stage, o.Code)
			}
		}
		if o.Verifier == "accept" {
			accepted++
		}
		if o.Finding {
			findings++
			t.Errorf("FINDING: %s %v accepted (%s)", p.ID, p.Mutations, o.Stage)
		}
	}
	if identity == 0 || accepted != identity {
		t.Fatalf("identity=%d accepted=%d", identity, accepted)
	}
	t.Logf("%d plans, %d identity (accepted), %d findings", len(plans), identity, findings)
}

func TestPlanValidationRejectsUnavailablePermissions(t *testing.T) {
	p := Plan{ID: "x", Mutations: []Mutation{{Op: OpSignWith, Value: "unenrolled"}}}
	if err := p.Validate(Capabilities{EnrolledSigner: true}); err == nil {
		t.Fatal("unenrolled keys not granted but plan accepted")
	}
	p = Plan{ID: "y", Mutations: []Mutation{{Op: "run_shell", Value: "rm -rf"}}}
	if err := p.Validate(Capabilities{EnrolledSigner: true, Unenrolled: true}); err == nil {
		t.Fatal("non-allowlisted op accepted")
	}
	p = Plan{ID: "z", Mutations: []Mutation{{Op: OpAddProof}}, Permissions: []string{"tls_credentials_A"}}
	if err := p.Validate(Capabilities{EnrolledSigner: true, Unenrolled: true}); err == nil {
		t.Fatal("unavailable permission accepted")
	}
}

func TestLedgerCaps(t *testing.T) {
	l := &Ledger{Path: t.TempDir() + "/l.json"}
	if err := l.Reserve("pilot", "a", 90); err != nil {
		t.Fatal(err)
	}
	if err := l.Reserve("pilot", "b", 20); err == nil {
		t.Fatal("pilot cap exceeded but admitted")
	}
	l.Settle("pilot", "a", 50, false, "")
	if err := l.Reserve("pilot", "b", 50); err != nil {
		t.Fatal(err)
	}
	l.SetBalance(1500)
	if err := l.Reserve("discovery", "c", 400); err != nil {
		t.Fatal(err)
	}
	if err := l.Reserve("heldout", "d", 400); err != nil {
		t.Fatal(err)
	}
	if err := l.Reserve("replication", "e", 300); err != nil {
		t.Fatal(err) // exactly at the 1200 total cap with 300 left in reserve
	}
	if err := l.Reserve("replication", "f", 1); err == nil {
		t.Fatal("total cap / reserve breached")
	}
}
