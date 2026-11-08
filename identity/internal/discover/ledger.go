package discover

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Budget caps proposed in the brief. Credits are an opaque unit of the provider's
// balance, not a dollar amount; nothing here converts them.
var PhaseCaps = map[string]int{"pilot": 100, "discovery": 400, "heldout": 400, "replication": 300}

const TotalCap = 1200
const Reserve = 300

// Entry is one ledger line: a reservation (outstanding) or a charge (settled).
type Entry struct {
	At      time.Time `json:"at"`
	Phase   string    `json:"phase"`
	Kind    string    `json:"kind"` // reserve | charge | release | failed
	Credits int       `json:"credits"`
	Ref     string    `json:"ref,omitempty"`
	Note    string    `json:"note,omitempty"`
}

type Ledger struct {
	Path    string  `json:"-"`
	Balance int     `json:"reported_available_credits"` // last value the provider reported
	Entries []Entry `json:"entries"`
}

func LoadLedger(path string) *Ledger {
	l := &Ledger{Path: path}
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, l)
	}
	l.Path = path
	return l
}

func (l *Ledger) save() error {
	b, _ := json.MarshalIndent(l, "", "  ")
	return os.WriteFile(l.Path, b, 0o644)
}

// Totals returns settled charges and outstanding reservations per phase and overall.
func (l *Ledger) Totals() (charged, reserved map[string]int, totalCharged, totalReserved int) {
	charged, reserved = map[string]int{}, map[string]int{}
	open := map[string]int{} // ref -> reserved credits
	for _, e := range l.Entries {
		switch e.Kind {
		case "reserve":
			open[e.Ref] += e.Credits
			reserved[e.Phase] += e.Credits
		case "release", "charge", "failed":
			if r, ok := open[e.Ref]; ok {
				reserved[e.Phase] -= r
				delete(open, e.Ref)
			}
			if e.Kind == "charge" {
				charged[e.Phase] += e.Credits
			}
		}
	}
	for p, c := range charged {
		totalCharged += c
		_ = p
	}
	for _, r := range reserved {
		totalReserved += r
	}
	return
}

// Reserve admits a batch only if its conservative bound fits the phase cap and the
// total cap after existing charges and outstanding reservations.
func (l *Ledger) Reserve(phase, ref string, bound int) error {
	cap, ok := PhaseCaps[phase]
	if !ok {
		return fmt.Errorf("unknown phase %q", phase)
	}
	if bound <= 0 {
		return errors.New("a batch needs a positive conservative cost bound")
	}
	charged, reserved, tc, tr := l.Totals()
	if charged[phase]+reserved[phase]+bound > cap {
		return fmt.Errorf("phase %s: %d charged + %d reserved + %d bound > cap %d", phase, charged[phase], reserved[phase], bound, cap)
	}
	if tc+tr+bound > TotalCap {
		return fmt.Errorf("total: %d charged + %d reserved + %d bound > cap %d", tc, tr, bound, TotalCap)
	}
	if l.Balance > 0 && l.Balance-(tr+bound) < Reserve {
		return fmt.Errorf("provider balance %d minus outstanding %d would drop under the %d-credit reserve", l.Balance, tr+bound, Reserve)
	}
	l.Entries = append(l.Entries, Entry{At: time.Now().UTC(), Phase: phase, Kind: "reserve", Credits: bound, Ref: ref})
	return l.save()
}

// Settle records the actual charge (or failure) for a reservation. A partial
// failure is settled with whatever the provider reported as consumed.
func (l *Ledger) Settle(phase, ref string, credits int, failed bool, note string) error {
	kind := "charge"
	if failed && credits == 0 {
		kind = "failed"
	}
	l.Entries = append(l.Entries, Entry{At: time.Now().UTC(), Phase: phase, Kind: kind, Credits: credits, Ref: ref, Note: note})
	return l.save()
}

func (l *Ledger) SetBalance(b int) { l.Balance = b; l.save() }
