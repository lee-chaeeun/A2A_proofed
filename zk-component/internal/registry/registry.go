// Package registry is the operator-provisioned enrollment registry the verifier
// trusts. Nothing in it is learned from agent responses.
package registry

import (
	"encoding/json"
	"fmt"
	"os"
)

// Deployment is one enrolled deployment. Keys are public only.
type Deployment struct {
	DeploymentID   string `json:"deployment_id"` // stable identity, independent of display name
	AttesterID     string `json:"attester_id"`   // PTV attester_id, == DeploymentID in this lab
	CardKeyID      string `json:"card_key_id"`   // JWS kid of the publisher key
	CardPublicPEM  string `json:"card_public_pem"`
	SFileKeyID     string `json:"sfile_key_id"`
	SFilePublicPEM string `json:"sfile_public_pem"`
	SIsoKeyID      string `json:"siso_key_id"`
	SIsoPublicPEM  string `json:"siso_public_pem"`
	AKPublicPEM    string `json:"ak_public_pem"`
	AKName         string `json:"ak_name"`
	AKQualified    string `json:"ak_qualified_name"`
	PCRBank        string `json:"pcr_bank"`
	PCRIndex       int    `json:"pcr_index"`
	PCRReference   string `json:"pcr_reference_hex"`
	// v2 transport enrollment (operator-provisioned, never learned from a card):
	TLSName string   `json:"tls_name,omitempty"` // DNS name the deployment's server certificate must carry
	Origins []string `json:"origins,omitempty"`  // authorized endpoint origins (http and https forms)
}

type Registry struct {
	Frozen      string                 `json:"frozen_at"`
	Deployments map[string]*Deployment `json:"deployments"` // label (A/B) -> record
}

func Load(path string) (*Registry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Registry
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	return &r, nil
}

func (r *Registry) Save(path string) error {
	b, _ := json.MarshalIndent(r, "", "  ")
	return os.WriteFile(path, b, 0o644)
}

// KeyOwner resolves an enrolled key identifier (card kid, S-file kid, S-iso kid,
// AK name or AK qualified name) to the label that enrolled it, or "".
func (r *Registry) KeyOwner(id string) string {
	for l, d := range r.Deployments {
		switch id {
		case d.CardKeyID, d.SFileKeyID, d.SIsoKeyID, d.AKName, d.AKQualified:
			return l
		}
	}
	return ""
}

// ByAttesterID resolves a PTV attester_id to a label and record.
func (r *Registry) ByAttesterID(id string) (string, *Deployment) {
	for l, d := range r.Deployments {
		if d.AttesterID == id {
			return l, d
		}
	}
	return "", nil
}
