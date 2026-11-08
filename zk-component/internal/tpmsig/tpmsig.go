// Package tpmsig talks to a TPM 2.0 (swtpm) over a raw unix socket with go-tpm's
// direct API. It provisions a restricted ECC P-256 attestation key (AK) inside the
// TPM, produces TPM2_Quote evidence, and signs arbitrary COSE Sig_structure bytes
// with the same AK via TPM2_Hash validation tickets. The AK private part never
// leaves the TPM.
package tpmsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	cose "github.com/veraison/go-cose"
)

// AKPersistentHandle is where provisioning stores the attestation key.
const AKPersistentHandle = tpm2.TPMHandle(0x81010002)

// RefPCR is the single PCR index appraised in this experiment (debug PCR, resettable).
const RefPCR = 16

// Conn is one connection to a TPM socket. swtpm serves one data connection at a
// time, so callers open, use and close.
type Conn struct {
	c net.Conn
	t transport.TPMCloser
}

// Open dials a unix socket (directly to swtpm, or to a signer gate in front of it).
func Open(sock string) (*Conn, error) {
	c, err := net.Dial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("tpm dial %s: %w", sock, err)
	}
	return &Conn{c: c, t: transport.FromReadWriteCloser(c)}, nil
}

func (c *Conn) Close() error { return c.t.Close() }

var akTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
		UserWithAuth: true, Restricted: true, SignEncrypt: true, NoDA: true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		Scheme: tpm2.TPMTECCScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
		},
		CurveID: tpm2.TPMECCNistP256,
	}),
}

// AKInfo is the public enrollment record of a provisioned AK.
type AKInfo struct {
	PublicPEM     string `json:"ak_public_pem"`
	Name          string `json:"ak_name"`           // hex TPM2B_NAME
	QualifiedName string `json:"ak_qualified_name"` // hex, as it appears in TPMS_ATTEST.qualifiedSigner
	Handle        uint32 `json:"ak_handle"`
}

// Provision creates SRK + restricted AK with the given auth, makes the AK persistent,
// and returns the public enrollment record. Must run against a clean emulator.
func (c *Conn) Provision(akAuth []byte) (*AKInfo, error) {
	srk, err := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}.Execute(c.t)
	if err != nil {
		return nil, fmt.Errorf("createprimary: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: srk.ObjectHandle}.Execute(c.t)
	cr, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name},
		InSensitive:  tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{UserAuth: tpm2.TPM2BAuth{Buffer: akAuth}}},
		InPublic:     tpm2.New2B(akTemplate),
	}.Execute(c.t)
	if err != nil {
		return nil, fmt.Errorf("create ak: %w", err)
	}
	ld, err := tpm2.Load{ParentHandle: tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name}, InPrivate: cr.OutPrivate, InPublic: cr.OutPublic}.Execute(c.t)
	if err != nil {
		return nil, fmt.Errorf("load ak: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: ld.ObjectHandle}.Execute(c.t)
	if _, err := (tpm2.EvictControl{
		Auth:             tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		ObjectHandle:     tpm2.NamedHandle{Handle: ld.ObjectHandle, Name: ld.Name},
		PersistentHandle: AKPersistentHandle,
	}).Execute(c.t); err != nil {
		return nil, fmt.Errorf("evictcontrol: %w", err)
	}
	return c.ReadAK()
}

// ReadAK reads the public enrollment record of the persistent AK.
func (c *Conn) ReadAK() (*AKInfo, error) {
	rp, err := tpm2.ReadPublic{ObjectHandle: AKPersistentHandle}.Execute(c.t)
	if err != nil {
		return nil, fmt.Errorf("readpublic: %w", err)
	}
	pub, err := rp.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	pk, err := ECDSAFromPublic(pub)
	if err != nil {
		return nil, err
	}
	der, _ := x509.MarshalPKIXPublicKey(pk)
	return &AKInfo{
		PublicPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		Name:          hex.EncodeToString(rp.Name.Buffer),
		QualifiedName: hex.EncodeToString(rp.QualifiedName.Buffer),
		Handle:        uint32(AKPersistentHandle),
	}, nil
}

// CreateTransientAK creates a never-enrolled AK (for the unknown-key fixture) and
// returns its handle and public key. The caller must flush it.
func (c *Conn) CreateTransientAK(auth []byte) (tpm2.TPMHandle, tpm2.TPM2BName, *ecdsa.PublicKey, error) {
	srk, err := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}.Execute(c.t)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	defer tpm2.FlushContext{FlushHandle: srk.ObjectHandle}.Execute(c.t)
	cr, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name},
		InSensitive:  tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{UserAuth: tpm2.TPM2BAuth{Buffer: auth}}},
		InPublic:     tpm2.New2B(akTemplate),
	}.Execute(c.t)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	ld, err := tpm2.Load{ParentHandle: tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name}, InPrivate: cr.OutPrivate, InPublic: cr.OutPublic}.Execute(c.t)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	pub, _ := cr.OutPublic.Contents()
	pk, err := ECDSAFromPublic(pub)
	return ld.ObjectHandle, ld.Name, pk, err
}

func (c *Conn) Flush(h tpm2.TPMHandle) { tpm2.FlushContext{FlushHandle: h}.Execute(c.t) }

// ECDSAFromPublic converts a TPMT_PUBLIC ECC P-256 key to crypto/ecdsa.
func ECDSAFromPublic(pub *tpm2.TPMTPublic) (*ecdsa.PublicKey, error) {
	ecc, err := pub.Unique.ECC()
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(ecc.X.Buffer), Y: new(big.Int).SetBytes(ecc.Y.Buffer)}, nil
}

// ParsePublicPEM parses a PKIX ECDSA public key.
func ParsePublicPEM(p string) (*ecdsa.PublicKey, error) {
	blk, _ := pem.Decode([]byte(p))
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA key")
	}
	return ek, nil
}

func pcrSel() tpm2.TPMLPCRSelection {
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(RefPCR)}}}
}

// ReadPCR returns the SHA-256 bank value of RefPCR.
func (c *Conn) ReadPCR() ([]byte, error) {
	pr, err := tpm2.PCRRead{PCRSelectionIn: pcrSel()}.Execute(c.t)
	if err != nil {
		return nil, err
	}
	if len(pr.PCRValues.Digests) != 1 {
		return nil, errors.New("unexpected PCR read result")
	}
	return pr.PCRValues.Digests[0].Buffer, nil
}

// ExtendPCR extends RefPCR with sha256(data).
func (c *Conn) ExtendPCR(data []byte) error {
	d := sha256.Sum256(data)
	_, err := tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(RefPCR), Auth: tpm2.PasswordAuth(nil)},
		Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: d[:]}}},
	}.Execute(c.t)
	return err
}

// ResetPCR resets RefPCR (allowed for PCR 16 at locality 0).
func (c *Conn) ResetPCR() error {
	_, err := tpm2.PCRReset{PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(RefPCR), Auth: tpm2.PasswordAuth(nil)}}.Execute(c.t)
	return err
}

// QuoteResult is the raw evidence produced by TPM2_Quote.
type QuoteResult struct {
	Quoted    []byte // TPMS_ATTEST bytes exactly as signed
	Signature []byte // marshalled TPMT_SIGNATURE
	PCRValue  []byte // current RefPCR value (diagnostic; the verifier uses its own reference)
}

// Quote produces a fresh quote over RefPCR with nonce as qualifying data.
func (c *Conn) Quote(handle tpm2.TPMHandle, name tpm2.TPM2BName, auth, nonce []byte) (*QuoteResult, error) {
	pcr, err := c.ReadPCR()
	if err != nil {
		return nil, err
	}
	q, err := tpm2.Quote{
		SignHandle:     tpm2.AuthHandle{Handle: handle, Name: name, Auth: tpm2.PasswordAuth(auth)},
		QualifyingData: tpm2.TPM2BData{Buffer: nonce},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		PCRSelect:      pcrSel(),
	}.Execute(c.t)
	if err != nil {
		return nil, fmt.Errorf("quote: %w", err)
	}
	return &QuoteResult{Quoted: q.Quoted.Bytes(), Signature: tpm2.Marshal(q.Signature), PCRValue: pcr}, nil
}

// QuotePersistent quotes with the enrolled persistent AK.
func (c *Conn) QuotePersistent(auth, nonce []byte) (*QuoteResult, error) {
	rp, err := tpm2.ReadPublic{ObjectHandle: AKPersistentHandle}.Execute(c.t)
	if err != nil {
		return nil, fmt.Errorf("readpublic: %w", err)
	}
	return c.Quote(AKPersistentHandle, rp.Name, auth, nonce)
}

// SignWithTicket hashes content in the TPM (owner hierarchy ticket) and signs the
// digest with the restricted AK. Returns a raw r||s ECDSA signature (COSE format).
func (c *Conn) SignWithTicket(handle tpm2.TPMHandle, name tpm2.TPM2BName, auth, content []byte) ([]byte, error) {
	hr, err := tpm2.Hash{Data: tpm2.TPM2BMaxBuffer{Buffer: content}, HashAlg: tpm2.TPMAlgSHA256, Hierarchy: tpm2.TPMRHOwner}.Execute(c.t)
	if err != nil {
		return nil, fmt.Errorf("tpm2_hash: %w", err)
	}
	sr, err := tpm2.Sign{
		KeyHandle:  tpm2.AuthHandle{Handle: handle, Name: name, Auth: tpm2.PasswordAuth(auth)},
		Digest:     hr.OutHash,
		InScheme:   tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		Validation: hr.Validation,
	}.Execute(c.t)
	if err != nil {
		return nil, fmt.Errorf("tpm2_sign: %w", err)
	}
	ecc, err := sr.Signature.Signature.ECDSA()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	copy(out[32-len(ecc.SignatureR.Buffer):32], ecc.SignatureR.Buffer)
	copy(out[64-len(ecc.SignatureS.Buffer):], ecc.SignatureS.Buffer)
	return out, nil
}

// COSESigner adapts a TPM AK to go-cose's Signer interface. Each Sign opens its own
// socket connection so the gate sees one invocation per signature.
type COSESigner struct {
	Sock   string
	Handle tpm2.TPMHandle
	Name   tpm2.TPM2BName
	Auth   []byte
	Hook   func(kind string) // invoked before each TPM operation (controller reporting)
	mu     sync.Mutex
}

func (s *COSESigner) Algorithm() cose.Algorithm { return cose.AlgorithmES256 }

func (s *COSESigner) Sign(_ io.Reader, content []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Hook != nil {
		s.Hook("tpm2_hash+tpm2_sign")
	}
	c, err := Open(s.Sock)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	name := s.Name
	if len(name.Buffer) == 0 {
		rp, err := tpm2.ReadPublic{ObjectHandle: s.Handle}.Execute(c.t)
		if err != nil {
			return nil, err
		}
		name = rp.Name
	}
	return c.SignWithTicket(s.Handle, name, s.Auth, content)
}

// QuoteVerdict is the structured result of verifying a quote.
type QuoteVerdict struct {
	Parsed          bool   `json:"parsed"`
	MagicOK         bool   `json:"magic_ok"`   // TPMS_ATTEST.magic == TPM_GENERATED_VALUE
	TypeOK          bool   `json:"type_ok"`    // TPM_ST_ATTEST_QUOTE
	SigAlgOK        bool   `json:"sig_alg_ok"` // TPMT_SIGNATURE is ECDSA with SHA-256
	NonceMatch      bool   `json:"nonce_match"`
	SignerMatch     bool   `json:"signer_match"`    // qualifiedSigner == enrolled AK qualified name
	SignatureValid  bool   `json:"signature_valid"` // ECDSA under enrolled AK public key
	PCRSelectionOK  bool   `json:"pcr_selection_ok"`
	PCRDigestMatch  bool   `json:"pcr_digest_match"` // against operator reference value
	PCRDigestHex    string `json:"pcr_digest_hex"`
	QualifiedSigner string `json:"qualified_signer_hex"`
	Reason          string `json:"reason,omitempty"`
}

// OK is the complete acceptance predicate: every structural and cryptographic
// check must hold. Callers must never accept a quote for which OK() is false.
func (v QuoteVerdict) OK() bool {
	return v.Parsed && v.MagicOK && v.TypeOK && v.SigAlgOK && v.NonceMatch && v.SignerMatch && v.SignatureValid && v.PCRSelectionOK && v.PCRDigestMatch
}

// VerifyQuote appraises quoted/signature bytes against enrolled AK and reference PCR.
// It validates: TPM_GENERATED magic, attestation type QUOTE, ECDSA/SHA-256 signature
// parameters, signature under the enrolled AK public key, qualifiedSigner, extraData
// == nonce, the exact PCR selection (sha256 bank, PCR 16 only) and pcrDigest ==
// sha256(reference PCR value). No field of the quote is trusted before the signature
// check, and no check is skipped when an earlier one fails (the verdict is complete).
func VerifyQuote(quoted, sig []byte, akPub *ecdsa.PublicKey, akQualifiedNameHex string, nonce, refPCR []byte) (v QuoteVerdict) {
	defer func() {
		if r := recover(); r != nil {
			v = QuoteVerdict{Reason: fmt.Sprintf("panic during quote appraisal: %v", r)}
		}
	}()
	if len(quoted) == 0 || len(sig) == 0 {
		v.Reason = "empty quote or signature"
		return v
	}
	// go-tpm checks the magic value while unmarshalling (gotpm:"check"); we record it
	// explicitly as well so the verdict shows which structural rule failed.
	if len(quoted) >= 4 {
		magic := uint32(quoted[0])<<24 | uint32(quoted[1])<<16 | uint32(quoted[2])<<8 | uint32(quoted[3])
		v.MagicOK = magic == uint32(tpm2.TPMGeneratedValue)
	}
	att, err := tpm2.Unmarshal[tpm2.TPMSAttest](quoted)
	if err != nil {
		v.Reason = "attest unmarshal: " + err.Error()
		return v
	}
	v.MagicOK = v.MagicOK && att.Magic == tpm2.TPMGeneratedValue
	v.TypeOK = att.Type == tpm2.TPMSTAttestQuote
	if !v.TypeOK {
		v.Reason = "attest type is not QUOTE"
		return v
	}
	qi, err := att.Attested.Quote()
	if err != nil {
		v.Reason = "attested is not quote info"
		return v
	}
	v.Parsed = true
	v.QualifiedSigner = hex.EncodeToString(att.QualifiedSigner.Buffer)
	v.NonceMatch = len(nonce) > 0 && string(att.ExtraData.Buffer) == string(nonce)
	v.SignerMatch = akQualifiedNameHex != "" && v.QualifiedSigner == akQualifiedNameHex
	ts, err := tpm2.Unmarshal[tpm2.TPMTSignature](sig)
	if err == nil && ts.SigAlg == tpm2.TPMAlgECDSA {
		if ecc, err := ts.Signature.ECDSA(); err == nil {
			v.SigAlgOK = ecc.Hash == tpm2.TPMAlgSHA256
			if v.SigAlgOK && akPub != nil {
				h := sha256.Sum256(quoted)
				v.SignatureValid = ecdsa.Verify(akPub, h[:], new(big.Int).SetBytes(ecc.SignatureR.Buffer), new(big.Int).SetBytes(ecc.SignatureS.Buffer))
			}
		}
	}
	want := pcrSel()
	if len(qi.PCRSelect.PCRSelections) == 1 {
		got := qi.PCRSelect.PCRSelections[0]
		v.PCRSelectionOK = got.Hash == want.PCRSelections[0].Hash && hex.EncodeToString(got.PCRSelect) == hex.EncodeToString(want.PCRSelections[0].PCRSelect)
	}
	v.PCRDigestHex = hex.EncodeToString(qi.PCRDigest.Buffer)
	exp := sha256.Sum256(refPCR)
	v.PCRDigestMatch = len(refPCR) == 32 && v.PCRDigestHex == hex.EncodeToString(exp[:])
	if !v.OK() {
		switch {
		case !v.MagicOK:
			v.Reason = "TPMS_ATTEST magic is not TPM_GENERATED"
		case !v.SigAlgOK:
			v.Reason = "signature is not ECDSA/SHA-256"
		case !v.SignatureValid:
			v.Reason = "quote signature invalid under enrolled AK"
		case !v.SignerMatch:
			v.Reason = "qualifiedSigner is not the enrolled AK"
		case !v.NonceMatch:
			v.Reason = "quote extraData != issued nonce"
		case !v.PCRSelectionOK:
			v.Reason = "PCR selection differs from policy"
		case !v.PCRDigestMatch:
			v.Reason = "PCR digest != reference value"
		}
	}
	return v
}

var _ crypto.PublicKey = (*ecdsa.PublicKey)(nil)

// Transport exposes the underlying go-tpm transport for callers that need a raw command.
func (c *Conn) Transport() transport.TPM { return c.t }
