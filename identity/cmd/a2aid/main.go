// a2aid: local A2A identity experiment (card / software challenge / TPM quote / PTV
// / transport controls / channel binding).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"

	"a2aid/internal/agent"
	"a2aid/internal/audit"
	"a2aid/internal/cardsig"
	"a2aid/internal/controller"
	"a2aid/internal/ctl"
	"a2aid/internal/gate"
	"a2aid/internal/matrix"
	"a2aid/internal/registry"
	"a2aid/internal/tpmsig"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "setup":
		setup(os.Args[2:])
	case "provision":
		provision(os.Args[2:])
	case "publish-card":
		publishCard(os.Args[2:])
	case "controller":
		runController(os.Args[2:])
	case "gate":
		runGate(os.Args[2:])
	case "agent":
		runAgent(os.Args[2:])
	case "matrix":
		matrix.Main(os.Args[2:])
	case "traces":
		matrix.TracesMain(os.Args[2:])
	case "audit-release":
		audit.Main(os.Args[2:])
	case "reverify":
		matrix.ReverifyMain(os.Args[2:])
	case "version":
		fmt.Println(matrix.Versions())
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: a2aid setup|provision|publish-card|controller|gate|agent|matrix|traces|audit-release|reverify|version ...")
	os.Exit(2)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func genKey(path string) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	der, _ := x509.MarshalECPrivateKey(k)
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	must(os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600))
	return k
}

func pubPEM(k *ecdsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- lab PKI -------------------------------------------------------------------

// labCA creates run/ca/{ca.pem,ca.key} (ECDSA P-256, 10 days).
func labCA(runDir string) (*x509.Certificate, *ecdsa.PrivateKey) {
	dir := filepath.Join(runDir, "ca")
	must(os.MkdirAll(dir, 0o755))
	key := genKey(filepath.Join(dir, "ca.key"))
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "a2aid lab root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(240 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	must(err)
	must(os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	ca, _ := x509.ParseCertificate(der)
	return ca, key
}

// serverCert issues dir/{cert.pem,key.pem} for name, signed by the issuer (or
// self-signed when issuer is nil: the "wrong certificate" fixture).
func serverCert(dir, name string, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) {
	must(os.MkdirAll(dir, 0o700))
	key := genKey(filepath.Join(dir, "key.pem"))
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(240 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	parent, pk := issuer, issuerKey
	if parent == nil {
		parent, pk = tpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, pk)
	must(err)
	must(os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
}

// ---- setup -----------------------------------------------------------------------

// setup: clean state -> two swtpm instances -> lab CA -> provision A and B.
func setup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	runDir := fs.String("run-dir", "run", "")
	fs.Parse(args)
	abs, _ := filepath.Abs(*runDir)
	must(os.MkdirAll(abs, 0o755))
	for _, l := range []string{"A", "B"} {
		if _, err := tpmsig.StartSWTPM(filepath.Join(abs, "tpm"+l)); err != nil {
			log.Fatalf("swtpm %s: %v", l, err)
		}
	}
	ca, caKey := labCA(abs)
	serverCert(filepath.Join(abs, "A", "tls"), matrix.AName, ca, caKey)
	serverCert(filepath.Join(abs, "B", "tls"), matrix.BName, ca, caKey)
	serverCert(filepath.Join(abs, "B", "tls-selfsigned-as-A"), matrix.AName, nil, nil) // wrong-issuer certificate for F17
	must(os.MkdirAll(filepath.Join(abs, "gate"), 0o755))
	provisionOne(abs, "A", "dep-A", "Atlas", matrix.AName, matrix.AURL, matrix.ATLSURL, filepath.Join(abs, "tpmA", "tpm.sock"), filepath.Join(abs, "gate", "tpmA.sock"), filepath.Join(abs, "gate", "swA.sock"))
	provisionOne(abs, "B", "dep-B", "Boreas", matrix.BName, matrix.BURL, matrix.BTLSURL, filepath.Join(abs, "tpmB", "tpm.sock"), filepath.Join(abs, "gate", "tpmB.sock"), filepath.Join(abs, "gate", "swB.sock"))
	fmt.Printf("setup complete; registry at %s/registry.json\n", abs)
}

func provision(args []string) {
	fs := flag.NewFlagSet("provision", flag.ExitOnError)
	runDir := fs.String("run-dir", "run", "")
	label := fs.String("label", "", "A or B")
	depID := fs.String("deployment-id", "", "")
	name := fs.String("name", "", "display name")
	tlsName := fs.String("tls-name", "", "enrolled DNS name")
	url := fs.String("url", "", "agent http base URL")
	httpsURL := fs.String("https-url", "", "agent https base URL")
	tpmSock := fs.String("tpm-sock", "", "swtpm data socket (direct, provisioning only)")
	tpmGate := fs.String("tpm-gate", "", "gate socket the agent will use")
	sisoGate := fs.String("siso-gate", "", "gate socket of the isolated software signer")
	fs.Parse(args)
	if *label == "" || *depID == "" || *tpmSock == "" {
		fs.Usage()
		os.Exit(2)
	}
	provisionOne(*runDir, *label, *depID, *name, *tlsName, *url, *httpsURL, *tpmSock, *tpmGate, *sisoGate)
}

// provisionOne enrolls one deployment: publisher key (outside the volume), S-file key
// (inside the volume), S-iso key + token (signer dir), TPM AK (inside the emulator),
// PCR reference, TLS name and origins, signed card, registry entry, gate config.
func provisionOne(runDir, label, depID, name, tlsName, url, httpsURL, tpmSock, tpmGate, sisoGate string) {
	base := filepath.Join(runDir, label)
	appDir, signerDir, pubDir := filepath.Join(base, "app"), filepath.Join(base, "signer"), filepath.Join(base, "publisher")
	for _, d := range []string{appDir, signerDir, pubDir} {
		must(os.MkdirAll(d, 0o755))
	}
	pubKey := genKey(filepath.Join(pubDir, "card.key"))
	sfile := genKey(filepath.Join(appDir, "sfile.key"))
	siso := genKey(filepath.Join(signerDir, "siso.key"))
	token := randHex(16)
	must(os.WriteFile(filepath.Join(signerDir, "siso_token"), []byte(token+"\n"), 0o600))
	akAuth := randHex(16)
	must(os.WriteFile(filepath.Join(signerDir, "ak_auth"), []byte(akAuth+"\n"), 0o600))

	c, err := tpmsig.Open(tpmSock)
	must(err)
	ak, err := c.Provision([]byte(akAuth))
	must(err)
	must(c.ExtendPCR([]byte("deployment-" + label + "-config-v1")))
	pcr, err := c.ReadPCR()
	must(err)
	c.Close()

	cfg := agent.AppConfig{DeploymentID: depID, SFileKeyID: label + "-sfile-k1", SFileKeyFile: "sfile.key", SIsoKeyID: label + "-siso-k1", TPMGateSock: tpmGate, SIsoGateSock: sisoGate}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	must(os.WriteFile(filepath.Join(appDir, "config.json"), b, 0o644))

	regPath := filepath.Join(runDir, "registry.json")
	reg, err := registry.Load(regPath)
	if err != nil {
		reg = &registry.Registry{Frozen: time.Now().UTC().Format(time.RFC3339), Deployments: map[string]*registry.Deployment{}}
	}
	origins := []string{}
	for _, u := range []string{url, httpsURL} {
		if u != "" {
			origins = append(origins, u)
		}
	}
	reg.Deployments[label] = &registry.Deployment{
		DeploymentID: depID, AttesterID: depID,
		CardKeyID: label + "-card-k1", CardPublicPEM: pubPEM(&pubKey.PublicKey),
		SFileKeyID: cfg.SFileKeyID, SFilePublicPEM: pubPEM(&sfile.PublicKey),
		SIsoKeyID: cfg.SIsoKeyID, SIsoPublicPEM: pubPEM(&siso.PublicKey),
		AKPublicPEM: ak.PublicPEM, AKName: ak.Name, AKQualified: ak.QualifiedName,
		PCRBank: "sha256", PCRIndex: tpmsig.RefPCR, PCRReference: hex.EncodeToString(pcr),
		TLSName: tlsName, Origins: origins,
	}
	must(reg.Save(regPath))

	gcPath := filepath.Join(runDir, "gate", "config.json")
	must(os.MkdirAll(filepath.Dir(gcPath), 0o755))
	var gc []gateEntry
	if gb, err := os.ReadFile(gcPath); err == nil {
		json.Unmarshal(gb, &gc)
	}
	gc = append(gc,
		gateEntry{Name: "tpm" + label, Kind: "tpm", Listen: tpmGate, Upstream: tpmSock},
		gateEntry{Name: "sw" + label, Kind: "sw", Listen: sisoGate, KeyFile: filepath.Join(signerDir, "siso.key"), TokenFile: filepath.Join(signerDir, "siso_token")})
	gb, _ := json.MarshalIndent(gc, "", "  ")
	must(os.WriteFile(gcPath, gb, 0o644))

	writeCard(runDir, label, name, "1.0.0", origins, "")
	fmt.Printf("provisioned %s: deployment=%s ak_name=%s pcr16=%s tls_name=%s\n", label, depID, ak.Name, hex.EncodeToString(pcr), tlsName)
}

type gateEntry struct {
	Name, Kind, Listen, Upstream, KeyFile, TokenFile string
}

// writeCard signs a card declaring one JSON-RPC interface per origin.
func writeCard(runDir, label, name, version string, origins []string, outPath string) {
	base := filepath.Join(runDir, label)
	kb, err := os.ReadFile(filepath.Join(base, "publisher", "card.key"))
	must(err)
	key, err := agent.ParseECPrivatePEM(kb)
	must(err)
	var ifaces []*a2a.AgentInterface
	for _, u := range origins {
		ifaces = append(ifaces, &a2a.AgentInterface{ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0", URL: u})
	}
	card := &a2a.AgentCard{
		Name:                name,
		Description:         "Scripted deployment for the A2A identity experiment (" + label + ").",
		Version:             version,
		Provider:            &a2a.AgentProvider{Org: "a2aid-lab", URL: origins[0]},
		DefaultInputModes:   []string{"application/json"},
		DefaultOutputModes:  []string{"application/json"},
		Capabilities:        a2a.AgentCapabilities{},
		SupportedInterfaces: ifaces,
		Skills:              []a2a.AgentSkill{{ID: "attest", Name: "Attested challenge", Description: "Answers a verifier challenge and accepts a synthetic job.", Tags: []string{"identity"}}},
	}
	signed, err := cardsig.Sign(card, key, label+"-card-k1")
	must(err)
	b, _ := json.MarshalIndent(signed, "", "  ")
	if outPath == "" {
		outPath = filepath.Join(base, "app", "card.json")
	}
	must(os.WriteFile(outPath, b, 0o644))
}

func publishCard(args []string) {
	fs := flag.NewFlagSet("publish-card", flag.ExitOnError)
	runDir := fs.String("run-dir", "run", "")
	label := fs.String("label", "", "")
	name := fs.String("name", "", "")
	version := fs.String("version", "1.0.0", "")
	urls := fs.String("urls", "", "comma-separated interface URLs")
	reload := fs.String("reload", "", "agent admin base URL to reload the card")
	fs.Parse(args)
	writeCard(*runDir, *label, *name, *version, strings.Split(*urls, ","), "")
	if *reload != "" {
		resp, err := http.Post(*reload+"/admin/reload-card", "application/json", strings.NewReader("{}"))
		must(err)
		resp.Body.Close()
	}
}

func runController(args []string) {
	fs := flag.NewFlagSet("controller", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:9100", "")
	fs.Parse(args)
	log.Printf("controller on %s", *listen)
	must(http.ListenAndServe(*listen, controller.New().Handler()))
}

func runGate(args []string) {
	fs := flag.NewFlagSet("gate", flag.ExitOnError)
	cfg := fs.String("config", "run/gate/config.json", "")
	admin := fs.String("admin", "127.0.0.1:9110", "")
	ctlURL := fs.String("controller", "http://127.0.0.1:9100", "")
	fs.Parse(args)
	b, err := os.ReadFile(*cfg)
	must(err)
	var entries []gateEntry
	must(json.Unmarshal(b, &entries))
	g := gate.New(ctl.New(*ctlURL, "gate"))
	for _, e := range entries {
		s := &gate.Signer{Name: e.Name, Kind: e.Kind, Listen: e.Listen, Upstream: e.Upstream}
		if e.Kind == "sw" {
			kb, err := os.ReadFile(e.KeyFile)
			must(err)
			s.Key, err = agent.ParseECPrivatePEM(kb)
			must(err)
			tb, err := os.ReadFile(e.TokenFile)
			must(err)
			s.Token = strings.TrimSpace(string(tb))
		}
		g.Add(s)
	}
	go func() { must(http.ListenAndServe(*admin, g.AdminHandler())) }()
	log.Printf("gate admin on %s, %d signers", *admin, len(entries))
	must(g.Serve())
}

func runAgent(args []string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	label := fs.String("label", "", "")
	listen := fs.String("listen", "", "plain HTTP listen address")
	tlsListen := fs.String("tls-listen", "", "HTTPS listen address")
	tlsDir := fs.String("tls-dir", "", "directory with cert.pem/key.pem")
	caFile := fs.String("ca", "", "lab root CA for outbound connections")
	appDir := fs.String("app-dir", "", "")
	signerDir := fs.String("signer-dir", "", "")
	ctlURL := fs.String("controller", "http://127.0.0.1:9100", "")
	fs.Parse(args)
	a, err := agent.New(*label, *listen, *appDir, *signerDir, ctl.New(*ctlURL, "agent-"+*label))
	must(err)
	a.CAFile = *caFile
	h := a.Handler()
	if *tlsListen != "" {
		must(a.LoadTLS(*tlsDir))
		ln, err := net.Listen("tcp", *tlsListen)
		must(err)
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, TLSConfig: a.TLSConfig()}
		go func() { must(srv.Serve(tls.NewListener(ln, srv.TLSConfig))) }()
		log.Printf("agent %s https on %s", *label, *tlsListen)
	}
	log.Printf("agent %s http on %s", *label, *listen)
	srv := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	must(srv.ListenAndServe())
}
