// a2aid: local A2A identity experiment (card / software challenge / TPM quote / PTV
// / transport controls / channel binding).
package main

import (
	"a2aid/internal/pqaudit"
	"a2aid/internal/pqdev"
	"a2aid/internal/pqsig"
	"a2aid/internal/wire"
	"context"
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
	"strconv"
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
	"a2aid/internal/zk"
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
	case "zk-fixtures":
		if err := zk.GenerateFixtures(argOr(os.Args[2:], "fixtures/zk")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "zk-matrix":
		zkMatrix(os.Args[2:])
	case "zk-oracle":
		zkOracle(os.Args[2:])
	case "zk-inventory":
		zkInventory(os.Args[2:])
	case "pq-bench":
		pqBench(os.Args[2:])
	case "audit-pq":
		pqAudit(os.Args[2:])
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
	fmt.Fprintln(os.Stderr, "usage: a2aid setup|provision|publish-card|controller|gate|agent|matrix|traces|zk-fixtures|zk-matrix|zk-oracle|zk-inventory|pq-bench|audit-pq|audit-release|reverify|version ...")
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
		// PQ device: one wolfTPM firmware-TPM instance per deployment, fresh NV.
		if _, err := pqdev.StartFWTPM(pqdev.DefaultBin("."), filepath.Join(abs, "fwtpm"+l), fwtpmPort[l], true); err != nil {
			log.Fatalf("fwtpm %s: %v", l, err)
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

	// a2aid-proof-v4 credentials: EC key and ML-DSA seed in the signer dir (gated
	// service), ML-DSA seed inside the volume (PQ-file), and an ML-DSA key created by
	// the deployment's emulated device (its authValue in the signer dir).
	ecKey := genKey(filepath.Join(signerDir, "ec.key"))
	envToken := randHex(16)
	must(os.WriteFile(filepath.Join(signerDir, "env_token"), []byte(envToken+"\n"), 0o600))
	pqEnvSeed, _ := pqsig.NewMLDSASeed()
	must(os.WriteFile(filepath.Join(signerDir, "pq-env.seed"), []byte(hex.EncodeToString(pqEnvSeed)+"\n"), 0o600))
	pqEnvPub, _, _ := pqsig.MLDSAKeyFromSeed(pqEnvSeed)
	pqFileSeed, _ := pqsig.NewMLDSASeed()
	must(os.WriteFile(filepath.Join(appDir, "pqfile.seed"), []byte(hex.EncodeToString(pqFileSeed)+"\n"), 0o600))
	pqFilePub, _, _ := pqsig.MLDSAKeyFromSeed(pqFileSeed)
	devAuth := randHex(16) // 32 bytes of hex text ≤ SHA-256 digest size
	must(os.WriteFile(filepath.Join(signerDir, "dev_auth"), []byte(devAuth+"\n"), 0o600))
	dev := &pqdev.Device{Bin: pqdev.DefaultBridge("."), Port: fwtpmPort[label], Handle: pqDeviceHandle, AuthFile: filepath.Join(signerDir, "dev_auth")}
	devRes, devPub, err := dev.Create(context.Background())
	must(err)
	if len(devPub) != pqsig.PublicKeySize {
		log.Fatalf("device public key is %d bytes", len(devPub))
	}
	devTrace, _ := json.MarshalIndent(map[string]any{"label": label, "handle": devRes.Handle, "attributes": devRes.Attributes, "name_hex": devRes.NameHex, "public_key_len": devRes.PublicKeyLen, "commands": devRes.Commands}, "", " ")
	must(os.WriteFile(filepath.Join(base, "pqdevice-provision.json"), devTrace, 0o644))

	c, err := tpmsig.Open(tpmSock)
	must(err)
	ak, err := c.Provision([]byte(akAuth))
	must(err)
	must(c.ExtendPCR([]byte("deployment-" + label + "-config-v1")))
	pcr, err := c.ReadPCR()
	must(err)
	c.Close()

	gateDir := filepath.Dir(sisoGate)
	ecGate, pqGate, devGate := filepath.Join(gateDir, "ec"+label+".sock"), filepath.Join(gateDir, "pq"+label+".sock"), filepath.Join(gateDir, "dev"+label+".sock")
	cfg := agent.AppConfig{DeploymentID: depID, SFileKeyID: label + "-sfile-k1", SFileKeyFile: "sfile.key", SIsoKeyID: label + "-siso-k1", TPMGateSock: tpmGate, SIsoGateSock: sisoGate,
		ECEnvGateSock: ecGate, PQEnvGateSock: pqGate, PQDeviceGateSock: devGate, PQFileSeedFile: "pqfile.seed",
		ECEnvKeyID: label + "-ecenv-k1", PQEnvKeyID: label + "-pqenv-k1", PQFileKeyID: label + "-pqfile-k1", PQDeviceKeyID: label + "-pqdev-k1"}
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
		V4Keys: map[string]registry.V4Key{
			wire.PolicyECEnv:    {Alg: pqsig.AlgES256, KID: cfg.ECEnvKeyID, Version: 1, Custody: "gated-service", PublicPEM: pubPEM(&ecKey.PublicKey)},
			wire.PolicyPQEnv:    {Alg: pqsig.AlgMLDSA, KID: cfg.PQEnvKeyID, Version: 1, Custody: "gated-service", PublicB64: wire.B64(pqsig.MLDSAPublicBytes(pqEnvPub))},
			wire.PolicyPQFile:   {Alg: pqsig.AlgMLDSA, KID: cfg.PQFileKeyID, Version: 1, Custody: "application-volume", PublicB64: wire.B64(pqsig.MLDSAPublicBytes(pqFilePub))},
			wire.PolicyPQDevice: {Alg: pqsig.AlgMLDSA, KID: cfg.PQDeviceKeyID, Version: 1, Custody: "emulated-device", PublicB64: wire.B64(devPub), DeviceHandle: devRes.Handle, DeviceName: devRes.NameHex},
		},
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
		gateEntry{Name: "sw" + label, Kind: "sw", Listen: sisoGate, KeyFile: filepath.Join(signerDir, "siso.key"), TokenFile: filepath.Join(signerDir, "siso_token")},
		gateEntry{Name: "ec" + label, Kind: "env", Alg: pqsig.AlgES256, Custody: "gated-service", Listen: ecGate, KeyFile: filepath.Join(signerDir, "ec.key"), TokenFile: filepath.Join(signerDir, "env_token")},
		gateEntry{Name: "pq" + label, Kind: "env", Alg: pqsig.AlgMLDSA, Custody: "gated-service", Listen: pqGate, SeedFile: filepath.Join(signerDir, "pq-env.seed"), TokenFile: filepath.Join(signerDir, "env_token")},
		gateEntry{Name: "dev" + label, Kind: "env", Alg: pqsig.AlgMLDSA, Custody: "emulated-device", Listen: devGate, DevicePort: fwtpmPort[label], DeviceHdl: fmt.Sprintf("0x%08x", pqDeviceHandle), DeviceAuth: filepath.Join(signerDir, "dev_auth"), TokenFile: filepath.Join(signerDir, "env_token")})
	if label == "A" { // clone control: a second emulator fed with a copy of A's NV file (started only by the X2 fixture)
		gc = append(gc, gateEntry{Name: "devAclone", Kind: "env", Alg: pqsig.AlgMLDSA, Custody: "emulated-device-clone", Listen: filepath.Join(gateDir, "devAclone.sock"), DevicePort: fwtpmPort["Aclone"], DeviceHdl: fmt.Sprintf("0x%08x", pqDeviceHandle), DeviceAuth: filepath.Join(signerDir, "dev_auth"), TokenFile: filepath.Join(signerDir, "env_token")})
	}
	gb, _ := json.MarshalIndent(gc, "", "  ")
	must(os.WriteFile(gcPath, gb, 0o644))

	writeCard(runDir, label, name, "1.0.0", origins, "")
	fmt.Printf("provisioned %s: deployment=%s ak_name=%s pcr16=%s tls_name=%s\n", label, depID, ak.Name, hex.EncodeToString(pcr), tlsName)
}

type gateEntry struct {
	Name, Kind, Listen, Upstream, KeyFile, TokenFile string
	// "env" signers (a2aid-proof-v4): one backend each
	Alg        string `json:",omitempty"` // ES256 | ML-DSA-65
	Custody    string `json:",omitempty"` // gated-service | emulated-device
	SeedFile   string `json:",omitempty"` // ML-DSA-65 seed (gated-service)
	DevicePort int    `json:",omitempty"` // emulated device command port
	DeviceAuth string `json:",omitempty"` // file holding the device key's authValue
	DeviceHdl  string `json:",omitempty"` // persistent handle
}

// fwtpmPort is the command port of each deployment's emulated PQ device (platform
// port = +1). The clone control uses the A-clone port.
var fwtpmPort = map[string]int{"A": 2321, "B": 2331, "Aclone": 2341}

const pqDeviceHandle = 0x81010001

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
		if e.Kind == "env" {
			tb, err := os.ReadFile(e.TokenFile)
			must(err)
			s.Token, s.Alg, s.Custody = strings.TrimSpace(string(tb)), e.Alg, e.Custody
			switch {
			case e.KeyFile != "":
				kb, err := os.ReadFile(e.KeyFile)
				must(err)
				s.Key, err = agent.ParseECPrivatePEM(kb)
				must(err)
			case e.SeedFile != "":
				sb, err := os.ReadFile(e.SeedFile)
				must(err)
				seed, err := hex.DecodeString(strings.TrimSpace(string(sb)))
				must(err)
				_, sk, err := pqsig.MLDSAKeyFromSeed(seed)
				must(err)
				s.MLDSA = sk
			case e.DevicePort != 0:
				h, _ := strconv.ParseUint(strings.TrimPrefix(e.DeviceHdl, "0x"), 16, 32)
				s.Device = &pqdev.Device{Bin: pqdev.DefaultBridge("."), Port: e.DevicePort, Handle: uint32(h), AuthFile: e.DeviceAuth}
			}
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

func argOr(args []string, def string) string {
	if len(args) > 0 && args[0] != "" {
		return args[0]
	}
	return def
}

// zkMatrix runs the optional proof-carrying task-result matrix (needs zk/ built).
func zkMatrix(args []string) {
	fs := flag.NewFlagSet("zk-matrix", flag.ExitOnError)
	runDir := fs.String("run-dir", "run", "identity lab run dir (scripts/setup.sh)")
	out := fs.String("out", "results/zk", "")
	zkDir := fs.String("zk-dir", "zk", "Rust workspace with target/release/{zkprove,zkverify,zkfake} and image-id.txt")
	fx := fs.String("fixtures", "fixtures/zk", "")
	pred := fs.String("predictions", "fixtures/zk/predictions.json", "")
	runPathFile := fs.String("run-path-file", "", "write the created run directory path here")
	fs.Parse(args)
	bin, _ := os.Executable()
	dir, err := zk.Run(zk.Options{RunDir: *runDir, Out: *out, ZKDir: *zkDir, Fixtures: *fx, Predictions: *pred, Bin: bin})
	if err != nil {
		fmt.Fprintln(os.Stderr, "zk-matrix:", err)
		os.Exit(1)
	}
	if *runPathFile != "" {
		os.WriteFile(*runPathFile, []byte(dir+"\n"), 0o644)
	}
}

// zkOracle scores a ZK run offline (exit 0 complete and clean, 1 observed
// disagreement/violation/evidence mismatch, 2 incomplete/malformed/unsupported).
func zkOracle(args []string) {
	fs := flag.NewFlagSet("zk-oracle", flag.ExitOnError)
	res := fs.String("results", "", "results/zk/<run> directory")
	openings := fs.String("openings", "fixtures/zk/openings.json", "synthetic private openings (oracle side)")
	verifyBin := fs.String("verify-bin", "zk/target/release/zkverify", "pinned verifier CLI re-run on every referenced receipt")
	legacy := fs.String("legacy-inventory", "", "declared inventory for a schema-1 run (separately identified replay/audit view)")
	outDir := fs.String("out", "", "directory for oracle.jsonl / oracle-summary.json / oracle.md (default: the run directory)")
	fs.Parse(args)
	if *res == "" {
		fs.Usage()
		os.Exit(2)
	}
	sum, _, err := zk.RunOracleOpts(zk.OracleOptions{Run: *res, Openings: *openings, VerifyBin: *verifyBin, LegacyInventory: *legacy, OutDir: *outDir})
	if err != nil {
		fmt.Fprintln(os.Stderr, "zk-oracle:", err)
		os.Exit(2)
	}
	fmt.Printf("zk-oracle: mode=%q declared=%d rows=%d scored=%d agree=%d disagree=%d violations=%d evidence_mismatch=%d incomplete=%d malformed=%d attack_successes=%d wrong_context=%s unsafe=%s denied_legit=%s exit=%d\n", sum.Mode, sum.Expected, sum.Rows, sum.Scored, sum.Agree, sum.Disagree, sum.Violations, sum.EvidenceMismatch, sum.Incomplete, sum.Malformed, sum.AttackSuccesses, sum.WrongContext, sum.UnsafeApprovals, sum.DeniedLegitimate, sum.ExitCode)
	for _, e := range sum.RunErrors {
		fmt.Println("  " + e)
	}
	os.Exit(sum.ExitCode)
}

// zkInventory writes a declared inventory (kind run or legacy) for a pinned image id.
func zkInventory(args []string) {
	fs := flag.NewFlagSet("zk-inventory", flag.ExitOnError)
	image := fs.String("image-id", "", "pinned guest image id (64 hex)")
	pred := fs.String("predictions", "fixtures/zk/predictions.json", "")
	kind := fs.String("kind", "legacy", "run | legacy")
	out := fs.String("out", "", "output file (default stdout)")
	fs.Parse(args)
	p, _, err := zk.LoadPredictions(*pred)
	if err != nil {
		fmt.Fprintln(os.Stderr, "zk-inventory:", err)
		os.Exit(2)
	}
	inv, err := zk.BuildInventory(*kind, "", *image, p)
	if err != nil {
		fmt.Fprintln(os.Stderr, "zk-inventory:", err)
		os.Exit(2)
	}
	if *out == "" {
		*out = "/dev/stdout"
	}
	if err := zk.WriteInventory(*out, inv); err != nil {
		fmt.Fprintln(os.Stderr, "zk-inventory:", err)
		os.Exit(2)
	}
}

// pqBench measures ML-DSA-65 / P-256 operations and the emulated-device signing path.
func pqBench(args []string) {
	fs := flag.NewFlagSet("pq-bench", flag.ExitOnError)
	n := fs.Int("samples", 30, "samples per operation")
	port := fs.Int("device-port", fwtpmPort["A"], "fwtpm_server command port (0 = skip the device)")
	auth := fs.String("device-auth", "run/A/signer/dev_auth", "authValue file of the device key")
	out := fs.String("out", "results/pq-bench", "output directory root")
	fs.Parse(args)
	var dev *pqdev.Device
	if *port != 0 {
		dev = &pqdev.Device{Bin: pqdev.DefaultBridge("."), Port: *port, Handle: pqDeviceHandle, AuthFile: *auth}
	}
	b, err := pqsig.RunBench(*n, dev)
	must(err)
	dir := filepath.Join(*out, time.Now().UTC().Format("20060102-150405"))
	must(os.MkdirAll(dir, 0o755))
	jb, _ := json.MarshalIndent(b, "", "  ")
	must(os.WriteFile(filepath.Join(dir, "bench.json"), jb, 0o644))
	fmt.Println(string(jb))
	fmt.Println("written to", dir)
}

// pqAudit re-verifies retained proof-v4 credentials of a matrix run (exit 0/1/2).
func pqAudit(args []string) {
	fs := flag.NewFlagSet("audit-pq", flag.ExitOnError)
	res := fs.String("results", "", "matrix run directory")
	reg := fs.String("registry", "", "trusted registry (default: <run>/enrollment-registry.json)")
	out := fs.String("out", "", "output directory (default: the run directory)")
	fs.Parse(args)
	if *res == "" {
		fs.Usage()
		os.Exit(2)
	}
	sum, _, err := pqaudit.Run(pqaudit.Options{Run: *res, Registry: *reg, OutDir: *out})
	if err != nil {
		fmt.Fprintln(os.Stderr, "audit-pq:", err)
		os.Exit(2)
	}
	fmt.Printf("audit-pq v%s (structural checker %s): declared=%d found=%d agree=%d disagree=%d violations=%d incomplete=%d malformed=%d unsupported=%d proofs_valid=%d proofs_invalid=%d attacker_deliveries=%d orphan_receipts=%d duplicate_decision_ids=%d structural=%v exit=%d\n", sum.Version, sum.StructuralChecker, sum.Expected, sum.Found, sum.Agree, sum.Disagree, sum.Violations, sum.Incomplete, sum.Malformed, sum.Unsupported, sum.ProofsVerified, sum.ProofsInvalid, sum.AttackSuccess, sum.OrphanReceipts, len(sum.DuplicateDecisions), sum.StructuralOutcomes, sum.ExitCode)
	for _, e := range sum.RunErrors {
		fmt.Println("  " + e)
	}
	os.Exit(sum.ExitCode)
}
